import asyncio
import logging
import time
from contextlib import suppress
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.core.config import Settings
from app.database.models import CitySnapshot, DecisionRecord, EventLifecycle, SensorEvent
from app.database.session import Database
from app.security.trust_engine import TrustEngine
from app.state.engine import CityEngine
from app.state.lifecycle import FINAL_STATES, audit, transition
from app.streaming.durable_buffer import recover_legacy_events

logger = logging.getLogger(__name__)

# Instrumentation thresholds (milliseconds) for logging slow worker stages.
_RECOVER_WARN_MS = 100.0
_QUERY_WARN_MS = 100.0
_BATCH_WARN_MS = 500.0
_REBUILD_WARN_MS = 500.0
_EMPTY_CYCLE_WARN_MS = 100.0

# Per-event instrumentation thresholds (milliseconds).
_EVENT_WARN_MS = 200.0


class EventProcessor:
    def __init__(self, database: Database, settings: Settings) -> None:
        self.database, self.settings = database, settings
        self.trust = TrustEngine(settings)
        self.city = CityEngine(database, settings)
        self._stop = asyncio.Event()

    async def run(self) -> None:
        while not self._stop.is_set():
            try:
                await self.tick()
            except Exception:
                logger.exception("event_worker_poll_failed")
            with suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=self.settings.worker_poll_seconds)

    def stop(self) -> None:
        self._stop.set()

    async def tick(self, now: datetime | None = None) -> int:
        return await asyncio.to_thread(self.process_batch, now or datetime.now(UTC))

    def process_batch(self, now: datetime) -> int:
        batch_started = time.perf_counter()
        count = 0
        rebuild_ms = 0.0
        with self.database.transaction() as session:
            recover_started = time.perf_counter()
            recover_legacy_events(session, now, self.settings.worker_batch_size)
            recover_ms = (time.perf_counter() - recover_started) * 1000.0
            query_started = time.perf_counter()
            rows = session.scalars(
                select(EventLifecycle)
                .where(
                    EventLifecycle.available_at <= now,
                    EventLifecycle.processing != "failed",
                )
                .order_by(EventLifecycle.available_at, EventLifecycle.event_id)
                .limit(self.settings.worker_batch_size)
            ).all()
            query_ms = (time.perf_counter() - query_started) * 1000.0
            process_started = time.perf_counter()
            # Per-event stage totals (ms) accumulated across the batch.
            stage_totals = {
                "savepoint": 0.0,
                "get_reading": 0.0,
                "transitions": 0.0,
                "trust": 0.0,
                "audit_ack": 0.0,
                "failure": 0.0,
            }
            slow_events = 0
            for row in rows:
                event_started = time.perf_counter()
                event_id = row.event_id
                per_event = dict.fromkeys(stage_totals, 0.0)
                try:
                    savepoint_started = time.perf_counter()
                    with session.begin_nested() as savepoint:
                        savepoint_entry_ms = (
                            (time.perf_counter() - savepoint_started) * 1000.0
                        )
                        reading = session.get(SensorEvent, event_id)
                        get_ms = (time.perf_counter() - savepoint_started) * 1000.0 - savepoint_entry_ms
                        row.processing = "processing"
                        row.attempts += 1
                        row.eligible = False
                        transition_ms = 0.0
                        if row.state == "RECEIVED":
                            t0 = time.perf_counter()
                            transition(
                                session,
                                row,
                                reading.correlation_id,
                                "VALIDATED",
                                "schema_validated_at_ingress",
                                now,
                            )
                            transition_ms += (time.perf_counter() - t0) * 1000.0
                        if row.state == "VALIDATED":
                            t0 = time.perf_counter()
                            transition(
                                session,
                                row,
                                reading.correlation_id,
                                "PENDING_VERDICT",
                                "awaiting_guardian",
                                now,
                            )
                            transition_ms += (time.perf_counter() - t0) * 1000.0
                        transitions_ms = transition_ms
                        t0 = time.perf_counter()
                        result = self.trust.evaluate(session, reading, row, now)
                        trust_ms = (time.perf_counter() - t0) * 1000.0
                        if row.state in FINAL_STATES and row.state != result.state:
                            t0 = time.perf_counter()
                            transition(
                                session,
                                row,
                                reading.correlation_id,
                                "PENDING_VERDICT",
                                "reevaluate_evidence",
                                now,
                            )
                            transitions_ms += (time.perf_counter() - t0) * 1000.0
                        t0 = time.perf_counter()
                        transition(
                            session, row, reading.correlation_id, result.state, result.reason, now
                        )
                        transitions_ms += (time.perf_counter() - t0) * 1000.0
                        row.verdict_id = result.verdict_id
                        row.eligible = result.state == "TRUSTED"
                        row.eligible_until = result.deadline if row.eligible else None
                        row.processing, row.acknowledged_at = "acknowledged", now
                        row.available_at = result.deadline
                        row.attempts, row.last_error = 0, None
                        t0 = time.perf_counter()
                        audit(
                            session,
                            event_id,
                            reading.correlation_id,
                            "event_acknowledged",
                            {"state": row.state, "verdict_id": str(row.verdict_id)},
                            now,
                        )
                        audit_ack_ms = (time.perf_counter() - t0) * 1000.0
                    # Exiting the with-block releases the SAVEPOINT and flushes.
                    savepoint_exit_ms = (
                        (time.perf_counter() - savepoint_started) * 1000.0
                        - savepoint_entry_ms - get_ms - transitions_ms - trust_ms - audit_ack_ms
                    )
                except Exception as exc:
                    t0 = time.perf_counter()
                    row = session.get(EventLifecycle, event_id)
                    reading = session.get(SensorEvent, event_id)
                    row.attempts += 1
                    row.eligible, row.eligible_until = False, None
                    row.last_error = type(exc).__name__
                    failed = row.attempts >= self.settings.worker_max_attempts
                    row.processing = "failed" if failed else "retry"
                    delay = self.settings.worker_retry_seconds * 2 ** (row.attempts - 1)
                    row.available_at = None if failed else now + timedelta(seconds=delay)
                    audit(
                        session,
                        event_id,
                        reading.correlation_id,
                        "event_processing_failed",
                        {"attempt": row.attempts, "error": type(exc).__name__, "terminal": failed},
                        now,
                    )
                    failure_ms = (time.perf_counter() - t0) * 1000.0
                    per_event["failure"] = failure_ms
                else:
                    per_event["savepoint"] = savepoint_entry_ms
                    per_event["get_reading"] = get_ms
                    per_event["transitions"] = transitions_ms
                    per_event["trust"] = trust_ms
                    per_event["audit_ack"] = audit_ack_ms
                    per_event["savepoint"] += savepoint_exit_ms
                for key, value in per_event.items():
                    stage_totals[key] += value
                event_ms = (time.perf_counter() - event_started) * 1000.0
                if event_ms > _EVENT_WARN_MS:
                    slow_events += 1
                    breakdown = " ".join(
                        f"{key}={value:.1f}ms" for key, value in per_event.items()
                    )
                    logger.warning(
                        "event_worker_event_slow total_ms=%.1f %s",
                        event_ms,
                        breakdown,
                    )
                count += 1
            process_ms = (time.perf_counter() - process_started) * 1000.0
            if rows:
                top_stage = max(stage_totals, key=stage_totals.get)
                aggregates = " ".join(
                    f"{key}={value:.1f}ms" for key, value in stage_totals.items()
                )
                logger.warning(
                    "event_worker_stage_totals events=%d slow_events=%d "
                    "process_ms=%.1f largest_stage=%s %s",
                    count,
                    slow_events,
                    process_ms,
                    top_stage,
                    aggregates,
                )
            if count:
                session.flush()
                rebuild_started = time.perf_counter()
                self.city.rebuild(session, now)
                rebuild_ms = (time.perf_counter() - rebuild_started) * 1000.0
            else:
                # Idle tick: only revalidate authorization when active decisions
                # exist. Decision inputs (quarantines, resource availability,
                # incident evidence) are re-derived from the live database by
                # DecisionEngine.context(), so the latest persisted city
                # snapshot is a sound state input even without a fresh rebuild.
                has_active = session.scalar(
                    select(DecisionRecord.id)
                    .where(
                        DecisionRecord.status.in_(
                            ["PROPOSED", "EVALUATED", "APPROVED"],
                        )
                    )
                    .limit(1)
                ) is not None
                if has_active:
                    snapshot = session.scalar(
                        select(CitySnapshot)
                        .order_by(CitySnapshot.version.desc())
                        .limit(1)
                    )
                    if snapshot is not None:
                        state = {
                            "version": snapshot.version,
                            "as_of": now.isoformat(),
                            **snapshot.payload,
                        }
                        self.city.decisions.invalidate(session, state, now)
                    else:
                        # No snapshot to safely revalidate against; fall back
                        # to a full rebuild so invalidation cannot be skipped.
                        self.city.rebuild(session, now)

        total_ms = (time.perf_counter() - batch_started) * 1000.0
        if count:
            if (
                recover_ms > _RECOVER_WARN_MS
                or query_ms > _QUERY_WARN_MS
                or process_ms > _BATCH_WARN_MS
                or rebuild_ms > _REBUILD_WARN_MS
                or total_ms > _BATCH_WARN_MS
            ):
                logger.warning(
                    "event_worker_batch_slow events=%d total_ms=%.1f "
                    "recover_ms=%.1f query_ms=%.1f process_ms=%.1f rebuild_ms=%.1f",
                    count,
                    total_ms,
                    recover_ms,
                    query_ms,
                    process_ms,
                    rebuild_ms,
                )
        elif (
            recover_ms > _EMPTY_CYCLE_WARN_MS
            or query_ms > _EMPTY_CYCLE_WARN_MS
            or total_ms > _EMPTY_CYCLE_WARN_MS
        ):
            # Empty poll that is still slow: the recovery/selection scans are the suspects.
            logger.warning(
                "event_worker_empty_cycle_slow events=0 total_ms=%.1f "
                "recover_ms=%.1f query_ms=%.1f process_ms=0.0 rebuild_ms=0.0",
                total_ms,
                recover_ms,
                query_ms,
            )

        return count
