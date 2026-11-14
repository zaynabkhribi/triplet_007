from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.models import (
    CityRegistryRecord,
    CitySnapshot,
    EventLifecycle,
    GuardianVerdictRecord,
    QuarantineRecord,
    SensorEvent,
)
from app.database.session import Database
from app.decision.engine import DecisionEngine
from app.intelligence.incident_detector import IncidentDetector
from app.intelligence.incident_rules import load_rules
from app.security.passport_trust import PassportEligibilityIndex, supplements_missing_verdict
from app.security.trust_engine import TrustEngine
from app.state.fusion import correlation, statistics
from app.state.lifecycle import utc
from app.state.registry import Registry


class CityEngine:
    def __init__(self, database: Database, settings: Settings) -> None:
        self.database, self.trust = database, TrustEngine(settings)

        self.incidents = IncidentDetector(
            settings,
            load_rules(settings.incident_rules_file, settings.environment),
        )

        self.decisions = DecisionEngine(settings, self.incidents.rules)

        # Task 7.3G-7B: Guardian-native passport eligibility. The index is
        # REFRESHED ASYNC (await index.refresh(...)) by the async call sites
        # that own an event loop (decisions API, actuator tick) BEFORE the
        # synchronous rebuild consumes the immutable snapshot. rebuild() is
        # strictly non-blocking. Disabled by default; dev/test only.
        from contextlib import suppress

        from app.integration.ngsi_twin import load_mapping

        mappings: list = []
        with suppress(Exception):  # noqa: BLE001 - no mapping file: passport inert
            mappings = list(load_mapping(settings.snap4city_devices_file).sensors)
        self.eligibility = PassportEligibilityIndex(settings, mappings)
        self.decisions.passport_eligibility = self.eligibility

    def recent_candidates(self, session: Session, now: datetime) -> list:
        """Recent (SensorEvent, EventLifecycle) rows for passport refresh."""
        cutoff = now - timedelta(
            seconds=min(
                self.trust.settings.event_freshness_seconds,
                self.trust.settings.guardian_passport_max_evidence_age_seconds,
            )
        )
        return list(
            session.execute(
                select(SensorEvent, EventLifecycle)
                .outerjoin(
                    EventLifecycle,
                    SensorEvent.id == EventLifecycle.event_id,
                )
                .where(
                    SensorEvent.occurred_at >= cutoff,
                    SensorEvent.occurred_at <= now,
                )
            ).all()
        )

    async def refresh_passports(self) -> dict:
        import asyncio

        now = self.eligibility.now()

        def collect():
            with self.database.transaction() as session:
                return self.recent_candidates(session, now)

        return await self.eligibility.refresh(await asyncio.to_thread(collect), now)

    async def read_current(self, reader):
        """Refresh and consume one authorization cycle without concurrent clearing."""
        import asyncio

        if not self.eligibility.enabled:
            return await asyncio.to_thread(reader)
        requested_at = self.eligibility.now()
        async with self.eligibility._refresh_lock:
            now = self.eligibility.now()
            completed_at = self.eligibility.snapshot(now).completed_at
            if completed_at is not None and completed_at >= requested_at:
                # A concurrent request already refreshed after this read began.
                # Consume it within the original per-entry expiry, never renew it.
                return await asyncio.to_thread(reader)

            def collect():
                with self.database.transaction() as session:
                    return self.recent_candidates(session, now)

            await self.eligibility._refresh(await asyncio.to_thread(collect), now)
            return await asyncio.to_thread(reader)

    def rebuild(self, session: Session, now: datetime) -> dict:
        passport_snapshot = self.eligibility.snapshot(now)
        record = session.get(CityRegistryRecord, 1)
        registry = Registry.model_validate(record.payload if record else {})

        zones = {zone: {"sensors": [], "measurements": {}} for zone in registry.zones}

        sensors, series = {}, {}

        definitions = list(registry.sensors)
        sensor_ids = [definition.sensor_id for definition in definitions]
        earliest_cutoff = min(
            (
                now
                - timedelta(
                    seconds=min(
                        registry.window_seconds,
                        definition.freshness_seconds,
                    )
                )
                for definition in definitions
            ),
            default=now,
        )
        history_ids = set(
            session.scalars(
                select(SensorEvent.sensor_id)
                .where(SensorEvent.sensor_id.in_(sensor_ids))
                .distinct()
            ).all()
        )
        recent_rows = (
            session.execute(
                select(SensorEvent, EventLifecycle)
                .outerjoin(EventLifecycle, SensorEvent.id == EventLifecycle.event_id)
                .where(
                    SensorEvent.sensor_id.in_(sensor_ids),
                    SensorEvent.occurred_at >= earliest_cutoff,
                    SensorEvent.occurred_at <= now,
                )
                .order_by(SensorEvent.sensor_id, SensorEvent.occurred_at, SensorEvent.id)
            ).all()
            if sensor_ids
            else []
        )
        rows_by_sensor: dict[str, list] = {sensor_id: [] for sensor_id in sensor_ids}
        for event, lifecycle in recent_rows:
            rows_by_sensor[event.sensor_id].append((event, lifecycle))

        event_ids = [event.id for event, _ in recent_rows]
        verdicts_by_event: dict[object, list] = {event_id: [] for event_id in event_ids}
        if event_ids:
            for verdict in session.scalars(
                select(GuardianVerdictRecord).where(
                    GuardianVerdictRecord.event_id.in_(event_ids)
                )
            ):
                verdicts_by_event[verdict.event_id].append(verdict)

        quarantine_rows = session.scalars(
            select(QuarantineRecord).where(
                QuarantineRecord.target_type == "sensor",
                QuarantineRecord.target_id.in_(sensor_ids),
            )
        ).all()
        quarantined_sensors = set()
        for sensor_id in sensor_ids:
            records = [row for row in quarantine_rows if row.target_id == sensor_id]
            if not records:
                continue
            rank = lambda row: (  # noqa: E731 - local ordering rule
                row.payload["event"]["revision"],
                utc(row.occurred_at),
            )
            latest = max(rank(row) for row in records)
            if any(
                row.payload["event"]["action"] == "quarantine"
                for row in records
                if rank(row) == latest
            ):
                quarantined_sensors.add(sensor_id)

        # Process each registered sensor independently
        for definition in definitions:
            cutoff = now - timedelta(
                seconds=min(
                    registry.window_seconds,
                    definition.freshness_seconds,
                )
            )

            # Preserve missing vs stale sensor distinction
            has_history = definition.sensor_id in history_ids

            # Query only the relevant recent measurements
            candidates = [
                (event, lifecycle)
                for event, lifecycle in rows_by_sensor.get(definition.sensor_id, [])
                if utc(event.occurred_at) >= cutoff
            ]

            points, evidence = {}, []
            latest_eligible = None
            duplicates = {}

            # Detect duplicate observation timestamps
            for event, _ in candidates:
                timestamp = utc(event.occurred_at)
                duplicates[timestamp] = duplicates.get(timestamp, 0) + 1

            # Task 7.3G-7B: NO blocking here. The eligibility snapshot was
            # refreshed ASYNC by the calling API/worker before rebuild() was
            # entered (see refresh_for_decision / refresh_for_dispatch). This
            # sync path only reads the immutable snapshot.

            # Validate every candidate through Guardian trust
            for event, lifecycle in candidates:
                timestamp = utc(event.occurred_at)
                payload = event.payload["event"]

                if (
                    not cutoff <= timestamp <= now
                    or duplicates[timestamp] != 1
                    or payload["sensor_type"] != definition.measurement
                    or payload["unit"] != definition.unit
                    or payload.get("attributes", {}).get("zone_id", definition.zone_id)
                    != definition.zone_id
                    or lifecycle is None
                ):
                    continue

                trust = self.trust.evaluate(
                    session,
                    event,
                    lifecycle,
                    now,
                    verdict_records=verdicts_by_event.get(event.id, []),
                    sensor_quarantined=definition.sensor_id in quarantined_sensors,
                )

                passport_eligible = supplements_missing_verdict(
                    trust
                ) and self.eligibility.enabled and passport_snapshot.eligible_at(event.id, now)
                if trust.state != "TRUSTED" and not passport_eligible:
                    continue
                if trust.state == "TRUSTED" and (
                    not lifecycle.eligible or trust.verdict_id != lifecycle.verdict_id
                ):
                    continue

                points[timestamp.timestamp()] = payload["value"]
                latest_eligible = event

                evidence.append(
                    {
                        "event_id": str(event.id),
                        "verdict_id": str(lifecycle.verdict_id),
                        "trust_source": "guardian_passport"
                        if passport_eligible
                        else "guardian_verdict",
                    }
                )

            # Determine current sensor availability
            available = bool(points) and latest_eligible is not None

            if not available:
                points, evidence = {}, []

            availability = "available" if available else "unavailable"

            if not has_history:
                availability = "missing"

            elif latest_eligible is None or utc(latest_eligible.occurred_at) < cutoff:
                availability = "stale"

            # Guardian quarantine overrides sensor availability
            if definition.sensor_id in quarantined_sensors:
                availability = "quarantined"
                points, evidence, available = {}, [], False

            # Store calculated state for this sensor
            sensors[definition.sensor_id] = {
                **definition.model_dump(),
                "availability": availability,
                "trust_status": ("trusted" if available else "unverified"),
                "last_observed_at": (
                    utc(latest_eligible.occurred_at).isoformat() if latest_eligible else None
                ),
                "value": (list(points.values())[-1] if points else None),
                "statistics": statistics(
                    list(points.items()),
                    registry.ema_alpha,
                ),
                "evidence": evidence,
            }

            series[definition.sensor_id] = points

            zones[definition.zone_id]["sensors"].append(definition.sensor_id)

        # Aggregate sensor measurements by zone
        for zone in zones.values():
            groups = {}

            for sensor_id in zone["sensors"]:
                sensor = sensors[sensor_id]
                key = sensor["measurement"] + ":" + sensor["unit"]

                groups.setdefault(key, []).append(sensor_id)

            for key, ids in groups.items():
                usable = [sid for sid in ids if sensors[sid]["value"] is not None]

                weight = sum(sensors[sid]["weight"] for sid in usable)

                zone["measurements"][key] = {
                    "value": (
                        sum(sensors[sid]["value"] * sensors[sid]["weight"] for sid in usable)
                        / weight
                        if weight
                        else None
                    ),
                    "contributors": usable,
                    "missing": sorted(set(ids) - set(usable)),
                    "correlations": [
                        {
                            "left": left,
                            "right": right,
                            "value": correlation(
                                series[left],
                                series[right],
                            ),
                        }
                        for index, left in enumerate(usable)
                        for right in usable[index + 1 :]
                    ],
                }

        # Persist city state only when it changes
        payload = {
            "zones": zones,
            "sensors": sensors,
            "registry": registry.model_dump(),
        }

        previous = session.scalar(
            select(CitySnapshot).order_by(CitySnapshot.version.desc()).limit(1)
        )

        if previous is None or previous.payload != payload:
            previous = CitySnapshot(
                created_at=now,
                payload=payload,
            )
            session.add(previous)
            session.flush()

        state = {
            "version": previous.version,
            "as_of": now.isoformat(),
            **payload,
        }

        # Preserve incident detection and decision invalidation
        self.incidents.evaluate(session, state, now)
        self.decisions.invalidate(session, state, now)

        return state

    def snapshot(self) -> dict:
        with self.database.transaction() as session:
            return self.rebuild(
                session,
                datetime.now(UTC),
            )
