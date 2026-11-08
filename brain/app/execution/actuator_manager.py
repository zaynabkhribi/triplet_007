import asyncio
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, UUID, uuid5

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.models import (
    ActuatorCommandRecord,
    ActuatorFeedbackRecord,
    CommandRevision,
    DecisionRecord,
)
from app.database.session import Database
from app.execution.command_gateway import CommandGateway
from app.execution.command_outbox import ACTIVE_COMMAND_STATES, due
from app.execution.feedback_manager import reconcile_feedback
from app.integration.http import client_context
from app.integration.orion_adapter import Delivery, OrionAdapter, OrionError
from app.schemas.actuator import ActuatorCommand, ActuatorFeedback
from app.security.event_hash import event_hash
from app.state.lifecycle import audit, utc


class MockTwinAdapter:
    def __init__(
        self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.settings, self.transport = settings, transport

    async def deliver(self, command: ActuatorCommand) -> ActuatorFeedback:
        if self.settings.brain_api_key is None:
            raise OrionError("brain_credentials_missing", False)
        try:
            async with httpx.AsyncClient(
                verify=client_context(self.settings),
                transport=self.transport,
                timeout=self.settings.command_timeout_seconds,
                trust_env=False,
            ) as client:
                response = await client.post(
                    str(self.settings.twin_base_url).rstrip("/") + "/commands",
                    headers={"X-API-Key": self.settings.brain_api_key.get_secret_value()},
                    json=command.model_dump(mode="json"),
                )
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise OrionError("twin_delivery_uncertain", True, True) from exc
        if response.status_code == 200:
            return ActuatorFeedback.model_validate(response.json())
        if response.status_code >= 500:
            raise OrionError("twin_temporarily_unavailable", True)
        raise OrionError(f"twin_rejected_{response.status_code}", False)


class ActuatorManager:
    def __init__(self, database: Database, settings: Settings, city_engine) -> None:
        self.database, self.settings, self.city = database, settings, city_engine
        self.adapter: CommandGateway = (
            OrionAdapter(settings)
            if settings.actuator_transport == "orion"
            else MockTwinAdapter(settings)
        )
        self._stop = asyncio.Event()

    async def run(self) -> None:
        while not self._stop.is_set():
            with suppress(Exception):
                await self.tick()
            with suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), self.settings.worker_poll_seconds)

    def stop(self) -> None:
        self._stop.set()

    def recover_startup(self, now: datetime | None = None) -> None:
        now = now or datetime.now(UTC)
        with self.database.transaction() as session:
            rows = session.scalars(
                select(ActuatorCommandRecord).where(
                    ActuatorCommandRecord.status == "DISPATCHING",
                )
            ).all()
            for row in rows:
                command = ActuatorCommand.model_validate(row.payload["command"])
                if utc(command.expires_at) <= now:
                    target, reason = "EXPIRED", "expired_during_restart"
                elif row.payload["candidate"].get("idempotent"):
                    target, reason = "PENDING", "idempotent_restart_recovery"
                else:
                    target, reason = "UNKNOWN", "non_idempotent_delivery_interrupted"
                self.transition(
                    session,
                    row,
                    target,
                    reason,
                    now,
                    next_attempt_at=now.isoformat() if target == "PENDING" else None,
                )

    def enqueue(
        self, session: Session, state: dict, decision_id: UUID, now: datetime
    ) -> list[dict]:
        decision = session.get(DecisionRecord, decision_id)
        if decision is None:
            raise ValueError("decision_not_found")
        if decision.status != "APPROVED" or not decision.payload.get("approved_actions"):
            raise PermissionError("decision_not_approved")
        current = self.city.decisions.context(session, state, now)
        if current["fingerprint"] != decision.payload[
            "fingerprint"
        ] or not self.city.decisions._verify_current(
            session,
            state,
            decision.payload["approved_actions"],
            decision.payload,
        ):
            raise PermissionError("decision_safety_revalidation_failed")
        commands = []
        for action in decision.payload["approved_actions"]:
            identifier = uuid5(NAMESPACE_URL, f"city-brain:{decision.id}:{action['candidate_id']}")
            existing = session.get(ActuatorCommandRecord, identifier)
            if existing:
                commands.append(self.serialize(existing))
                continue
            conflict = session.scalar(
                select(ActuatorCommandRecord)
                .where(
                    ActuatorCommandRecord.actuator_id == action["actuator_id"],
                    ActuatorCommandRecord.status.in_(ACTIVE_COMMAND_STATES),
                )
                .limit(1)
            )
            if conflict:
                raise ValueError("conflicting_active_command")
            expires = now + timedelta(seconds=self.settings.command_ttl_seconds)
            command = ActuatorCommand(
                command_id=identifier,
                decision_id=decision.id,
                correlation_id=decision.correlation_id,
                issued_at=now,
                actuator_id=action["actuator_id"],
                action=action["action_type"],
                parameters=action["parameters"],
                expires_at=expires,
            )
            row = ActuatorCommandRecord(
                id=identifier,
                correlation_id=decision.correlation_id,
                occurred_at=now,
                actuator_id=action["actuator_id"],
                status="PENDING",
                payload={
                    "command": command.model_dump(mode="json"),
                    "decision_id": str(decision.id),
                    "candidate": action,
                    "attempts": 0,
                    "next_attempt_at": now.isoformat(),
                    "delivery": None,
                    "execution": None,
                },
            )
            session.add(row)
            self.transition(session, row, "PENDING", "authorized_command_created", now)
            commands.append(self.serialize(row))
        return commands

    async def tick(self, now: datetime | None = None) -> int:
        now = now or datetime.now(UTC)
        # Dispatch boundary gate: when execution is disabled, tick() must not
        # claim commands (so no PENDING command can reach DISPATCHING) and
        # must never invoke the outbound adapter.
        if not self.settings.actuator_execution_enabled:
            return 0
        claimed = self._claim(now)
        if claimed is None:
            return 0
        row_id, command, prior = claimed
        if prior == "DELIVERED":
            await self._reconcile_or_timeout(row_id, command, now)
            return 1
        try:
            result = await self.adapter.deliver(command)
        except OrionError as exc:
            self._delivery_error(row_id, exc, now)
        else:
            if isinstance(result, ActuatorFeedback):
                self.record_feedback(result, datetime.now(UTC))
            else:
                self._delivered(row_id, result, datetime.now(UTC))
        return 1

    def _claim(self, now: datetime) -> tuple[UUID, ActuatorCommand, str] | None:
        with self.database.transaction() as session:
            row = due(session, now)
            if row is None:
                return None
            command = ActuatorCommand.model_validate(row.payload["command"])
            if utc(command.expires_at) <= now:
                self.transition(session, row, "EXPIRED", "command_expired", now)
                return None
            if row.status == "DELIVERED":
                return row.id, command, "DELIVERED"
            state = self.city.rebuild(session, now)
            decision = session.get(DecisionRecord, command.decision_id)
            valid = (
                decision is not None
                and decision.status == "APPROVED"
                and self.city.decisions._verify_current(
                    session,
                    state,
                    decision.payload["approved_actions"],
                    decision.payload,
                )
                and any(
                    item["candidate_id"] == row.payload["candidate"]["candidate_id"]
                    for item in decision.payload["approved_actions"]
                )
            )
            if not valid:
                self.transition(session, row, "REJECTED", "safety_revalidation_failed", now)
                return None
            self.transition(session, row, "DISPATCHING", "delivery_started", now, attempts=1)
            return row.id, command, "PENDING"

    async def _reconcile_or_timeout(
        self, row_id: UUID, command: ActuatorCommand, now: datetime
    ) -> None:
        if isinstance(self.adapter, OrionAdapter):
            try:
                state = await self.adapter.state(command.actuator_id)
            except OrionError:
                state = None
            if state and state.get("command_id") == str(command.command_id):
                status = str(state.get("status", "")).lower()
                if status in {"executed", "failed", "unknown"}:
                    with self.database.transaction() as session:
                        row = session.get(ActuatorCommandRecord, row_id)
                        self.transition(
                            session,
                            row,
                            status.upper(),
                            "orion_state_reconciliation",
                            now,
                            execution={"source": "orion_state", "state": state},
                        )
                    return
        with self.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, row_id)
            delivered_at = datetime.fromisoformat(row.payload["delivered_at"])
            if now >= delivered_at + timedelta(
                seconds=self.settings.command_feedback_timeout_seconds
            ):
                self.transition(session, row, "UNKNOWN", "execution_feedback_timeout", now)
            else:
                row.payload = row.payload | {
                    "next_attempt_at": (
                        now + timedelta(seconds=self.settings.command_retry_seconds)
                    ).isoformat()
                }

    def _delivered(self, row_id: UUID, result: Delivery, now: datetime) -> None:
        with self.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, row_id)
            if row.status == "EXECUTED":
                return
            self.transition(
                session,
                row,
                "DELIVERED",
                "broker_accepted_command",
                now,
                delivery={"accepted": result.accepted, "http_status": result.transport_status},
                delivered_at=now.isoformat(),
                next_attempt_at=(
                    now + timedelta(seconds=self.settings.command_retry_seconds)
                ).isoformat(),
            )

    def _delivery_error(self, row_id: UUID, error: OrionError, now: datetime) -> None:
        with self.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, row_id)
            attempts = row.payload["attempts"]
            idempotent = bool(row.payload["candidate"].get("idempotent"))
            if error.uncertain and not idempotent:
                target = "UNKNOWN"
            elif error.retryable and idempotent and attempts < self.settings.command_max_attempts:
                target = "PENDING"
            else:
                target = "FAILED"
            delay = self.settings.command_retry_seconds * 2 ** max(attempts - 1, 0)
            self.transition(
                session,
                row,
                target,
                error.code,
                now,
                next_attempt_at=(now + timedelta(seconds=delay)).isoformat()
                if target == "PENDING"
                else None,
            )

    def record_feedback(self, feedback: ActuatorFeedback, now: datetime) -> dict:
        with self.database.transaction() as session:
            existing = session.get(ActuatorFeedbackRecord, feedback.feedback_id)
            digest = event_hash(feedback)
            if existing:
                if existing.payload["sha256"] != digest:
                    raise ValueError("conflicting_feedback_id")
                return {"status": "duplicate", "command_id": str(feedback.command_id)}
            row = session.get(ActuatorCommandRecord, feedback.command_id)
            if row is None:
                raise LookupError("command_not_found")
            target, changes = reconcile_feedback(session, row, feedback, now)
            session.add(
                ActuatorFeedbackRecord(
                    id=feedback.feedback_id,
                    command_id=feedback.command_id,
                    correlation_id=feedback.correlation_id,
                    occurred_at=feedback.occurred_at,
                    status=feedback.status.value,
                    payload={"event": feedback.model_dump(mode="json"), "sha256": digest},
                )
            )
            self.transition(
                session, row, target, "execution_feedback_received", now, execution=changes
            )
            return {"status": "stored", "command_id": str(feedback.command_id)}

    def transition(
        self,
        session: Session,
        row: ActuatorCommandRecord,
        target: str,
        reason: str,
        now: datetime,
        attempts: int = 0,
        **changes,
    ) -> None:
        allowed = {
            "PENDING": {"PENDING", "DISPATCHING", "REJECTED", "FAILED", "EXPIRED"},
            "DISPATCHING": {"PENDING", "DELIVERED", "EXECUTED", "FAILED", "UNKNOWN", "EXPIRED"},
            "DELIVERED": {"DELIVERED", "EXECUTED", "FAILED", "UNKNOWN", "EXPIRED"},
            "UNKNOWN": {"EXECUTED", "FAILED"},
            "FAILED": set(),
            "REJECTED": set(),
            "EXPIRED": set(),
            "EXECUTED": set(),
        }
        if target not in allowed.get(row.status, set()):
            raise ValueError(f"invalid command transition: {row.status} -> {target}")
        row.status = target
        row.payload = (
            row.payload
            | changes
            | {
                "attempts": row.payload.get("attempts", 0) + attempts,
                "reason": reason,
                "updated_at": now.isoformat(),
            }
        )
        revision = {"status": target, **row.payload}
        session.add(CommandRevision(command_id=row.id, created_at=now, payload=revision))
        audit(
            session,
            row.id,
            row.correlation_id,
            "command_transition",
            revision,
            now,
            actor="actuator-manager",
        )
        session.flush()

    @staticmethod
    def serialize(row: ActuatorCommandRecord) -> dict:
        return {
            "command_id": str(row.id),
            "correlation_id": str(row.correlation_id),
            "created_at": utc(row.occurred_at).isoformat(),
            "actuator_id": row.actuator_id,
            "status": row.status,
            **row.payload,
        }
