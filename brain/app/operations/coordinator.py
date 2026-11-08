import asyncio
import logging
from contextlib import suppress
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select

from app.database.models import ActuatorCommandRecord, DecisionRecord

logger = logging.getLogger(__name__)


class OperationalCoordinator:
    def __init__(self, database, settings, city_engine, actuator_manager) -> None:
        self.database = database
        self.settings = settings
        self.city = city_engine
        self.actuators = actuator_manager
        self._stop = asyncio.Event()

    async def run(self) -> None:
        while not self._stop.is_set():
            try:
                created = await asyncio.to_thread(self.coordinate)
                if created and self.settings.actuator_execution_enabled:
                    await self.actuators.tick()
            except Exception:
                logger.exception("operational_coordination_failed")
            with suppress(TimeoutError):
                await asyncio.wait_for(
                    self._stop.wait(), self.settings.operational_coordination_seconds
                )

    def stop(self) -> None:
        self._stop.set()

    def coordinate(self) -> bool:
        now = datetime.now(UTC)
        with self.database.transaction() as session:
            state = self.city.rebuild(session, now)
            code, decision = self.city.decisions.evaluate(session, state, uuid4())
            if code != 200 or decision["status"] in {"REJECTED", "CANCELLED"}:
                return False
            if decision["status"] == "EVALUATED" and decision.get("selected_actions"):
                if not (
                    self.settings.operational_auto_approve
                    and self.city.decisions.policy
                    and self.city.decisions.policy.simulation_only
                ):
                    return False
                code, decision = self.city.decisions.evaluate(
                    session,
                    state,
                    uuid4(),
                    UUID(decision["decision_id"]),
                    "approved standalone mock operation",
                )
                if code != 200:
                    return False
            if decision["status"] != "APPROVED":
                return False
            row = session.get(DecisionRecord, UUID(decision["decision_id"]))
            if row is None or row.payload.get("commands_created"):
                return False
            incident_ids = {
                action["incident_id"] for action in row.payload.get("approved_actions", [])
            }
            prior = session.scalars(select(ActuatorCommandRecord)).all()
            if any(
                command.payload.get("candidate", {}).get("incident_id") in incident_ids
                and command.status not in {"REJECTED", "FAILED", "EXPIRED"}
                for command in prior
            ):
                row.payload = row.payload | {"commands_created": True}
                return False
            commands = self.actuators.enqueue(session, state, row.id, datetime.now(UTC))
            row.payload = row.payload | {"commands_created": True}
            return bool(commands)
