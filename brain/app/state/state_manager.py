from datetime import UTC, datetime

from sqlalchemy import select

from app.database.models import EventLifecycle, SensorEvent
from app.database.session import Database
from app.security.trust_engine import quarantined
from app.state.city_state import CityState
from app.state.lifecycle import utc


class StateManager:
    def __init__(self, database: Database | None = None) -> None:
        self._current: CityState | None = None
        self.database = database

    def snapshot(self) -> dict:
        if self.database is None:
            raise RuntimeError("persistent state requires a database")
        now = datetime.now(UTC)
        with self.database.transaction() as session:
            rows = session.execute(
                select(SensorEvent, EventLifecycle)
                .outerjoin(
                    EventLifecycle,
                    SensorEvent.id == EventLifecycle.event_id,
                )
                .order_by(SensorEvent.occurred_at.desc(), SensorEvent.id.desc())
            ).all()
            seen, values = {}, {}
            for reading, lifecycle in rows:
                if reading.sensor_id in seen:
                    if utc(reading.occurred_at) == seen[reading.sensor_id]:
                        values.pop(reading.sensor_id, None)
                    continue
                seen[reading.sensor_id] = utc(reading.occurred_at)
                if (
                    lifecycle is not None
                    and lifecycle.eligible
                    and lifecycle.eligible_until is not None
                    and utc(lifecycle.eligible_until) > now
                    and not quarantined(session, "sensor", reading.sensor_id)
                ):
                    values[reading.sensor_id] = reading.payload["event"]
            return {"as_of": now, "sensors": values}

    @property
    def current(self) -> CityState | None:
        return self._current

    def update(self, state: CityState) -> None:
        if self.database is not None:
            raise ValueError("persistent operational state only accepts verified event evidence")
        self._current = state
