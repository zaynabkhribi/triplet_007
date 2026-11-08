from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import EventLifecycle, SensorEvent
from app.state.lifecycle import audit


def recover_legacy_events(session: Session, now: datetime, limit: int) -> None:
    readings = session.scalars(
        select(SensorEvent)
        .outerjoin(
            EventLifecycle,
            SensorEvent.id == EventLifecycle.event_id,
        )
        .where(EventLifecycle.event_id.is_(None))
        .limit(limit)
    ).all()
    for reading in readings:
        session.add(
            EventLifecycle(
                event_id=reading.id,
                state="RECEIVED",
                processing="queued",
                received_at=now,
                available_at=now,
                eligible=False,
                attempts=0,
            )
        )
        audit(session, reading.id, reading.correlation_id, "event_recovered", {}, now)
    session.flush()
