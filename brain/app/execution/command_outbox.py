from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import ActuatorCommandRecord

ACTIVE_COMMAND_STATES = {"PENDING", "DISPATCHING", "DELIVERED"}
FINAL_COMMAND_STATES = {"EXECUTED", "REJECTED", "FAILED", "EXPIRED", "UNKNOWN"}


def due(session: Session, now: datetime) -> ActuatorCommandRecord | None:
    rows = session.scalars(
        select(ActuatorCommandRecord)
        .where(ActuatorCommandRecord.status.in_(["PENDING", "DELIVERED"]))
        .order_by(ActuatorCommandRecord.occurred_at, ActuatorCommandRecord.id)
    ).all()
    return next(
        (
            row
            for row in rows
            if row.payload.get("next_attempt_at") is None
            or datetime.fromisoformat(row.payload["next_attempt_at"]) <= now
        ),
        None,
    )
