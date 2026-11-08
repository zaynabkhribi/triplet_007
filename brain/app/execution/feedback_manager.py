from datetime import datetime

from sqlalchemy.orm import Session

from app.database.models import ActuatorCommandRecord
from app.schemas.actuator import ActuatorFeedback

FEEDBACK_TARGET = {
    "accepted": "DELIVERED",
    "executed": "EXECUTED",
    "failed": "FAILED",
    "unknown": "UNKNOWN",
}


def reconcile_feedback(
    session: Session,
    command: ActuatorCommandRecord,
    feedback: ActuatorFeedback,
    now: datetime,
) -> tuple[str, dict]:
    if command.correlation_id != feedback.correlation_id:
        raise ValueError("feedback correlation mismatch")
    target = FEEDBACK_TARGET[feedback.status.value]
    if command.status in {"REJECTED", "EXPIRED"}:
        raise ValueError("feedback cannot revive terminal command")
    if command.status == "EXECUTED" and target != "EXECUTED":
        raise ValueError("feedback conflicts with executed command")
    return target, {
        "feedback_id": str(feedback.feedback_id),
        "feedback_status": feedback.status.value,
        "feedback_detail": feedback.detail,
        "feedback_at": feedback.occurred_at.isoformat(),
        "reconciled_at": now.isoformat(),
    }
