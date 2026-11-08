import asyncio

from fastapi import APIRouter, Depends, Request

from app.api.actions import _feedback
from app.api.ingestion import persist
from app.database.models import ActuatorFeedbackRecord
from app.schemas.actuator import ActuatorFeedback
from app.security.authorization import require_role

router = APIRouter(prefix="/feedback", tags=["feedback"])


@router.post("", status_code=202, dependencies=[Depends(require_role("twin"))])
async def receive_feedback(event: ActuatorFeedback, request: Request) -> dict[str, str]:
    try:
        return await _feedback(event, request)
    except Exception as exc:
        if getattr(exc, "status_code", None) != 404:
            raise
        return await asyncio.to_thread(
            persist,
            request,
            event,
            ActuatorFeedbackRecord,
            event.feedback_id,
            event.occurred_at,
            command_id=event.command_id,
            status=event.status.value,
        )
