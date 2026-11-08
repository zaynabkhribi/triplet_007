import asyncio

from fastapi import APIRouter, Depends, Request

from app.api.ingestion import persist, persist_batch
from app.database.models import GuardianVerdictRecord, QuarantineRecord
from app.schemas.guardian import GuardianVerdict, QuarantineNotification
from app.security.authorization import require_role

router = APIRouter(tags=["verdicts"], dependencies=[Depends(require_role("guardian"))])


@router.post("/verdicts", status_code=202)
async def receive_verdicts(event: GuardianVerdict, request: Request) -> dict[str, str]:
    return await asyncio.to_thread(
        persist,
        request,
        event,
        GuardianVerdictRecord,
        event.verdict_id,
        event.issued_at,
        event_id=event.event_id,
        status=event.status.value,
    )


@router.post("/verdicts/batch", status_code=202)
async def receive_verdict_batch(
    events: list[GuardianVerdict], request: Request
) -> list[dict[str, str]]:
    return await asyncio.to_thread(persist_batch, request, events)


@router.post("/quarantines", status_code=202)
async def receive_quarantine(event: QuarantineNotification, request: Request) -> dict[str, str]:
    return await asyncio.to_thread(
        persist,
        request,
        event,
        QuarantineRecord,
        event.notification_id,
        event.issued_at,
        target_type=event.target_type,
        target_id=event.target_id,
    )
