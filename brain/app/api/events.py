import asyncio
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select

from app.database.models import AuditEvent, EventLifecycle, GuardianVerdictRecord, SensorEvent
from app.security.authorization import require_role
from app.security.trust_engine import quarantined
from app.state.lifecycle import utc

router = APIRouter(
    dependencies=[Depends(require_role("brain", "guardian", "twin"))], tags=["trust"]
)


def event_status(request: Request, event_id: UUID) -> dict:
    with request.app.state.database.transaction() as session:
        row = session.get(EventLifecycle, event_id)
        if row is None:
            raise HTTPException(404, "event not found")
        now = datetime.now(UTC)
        eligible = row.eligible and row.eligible_until is not None and utc(row.eligible_until) > now
        trust_state = (
            row.state.lower()
            if row.state
            in {
                "TRUSTED",
                "UNTRUSTED",
                "UNCERTAIN",
                "EXPIRED",
            }
            else "pending"
        )
        if row.processing in {"retry", "failed"}:
            trust_state = "uncertain"
        elif row.eligible and not eligible:
            trust_state = "expired"
        return {
            "event_id": str(event_id),
            "state": row.state,
            "processing": row.processing,
            "trust_state": trust_state,
            "eligible": eligible,
            "reason": row.reason,
            "attempts": row.attempts,
            "verdict_id": str(row.verdict_id) if row.verdict_id else None,
            "acknowledged_at": row.acknowledged_at,
            "next_attempt_at": row.available_at,
            "last_error": row.last_error,
        }


@router.get("/events/{event_id}")
async def get_event(event_id: UUID, request: Request) -> dict:
    return await asyncio.to_thread(event_status, request, event_id)


@router.get("/events/{event_id}/history")
async def get_history(event_id: UUID, request: Request, limit: int = 100, offset: int = 0) -> dict:
    if not 1 <= limit <= 1000 or offset < 0:
        raise HTTPException(422, "invalid pagination")

    def read() -> dict:
        with request.app.state.database.transaction() as session:
            if session.get(SensorEvent, event_id) is None:
                raise HTTPException(404, "event not found")
            verdicts = session.scalars(
                select(GuardianVerdictRecord)
                .where(
                    GuardianVerdictRecord.event_id == event_id,
                )
                .order_by(GuardianVerdictRecord.occurred_at, GuardianVerdictRecord.id)
                .offset(offset)
                .limit(limit)
            ).all()
            events = session.scalars(
                select(AuditEvent)
                .where(
                    AuditEvent.payload["event_id"].as_string() == str(event_id),
                )
                .order_by(AuditEvent.payload["sequence"].as_integer(), AuditEvent.occurred_at)
                .offset(offset)
                .limit(limit)
            ).all()
            return {
                "verdicts": [record.payload["event"] for record in verdicts],
                "audit": [
                    {"action": record.action, "at": record.occurred_at, "detail": record.payload}
                    for record in events
                ],
            }

    return await asyncio.to_thread(read)


@router.get("/quarantines/{target_type}/{target_id}")
async def get_quarantine(target_type: str, target_id: str, request: Request) -> dict:
    if target_type not in {"sensor", "actuator"}:
        raise HTTPException(422, "invalid target type")

    def read() -> dict:
        with request.app.state.database.transaction() as session:
            return {
                "target_type": target_type,
                "target_id": target_id,
                "quarantined": quarantined(session, target_type, target_id),
            }

    return await asyncio.to_thread(read)


@router.get("/state/trusted")
async def get_trusted_state(request: Request) -> dict:
    return await asyncio.to_thread(request.app.state.state_manager.snapshot)
