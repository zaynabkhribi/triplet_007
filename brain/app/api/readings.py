import asyncio

from fastapi import APIRouter, Depends, Request

from app.api.ingestion import persist, persist_batch
from app.database.models import SensorEvent
from app.schemas.sensor import SensorReading
from app.security.authorization import require_role

router = APIRouter(prefix="/readings", tags=["readings"])


@router.post("", status_code=202, dependencies=[Depends(require_role("twin"))])
async def receive_readings(event: SensorReading, request: Request) -> dict[str, str]:
    return await asyncio.to_thread(
        persist,
        request,
        event,
        SensorEvent,
        event.event_id,
        event.occurred_at,
        sensor_id=event.sensor_id,
    )


@router.post("/batch", status_code=202, dependencies=[Depends(require_role("twin"))])
async def receive_reading_batch(
    events: list[SensorReading], request: Request
) -> list[dict[str, str]]:
    return await asyncio.to_thread(persist_batch, request, events)
