import asyncio
from datetime import datetime
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from app.database.models import ForecastRecord
from app.intelligence.inference import currently_eligible, run_inference
from app.security.authorization import require_role

router = APIRouter(
    prefix="/v1",
    tags=["inference"],
    dependencies=[Depends(require_role("brain", "guardian", "twin"))],
)


class ForecastRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sensor_id: str = Field(min_length=1, max_length=128)
    correlation_id: UUID = Field(default_factory=uuid4)
    horizons_minutes: list[int] = Field(min_length=1, max_length=3)
    origin: datetime | None = None


@router.get("/models")
@router.get("/models/status")
async def models(request: Request) -> list[dict]:
    return request.app.state.artifacts.status()


@router.post("/forecasts/{family}")
async def forecast(
    family: Literal["traffic", "water"],
    event: ForecastRequest,
    request: Request,
) -> dict:
    allowed = {"traffic": {15, 30, 60}, "water": {60, 180, 360}}
    if not set(event.horizons_minutes) <= allowed[family]:
        raise HTTPException(422, "unsupported horizons")
    code, detail = await asyncio.to_thread(
        run_inference,
        request.app.state.database,
        request.app.state.settings,
        request.app.state.artifacts,
        family,
        event,
    )
    if code != 200:
        raise HTTPException(code, detail)
    return detail


@router.get("/forecasts/history")
async def history(request: Request, limit: int = Query(100, ge=1, le=1000)) -> list[dict]:
    def read() -> list[dict]:
        with request.app.state.database.transaction() as session:
            rows = session.scalars(
                select(ForecastRecord)
                .order_by(
                    ForecastRecord.occurred_at.desc(),
                    ForecastRecord.id,
                )
                .limit(limit)
            ).all()
            return [
                {
                    "forecast_id": str(row.id),
                    "family": row.family,
                    "status": row.status,
                    "created_at": row.occurred_at,
                    "currently_eligible": currently_eligible(
                        session,
                        request.app.state.settings,
                        row.payload,
                    ),
                    **row.payload,
                }
                for row in rows
            ]

    return await asyncio.to_thread(read)
