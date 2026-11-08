import asyncio

from fastapi import APIRouter, Request
from pydantic import BaseModel
from sqlalchemy import text

router = APIRouter(prefix="/health", tags=["health"])


class HealthResponse(BaseModel):
    status: str


@router.get("/live", response_model=HealthResponse)
async def live() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/ready", response_model=HealthResponse)
async def ready(request: Request) -> HealthResponse:
    def check() -> None:
        with request.app.state.database.transaction() as session:
            session.execute(text("SELECT 1"))

    await asyncio.to_thread(check)
    return HealthResponse(status="ready")
