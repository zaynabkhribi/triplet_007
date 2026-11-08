import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select

from app.database.models import CitySnapshot
from app.security.authorization import require_role

router = APIRouter(
    prefix="/v1/city",
    tags=["city"],
    dependencies=[Depends(require_role("brain", "guardian", "twin"))],
)


@router.get("/state")
async def state(request: Request) -> dict:
    return await asyncio.to_thread(request.app.state.city_engine.snapshot)


@router.get("/zones")
async def zones(request: Request) -> dict:
    return (await state(request))["zones"]


@router.get("/zones/{zone_id}")
async def zone(zone_id: str, request: Request) -> dict:
    result = (await zones(request)).get(zone_id)
    if result is None:
        raise HTTPException(404, "zone not registered")
    return result


@router.get("/sensors")
async def sensors(request: Request) -> dict:
    return (await state(request))["sensors"]


@router.get("/sensors/{sensor_id}")
async def sensor(sensor_id: str, request: Request) -> dict:
    result = (await sensors(request)).get(sensor_id)
    if result is None:
        raise HTTPException(404, "sensor not registered")
    return result


@router.get("/history")
async def history(
    request: Request,
    after_version: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
) -> list[dict]:
    def read() -> list[dict]:
        with request.app.state.database.transaction() as session:
            rows = session.scalars(
                select(CitySnapshot)
                .where(
                    CitySnapshot.version > after_version,
                )
                .order_by(CitySnapshot.version)
                .limit(limit)
            ).all()
            return [
                {"version": row.version, "created_at": row.created_at, **row.payload}
                for row in rows
            ]

    return await asyncio.to_thread(read)
