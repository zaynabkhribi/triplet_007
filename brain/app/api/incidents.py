import asyncio
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select

from app.database.models import IncidentRecord, IncidentRevision
from app.security.authorization import require_role

router = APIRouter(
    tags=["incidents"], dependencies=[Depends(require_role("brain", "guardian", "twin"))]
)


def serialize(row: IncidentRecord) -> dict:
    return {
        "incident_id": str(row.id),
        "correlation_id": str(row.correlation_id),
        "detected_at": row.occurred_at,
        **row.payload,
    }


def read(request: Request, view: str, limit: int, identifier: UUID | None = None) -> list | dict:
    with request.app.state.database.transaction() as session:
        request.app.state.city_engine.rebuild(session, datetime.now(UTC))
        if view == "history":
            query = select(IncidentRevision)
            if identifier:
                query = query.where(IncidentRevision.incident_id == identifier)
            rows = session.scalars(query.order_by(IncidentRevision.id.desc()).limit(limit))
            return [
                {
                    "revision_id": r.id,
                    "incident_id": str(r.incident_id),
                    "created_at": r.created_at,
                    **r.payload,
                }
                for r in rows
            ]
        if identifier:
            row = session.get(IncidentRecord, identifier)
            if row is None:
                raise HTTPException(404, "incident not found")
            return serialize(row)
        query = select(IncidentRecord)
        if view == "active":
            query = query.where(
                IncidentRecord.payload["status"]
                .as_string()
                .in_(
                    ["DETECTED", "ACTIVE", "ESCALATED"],
                )
            )
        return [
            serialize(row)
            for row in session.scalars(
                query.order_by(
                    IncidentRecord.occurred_at.desc(),
                    IncidentRecord.id,
                ).limit(limit)
            )
        ]


@router.get("/incidents", include_in_schema=False)
@router.get("/v1/incidents")
async def list_incidents(request: Request, limit: int = Query(100, ge=1, le=1000)) -> list:
    return await asyncio.to_thread(read, request, "all", limit)


@router.get("/v1/incidents/active")
async def active(request: Request, limit: int = Query(100, ge=1, le=1000)) -> list:
    return await asyncio.to_thread(read, request, "active", limit)


@router.get("/v1/incidents/history")
async def history(
    request: Request,
    incident_id: UUID | None = None,
    limit: int = Query(100, ge=1, le=1000),
) -> list:
    return await asyncio.to_thread(read, request, "history", limit, incident_id)


@router.get("/v1/incidents/{incident_id}")
async def detail(incident_id: UUID, request: Request) -> dict:
    return await asyncio.to_thread(read, request, "detail", 1, incident_id)
