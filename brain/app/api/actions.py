import asyncio
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from app.database.models import ActuatorCommandRecord, CommandRevision
from app.schemas.actuator import ActuatorFeedback
from app.security.authorization import require_role
from app.security.validation import require_reasonable_timestamp

router = APIRouter(prefix="/v1/actions", tags=["actions"])
reader = Depends(require_role("brain", "guardian", "twin"))


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision_id: UUID


@router.post("/execute", dependencies=[Depends(require_role("brain"))])
async def execute(event: ExecuteRequest, request: Request) -> dict:
    def create() -> list[dict]:
        with request.app.state.database.transaction() as session:
            now = datetime.now(UTC)
            state = request.app.state.city_engine.rebuild(session, now)
            return request.app.state.actuator_manager.enqueue(
                session,
                state,
                event.decision_id,
                now,
            )

    try:
        commands = await asyncio.to_thread(create)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    return {
        "commands": commands,
        "dispatch_enabled": request.app.state.settings.actuator_execution_enabled,
    }


def read(
    request: Request,
    limit: int,
    identifier: UUID | None = None,
    history: bool = False,
) -> list | dict:
    with request.app.state.database.transaction() as session:
        if history:
            query = select(CommandRevision)
            if identifier:
                query = query.where(CommandRevision.command_id == identifier)
            return [
                {
                    "revision_id": row.id,
                    "command_id": str(row.command_id),
                    "created_at": row.created_at,
                    **row.payload,
                }
                for row in session.scalars(query.order_by(CommandRevision.id.desc()).limit(limit))
            ]
        if identifier:
            row = session.get(ActuatorCommandRecord, identifier)
            if row is None:
                raise HTTPException(404, "command not found")
            return request.app.state.actuator_manager.serialize(row)
        rows = session.scalars(
            select(ActuatorCommandRecord)
            .order_by(
                ActuatorCommandRecord.occurred_at.desc(),
                ActuatorCommandRecord.id,
            )
            .limit(limit)
        )
        return [request.app.state.actuator_manager.serialize(row) for row in rows]


@router.get("", dependencies=[reader])
async def list_actions(request: Request, limit: int = Query(100, ge=1, le=1000)) -> list:
    return await asyncio.to_thread(read, request, limit)


@router.get("/history", dependencies=[reader])
async def history(
    request: Request, command_id: UUID | None = None, limit: int = Query(100, ge=1, le=1000)
) -> list:
    return await asyncio.to_thread(read, request, limit, command_id, True)


@router.get("/{command_id}", dependencies=[reader])
async def detail(command_id: UUID, request: Request) -> dict:
    return await asyncio.to_thread(read, request, 1, command_id)


@router.post("/{command_id}/feedback", dependencies=[Depends(require_role("twin"))])
async def feedback(command_id: UUID, event: ActuatorFeedback, request: Request) -> dict:
    if command_id != event.command_id:
        raise HTTPException(409, "feedback command ID does not match path")
    return await _feedback(event, request)


async def _feedback(event: ActuatorFeedback, request: Request) -> dict:
    require_reasonable_timestamp(
        event.occurred_at,
        request.app.state.settings.replay_window_seconds,
    )
    try:
        return await asyncio.to_thread(
            request.app.state.actuator_manager.record_feedback,
            event,
            datetime.now(UTC),
        )
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
