import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from app.database.models import DecisionRecord, DecisionRevision
from app.decision.engine import serialize
from app.security.authorization import require_role

router = APIRouter(tags=["decisions"])
reader = Depends(require_role("brain", "guardian", "twin"))


class Approval(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    decision_id: UUID
    reason: str = Field(min_length=1, max_length=512)


class EvaluationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    correlation_id: UUID = Field(default_factory=uuid4)
    approval: Approval | None = None


@router.post("/v1/decisions/evaluate", dependencies=[Depends(require_role("brain"))])
async def evaluate(event: EvaluationRequest, request: Request) -> dict:
    def run() -> tuple[int, dict]:
        city = request.app.state.city_engine
        with request.app.state.database.transaction() as session:
            state = city.rebuild(session, datetime.now(UTC))
            return city.decisions.evaluate(
                session,
                state,
                event.correlation_id,
                event.approval.decision_id if event.approval else None,
                event.approval.reason if event.approval else None,
            )

    code, result = await asyncio.to_thread(run)
    if code != 200:
        raise HTTPException(code, result)
    return result


def read(
    request: Request, limit: int, identifier: UUID | None = None, history: bool = False
) -> list | dict:
    with request.app.state.database.transaction() as session:
        request.app.state.city_engine.rebuild(session, datetime.now(UTC))
        if history:
            query = select(DecisionRevision)
            if identifier:
                query = query.where(DecisionRevision.decision_id == identifier)
            return [
                {
                    "revision_id": r.id,
                    "decision_id": str(r.decision_id),
                    "created_at": r.created_at,
                    **r.payload,
                }
                for r in session.scalars(query.order_by(DecisionRevision.id.desc()).limit(limit))
            ]
        if identifier:
            row = session.get(DecisionRecord, identifier)
            if row is None:
                raise HTTPException(404, "decision not found")
            return serialize(row)
        return [
            serialize(row)
            for row in session.scalars(
                select(DecisionRecord)
                .order_by(
                    DecisionRecord.occurred_at.desc(),
                    DecisionRecord.id,
                )
                .limit(limit)
            )
        ]


@router.get("/decisions", dependencies=[reader], include_in_schema=False)
@router.get("/v1/decisions", dependencies=[reader])
async def list_decisions(request: Request, limit: int = Query(100, ge=1, le=1000)) -> list:
    return await asyncio.to_thread(read, request, limit)


@router.get("/v1/decisions/history", dependencies=[reader])
async def history(
    request: Request, decision_id: UUID | None = None, limit: int = Query(100, ge=1, le=1000)
) -> list:
    return await asyncio.to_thread(read, request, limit, decision_id, True)


@router.get("/v1/decisions/{decision_id}", dependencies=[reader])
async def detail(decision_id: UUID, request: Request) -> dict:
    return await asyncio.to_thread(read, request, 1, decision_id)
