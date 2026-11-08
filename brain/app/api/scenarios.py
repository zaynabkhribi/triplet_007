from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.scenarios import SCENARIOS
from app.security.authorization import require_role

router = APIRouter(prefix="/v1/scenarios", tags=["scenarios"])


@router.get("", dependencies=[Depends(require_role("brain", "guardian", "twin"))])
async def scenarios(request: Request, limit: int = Query(100, ge=1, le=1000)) -> dict:
    return {
        "catalog": SCENARIOS,
        "executions": request.app.state.scenarios.list_executions(limit),
    }


@router.post("/{scenario_id}/run", dependencies=[Depends(require_role("brain"))])
async def run(scenario_id: str, request: Request) -> dict:
    try:
        return await request.app.state.scenarios.run(scenario_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.post("/reset", dependencies=[Depends(require_role("brain"))])
async def reset(request: Request) -> dict:
    return request.app.state.scenarios.reset()


@router.get(
    "/executions/{execution_id}", dependencies=[Depends(require_role("brain", "guardian", "twin"))]
)
async def execution(execution_id: UUID, request: Request) -> dict:
    try:
        return request.app.state.scenarios.get(execution_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
