import asyncio
import json
import math
import statistics
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import func, select, text

from app.dashboard.security import (
    COOKIE_NAME,
    dashboard_session,
    require_csrf,
    require_dashboard_role,
)
from app.database.models import (
    ActuatorCommandRecord,
    AuditEvent,
    DecisionRecord,
    EventLifecycle,
    ForecastRecord,
    GuardianVerdictRecord,
    IncidentRecord,
    QuarantineRecord,
    ScenarioLog,
    SensorEvent,
)
from app.intelligence.inference import currently_eligible
from app.scenarios import SCENARIOS
from app.security.authentication import authenticate_service
from app.security.trust_engine import quarantined
from app.state.lifecycle import utc

router = APIRouter(tags=["dashboard"])
STATIC = Path(__file__).resolve().parent / "static"


@router.get("/dashboard", include_in_schema=False)
async def dashboard() -> FileResponse:
    return FileResponse(
        STATIC / "index.html",
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": (
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
                "frame-ancestors 'none'"
            ),
        },
    )


@router.post("/dashboard/session", include_in_schema=False)
async def create_session(
    request: Request,
    response: Response,
    role: str = Depends(authenticate_service),
) -> dict:
    token, session = request.app.state.dashboard_sessions.create(role)
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        max_age=request.app.state.settings.dashboard_session_seconds,
        path="/",
    )
    return {"role": role, "csrf": session.csrf, "expires_at": session.expires_at}


@router.get("/dashboard/session", include_in_schema=False)
async def get_session(request: Request) -> dict:
    session = dashboard_session(request)
    return {
        "role": session.role,
        "csrf": session.csrf,
        "expires_at": session.expires_at,
    }


@router.delete("/dashboard/session", include_in_schema=False)
async def delete_session(request: Request, response: Response) -> dict:
    session = dashboard_session(request)
    require_csrf(request, session)
    request.app.state.dashboard_sessions.revoke(request.cookies.get(COOKIE_NAME))
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"status": "signed_out"}


def _record(row, identifier: str, status: str) -> dict:
    return {
        "id": str(row.id),
        "at": utc(row.occurred_at).isoformat(),
        "status": status,
        **row.payload,
        "record_type": identifier,
    }


def snapshot(request: Request) -> dict:
    with request.app.state.database.transaction() as session:
        now = datetime.now(UTC)
        state = request.app.state.city_engine.rebuild(session, now)
        incidents = session.scalars(
            select(IncidentRecord)
            .order_by(
                IncidentRecord.occurred_at.desc(),
                IncidentRecord.id,
            )
            .limit(100)
        ).all()
        decisions = session.scalars(
            select(DecisionRecord)
            .order_by(
                DecisionRecord.occurred_at.desc(),
                DecisionRecord.id,
            )
            .limit(100)
        ).all()
        commands = session.scalars(
            select(ActuatorCommandRecord)
            .order_by(
                ActuatorCommandRecord.occurred_at.desc(),
                ActuatorCommandRecord.id,
            )
            .limit(100)
        ).all()
        forecasts = session.scalars(
            select(ForecastRecord)
            .where(
                ForecastRecord.status == "succeeded",
            )
            .order_by(ForecastRecord.occurred_at.desc())
            .limit(30)
        ).all()
        readings = session.execute(
            select(SensorEvent, EventLifecycle)
            .outerjoin(
                EventLifecycle,
                SensorEvent.id == EventLifecycle.event_id,
            )
            .order_by(SensorEvent.occurred_at.desc())
            .limit(100)
        ).all()
        verdicts = session.scalars(
            select(GuardianVerdictRecord)
            .order_by(
                GuardianVerdictRecord.occurred_at.desc(),
                GuardianVerdictRecord.id,
            )
            .limit(100)
        ).all()
        quarantine_history = session.scalars(
            select(QuarantineRecord)
            .order_by(
                QuarantineRecord.occurred_at.desc(),
                QuarantineRecord.id,
            )
            .limit(100)
        ).all()
        window_start = now - timedelta(seconds=60)
        recent_lifecycles = session.scalars(
            select(EventLifecycle)
            .where(
                EventLifecycle.acknowledged_at.is_not(None),
                EventLifecycle.received_at >= window_start,
            )
            .order_by(EventLifecycle.acknowledged_at.desc())
            .limit(1000)
        ).all()
        latencies = sorted(
            (utc(row.acknowledged_at) - utc(row.received_at)).total_seconds() * 1000
            for row in recent_lifecycles
        )
        ten_seconds_ago = now - timedelta(seconds=10)
        incoming_recent = session.scalar(
            select(func.count())
            .select_from(SensorEvent)
            .where(SensorEvent.occurred_at >= ten_seconds_ago)
        )
        processed = session.scalar(
            select(func.count())
            .select_from(EventLifecycle)
            .where(EventLifecycle.processing == "acknowledged")
        )
        trusted = session.scalar(
            select(func.count())
            .select_from(EventLifecycle)
            .where(EventLifecycle.state == "TRUSTED")
        )
        rejected = session.scalar(
            select(func.count())
            .select_from(EventLifecycle)
            .where(EventLifecycle.state.in_(["UNTRUSTED", "UNCERTAIN", "EXPIRED"]))
        )
        backlog = session.scalar(
            select(func.count())
            .select_from(EventLifecycle)
            .where(EventLifecycle.processing != "acknowledged")
        )
        session.execute(text("SELECT 1"))
        security = [
            {
                "type": "trust",
                "event_id": str(event.id),
                "state": lifecycle.state,
                "reason": lifecycle.reason,
            }
            for event, lifecycle in readings
            if lifecycle is not None and lifecycle.state in {"UNTRUSTED", "UNCERTAIN", "EXPIRED"}
        ] + [
            {
                "type": "quarantine",
                "target_type": row.target_type,
                "target_id": row.target_id,
                "event": row.payload["event"],
            }
            for row in quarantine_history
            if row.payload["event"]["action"] == "quarantine"
            and quarantined(session, row.target_type, row.target_id)
        ]
        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "health": {"database": "ready"},
            "environment": "mock-development"
            if request.app.state.settings.operational_demo_enabled
            else request.app.state.settings.environment,
            "metrics": {
                "incoming_events_per_second": round((incoming_recent or 0) / 10, 2),
                "processed_observations": processed or 0,
                "trusted_readings": trusted or 0,
                "rejected_readings": rejected or 0,
                "active_incidents": sum(
                    row.payload["status"] in {"DETECTED", "ACTIVE", "ESCALATED"}
                    for row in incidents
                ),
                "approved_decisions": sum(row.status == "APPROVED" for row in decisions),
                "rejected_decisions": sum(row.status == "REJECTED" for row in decisions),
                "executed_commands": sum(row.status == "EXECUTED" for row in commands),
                "backlog": backlog or 0,
                "processing_errors": sum(row.processing == "failed" for row in recent_lifecycles),
                "latency_p50_ms": round(statistics.median(latencies), 2) if latencies else None,
                "latency_p95_ms": round(
                    latencies[max(0, math.ceil(len(latencies) * 0.95) - 1)], 2
                )
                if latencies
                else None,
            },
            "models": request.app.state.artifacts.status(),
            "city": state,
            "incidents": [_record(row, "incident", row.payload["status"]) for row in incidents],
            "decisions": [_record(row, "decision", row.status) for row in decisions],
            "actions": [request.app.state.actuator_manager.serialize(row) for row in commands],
            "forecasts": [
                _record(row, "forecast", row.status)
                | {
                    "currently_eligible": currently_eligible(
                        session,
                        request.app.state.settings,
                        row.payload,
                        datetime.now(UTC),
                    )
                }
                for row in forecasts
            ],
            "readings": [
                {
                    "event_id": str(event.id),
                    "sensor_id": event.sensor_id,
                    "at": utc(event.occurred_at).isoformat(),
                    "value": event.payload["event"]["value"],
                    "unit": event.payload["event"]["unit"],
                    "trust": lifecycle.state if lifecycle else "RECEIVED",
                }
                for event, lifecycle in readings
            ],
            "verdicts": [row.payload["event"] for row in verdicts],
            "security_alerts": security,
        }
async def provider_status(request: Request) -> dict:
    settings = request.app.state.settings
    headers = (
        {"X-API-Key": settings.brain_api_key.get_secret_value()}
        if settings.brain_api_key
        else {}
    )
    async with httpx.AsyncClient(timeout=2, trust_env=False) as client:
        async def get(url: object, path: str, protected: bool = False) -> dict:
            if not url:
                return {"connected": False, "reason": "not_configured"}
            try:
                response = await client.get(
                    str(url).rstrip("/") + path,
                    headers=headers if protected else {},
                )
                response.raise_for_status()
                return {"connected": True, **response.json()}
            except (httpx.HTTPError, ValueError):
                return {"connected": False, "reason": "unavailable"}

        twin, guardian = await asyncio.gather(
            get(settings.twin_base_url, "/operations", True),
            get(settings.guardian_base_url, "/health"),
        )
    return {
        "brain": {"connected": True, "processing": settings.worker_enabled},
        "twin": twin,
        "guardian": guardian,
    }


def timeline(
    request: Request,
    limit: int = 200,
    important_only: bool = False,
) -> list[dict]:
    with request.app.state.database.transaction() as session:
        query = select(AuditEvent)

        if important_only:
            query = query.where(
                AuditEvent.action.in_([
                    "incident_updated",
                    "decision_transition",
                    "command_transition",
                    "event_processing_failed",
                    "forecast_failed",
                ])
            )

        audit = session.scalars(
            query.order_by(
                AuditEvent.occurred_at.desc(),
                AuditEvent.id.desc(),
            ).limit(limit)
        ).all()

        scenarios = [] if important_only else session.scalars(
            select(ScenarioLog)
            .order_by(
                ScenarioLog.occurred_at.desc(),
                ScenarioLog.id.desc(),
            )
            .limit(limit)
        ).all()

        rows = [
            {
                "key": f"audit:{row.id}",
                "at": utc(row.occurred_at).isoformat(),
                "source": row.actor,
                "stage": row.action,
                "status": "RECORDED",
                "event_id": row.payload.get("event_id"),
                "detail": row.payload,
            }
            for row in audit
        ] + [
            {
                "key": f"scenario:{row.id}",
                "at": utc(row.occurred_at).isoformat(),
                "source": "scenario",
                "stage": row.stage,
                "status": row.status,
                "execution_id": str(row.execution_id),
                "detail": row.detail,
            }
            for row in scenarios
        ]

        return sorted(
            rows,
            key=lambda item: (item["at"], item["key"]),
            reverse=True,
        )[:limit]


@router.get("/dashboard/api/snapshot", include_in_schema=False)
async def dashboard_snapshot(request: Request) -> dict:
    require_dashboard_role(request, "brain", "guardian", "twin")
    return await asyncio.to_thread(snapshot, request)


@router.get("/dashboard/api/operations", include_in_schema=False)
async def dashboard_operations(request: Request) -> dict:
    require_dashboard_role(request, "brain", "guardian", "twin")
    return await provider_status(request)


@router.post("/dashboard/api/operations/{action}", include_in_schema=False)
async def control_operations(action: str, request: Request) -> dict:
    session = require_dashboard_role(request, "brain")
    require_csrf(request, session)
    if action not in {"start", "stop", "reset", "inject", "clear"}:
        raise HTTPException(422, "invalid operational control")
    payload = await request.json() if await request.body() else {}
    settings = request.app.state.settings
    if not settings.twin_base_url or not settings.brain_api_key:
        raise HTTPException(503, "Mock Twin is not configured")
    async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
        try:
            response = await client.post(
                str(settings.twin_base_url).rstrip("/") + f"/operations/{action}",
                headers={"X-API-Key": settings.brain_api_key.get_secret_value()},
                json=payload,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise HTTPException(502, "Mock Twin control failed") from exc
    return response.json()


@router.get("/dashboard/api/timeline", include_in_schema=False)
async def dashboard_timeline(request: Request, limit: int = Query(200, ge=1, le=1000)) -> list:
    require_dashboard_role(request, "brain", "guardian", "twin")
    return await asyncio.to_thread(timeline, request, limit)


@router.get("/dashboard/events", include_in_schema=False)
async def dashboard_events(request: Request) -> StreamingResponse:
    require_dashboard_role(request, "brain", "guardian", "twin")

    async def stream():
        while True:
            if await request.is_disconnected():
                break
            items = await asyncio.to_thread(timeline, request, 100)
            yield f"event: timeline\ndata: {json.dumps(items, separators=(',', ':'))}\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/dashboard/api/scenarios/{scenario_id}/run", include_in_schema=False)
async def run_scenario(scenario_id: str, request: Request) -> dict:
    session = require_dashboard_role(request, "brain")
    require_csrf(request, session)
    try:
        return await request.app.state.scenarios.run(scenario_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/dashboard/api/scenarios", include_in_schema=False)
async def scenario_history(request: Request, limit: int = Query(50, ge=1, le=200)) -> dict:
    require_dashboard_role(request, "brain", "guardian", "twin")
    return {
        "catalog": SCENARIOS,
        "executions": await asyncio.to_thread(
            request.app.state.scenarios.list_executions,
            limit,
        ),
    }


@router.get("/dashboard/api/scenarios/executions/{execution_id}", include_in_schema=False)
async def scenario_execution(execution_id: UUID, request: Request) -> dict:
    require_dashboard_role(request, "brain", "guardian", "twin")
    try:
        return await asyncio.to_thread(request.app.state.scenarios.get, execution_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.post("/dashboard/api/scenarios/{scenario_id}/start", include_in_schema=False)
async def start_scenario(scenario_id: str, request: Request) -> dict:
    session = require_dashboard_role(request, "brain")
    require_csrf(request, session)
    try:
        body = await request.body()
        payload = json.loads(body) if body else {}
        return request.app.state.scenarios.start_live(
            scenario_id,
            int(payload.get("sensor_count", 10)),
            int(payload.get("seed", request.app.state.settings.simulation_seed)),
        )
    except ValueError as exc:
        code = {
            "simulation_already_running": 409,
            "invalid_sensor_count": 422,
        }.get(str(exc), 404)
        raise HTTPException(code, str(exc)) from exc


@router.post("/dashboard/api/scenarios/executions/{execution_id}/control", include_in_schema=False)
async def control_scenario(execution_id: UUID, request: Request) -> dict:
    session = require_dashboard_role(request, "brain")
    require_csrf(request, session)
    payload = await request.json()
    try:
        return request.app.state.scenarios.control(
            execution_id,
            str(payload.get("action", "")),
            float(payload["speed"]) if "speed" in payload else None,
        )
    except LookupError as exc:
        raise HTTPException(409, str(exc)) from exc
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc


@router.post("/dashboard/api/scenarios/reset", include_in_schema=False)
async def reset_scenarios(request: Request) -> dict:
    session = require_dashboard_role(request, "brain")
    require_csrf(request, session)
    return await asyncio.to_thread(request.app.state.scenarios.reset)
