import asyncio
import json
import math
import statistics
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
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


@router.get("/dashboard/mock-login", include_in_schema=False)
async def mock_dashboard_login(request: Request) -> RedirectResponse:
    """Create a local mock-only operator session without exposing its API key."""
    settings = request.app.state.settings
    client = request.client.host if request.client else ""
    if settings.aegiscity_mode != "mock" or client not in {"127.0.0.1", "::1"}:
        raise HTTPException(404, "not found")
    token, _ = request.app.state.dashboard_sessions.create("brain")
    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        samesite="strict",
        secure=False,
        max_age=settings.dashboard_session_seconds,
    )
    return response


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
        passport_snapshot = request.app.state.city_engine.eligibility.snapshot(now)
        for sensor in state["sensors"].values():
            for evidence in sensor["evidence"]:
                if evidence.get("trust_source") == "guardian_passport":
                    expiry = passport_snapshot.expiry_by_event.get(UUID(evidence["event_id"]))
                    evidence["authorization_expires_at"] = (
                        expiry.isoformat() if expiry else now.isoformat()
                    )
        eligible_evidence = {
            e["event_id"]: e
            for sensor in state["sensors"].values()
            if sensor["availability"] == "available"
            for e in sensor["evidence"]
        }
        eligible_sensors = sum(
            sensor["availability"] == "available" for sensor in state["sensors"].values()
        )
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
        # Task 7.3F-1: expose the audit-tail reconciliation state honestly.
        # The durable cursor (highest accounted audit seq) and the pending
        # store are Brain-owned state files of the Real-Readonly worker; a
        # lower pending count means more evidence was exactly matched.
        audit_verified = pending_count = None
        cursor_path = pending_path = None
        if getattr(request.app.state.settings, "guardian_evidence_source", "") == "audit_tail":
            from app.integration.guardian_compat import (
                audit_cursor_path,
                audit_pending_path,
            )

            try:
                cursor_path = audit_cursor_path(request.app.state.settings)
                pending_path = audit_pending_path(request.app.state.settings)
                from app.integration.guardian_compat import AuditCursor, PendingEvidenceStore

                audit_cursor = AuditCursor(cursor_path)
                audit_verified = audit_cursor.load()
                pending_count = len(PendingEvidenceStore(pending_path).load())
            except Exception:  # noqa: BLE001 - dashboard must not fail on state files
                audit_verified = pending_count = None
        # Task 7.3F-2: raw observation layer - latest STORED reading per
        # sensor, independent of trust eligibility. Readings are ordered
        # newest-first, so the first occurrence of each sensor_id is its
        # latest raw observation. The frontend labels this as raw/untrusted,
        # distinct from the trusted fused city state.
        raw_latest: dict[str, dict] = {}
        for event, _ in readings:
            if event.sensor_id in raw_latest:
                continue
            raw_latest[event.sensor_id] = {
                "value": event.payload["event"]["value"],
                "unit": event.payload["event"]["unit"],
                "at": utc(event.occurred_at).isoformat(),
            }
        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "health": {"database": "ready"},
            "environment": "mock-simulation"
            if request.app.state.settings.aegiscity_mode == "mock"
            else request.app.state.settings.environment,
            "evidence_mode": "guardian_passports"
            if request.app.state.settings.guardian_passport_enabled
            else "audit_tail_reconciliation"
            if getattr(request.app.state.settings, "guardian_evidence_source", "")
            == "audit_tail"
            else "guardian_verdicts",
            "audit_verified_matches": audit_verified,
            "audit_pending": pending_count,
            "security": {
                "mode": request.app.state.settings.aegiscity_mode,
                "actuator_execution_enabled": request.app.state.settings.actuator_execution_enabled,
                "automatic_approval_enabled": request.app.state.settings.operational_auto_approve,
                "mock_controls_enabled": bool(request.app.state.settings.twin_base_url),
            },
            "metrics": {
                "incoming_events_per_second": round((incoming_recent or 0) / 10, 2),
                "processed_observations": processed or 0,
                "trusted_readings": len(eligible_evidence),
                "durable_trusted_readings": trusted or 0,
                "eligible_sensors": eligible_sensors,
                "registered_sensors": len(state["sensors"]),
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
                    "trust": "TRUSTED" if str(event.id) in eligible_evidence
                    else lifecycle.state if lifecycle else "RECEIVED",
                    "currently_eligible": str(event.id) in eligible_evidence,
                    "trust_source": eligible_evidence.get(str(event.id), {}).get("trust_source"),
                    "authorization_expires_at": eligible_evidence.get(str(event.id), {}).get(
                        "authorization_expires_at"
                    ),
                }
                for event, lifecycle in readings
            ],
            "verdicts": [row.payload["event"] for row in verdicts],
            "raw_latest": raw_latest,
            "security_alerts": security,
        }
async def provider_status(request: Request) -> dict:
    settings = request.app.state.settings
    headers = (
        {"X-API-Key": settings.brain_api_key.get_secret_value()}
        if settings.brain_api_key
        else {}
    )

    async def guardian_health(client: httpx.AsyncClient) -> dict:
        """Real Guardian exposes GET /healthz (no auth); probe that.

        The old code called /health (the mock Guardian route), so the real
        layer always showed 'offline'. Try /healthz first, fall back.
        """
        base = settings.guardian_base_url
        if not base:
            return {"connected": False, "reason": "not_configured"}
        for path in ("/healthz", "/health"):
            try:
                response = await client.get(
                    str(base).rstrip("/") + path,
                    headers=headers if path == "/health" else {},
                )
                response.raise_for_status()
                return {"connected": True, **response.json()}
            except (httpx.HTTPError, ValueError):
                continue
        return {"connected": False, "reason": "unavailable"}

    async def twin_publish_state(client: httpx.AsyncClient) -> dict:
        """Infer Remote Twin publisher activity from Orion entity freshness.

        There is no Twin process of ours to poll in the Real-Readonly
        profile (TWIN_BASE_URL unset): the publisher is the partner's
        hosted Twin. The honest liveness signal is whether the monitored
        entity's timestamp is advancing (<= 120 s old).
        """
        if settings.aegiscity_mode == "mock":
            if not settings.twin_base_url:
                return {"connected": False, "reason": "not_configured"}
            try:
                response = await client.get(
                    str(settings.twin_base_url).rstrip("/") + "/operations",
                    headers=headers,
                )
                response.raise_for_status()
                status = response.json()
                return {
                    "connected": True,
                    "publisher": "isolated-mock-twin",
                    "last_publish_age_s": None,
                    **status,
                }
            except (httpx.HTTPError, ValueError):
                return {"connected": False, "reason": "mock_twin_unavailable"}

        base = settings.orion_base_url
        devices = getattr(settings, "snap4city_devices_file", None)
        if not base or not devices:
            return {"connected": False, "reason": "not_configured"}
        entity_id = "us-b-bldg-01"
        try:
            from app.integration.ngsi_twin import load_mapping

            mapping = load_mapping(devices).sensors
            entity_id = mapping[0].entity_id if mapping else entity_id
        except Exception:  # noqa: BLE001 - fall back to the default entity
            pass
        try:
            response = await client.get(
                str(base).rstrip("/") + f"/v2/entities/{entity_id}",
                params={"type": "BuildingSensor", "elementid": entity_id},
            )
            response.raise_for_status()
            entity = response.json()
        except (httpx.HTTPError, ValueError):
            return {"connected": False, "reason": "orion_unreachable"}
        # 7.3F-2 root cause: NGSI entities carry attributes as nested
        # {type, value} dicts. Reading `entity["timestamp"]` raw returned a
        # dict, which failed the string check, so age was never computed and
        # the publisher was ALWAYS reported stale. Flatten first (same
        # canonicalization as the ingest poller and the check script).
        stamp = entity.get("timestamp")
        if isinstance(stamp, dict) and "value" in stamp:
            stamp = stamp["value"]
        values = {
            k: v.get("value") if isinstance(v, dict) and "value" in v else v
            for k, v in entity.items()
            if k not in ("id", "type")
        }
        age_s = None
        running = False
        if isinstance(stamp, str) and stamp.strip():
            try:
                ts = datetime.fromisoformat(stamp.strip().replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=UTC)
                age_s = max(0.0, (datetime.now(UTC) - ts).total_seconds())
                running = age_s <= 120
            except ValueError:
                pass
        return {
            "connected": True,
            "running": running,
            "publisher": "hosted-partner-twin",
            "last_publish_age_s": round(age_s, 1) if age_s is not None else None,
            "last_timestamp": stamp,
            "values": values,
        }

    async with httpx.AsyncClient(timeout=4, trust_env=False) as client:
        twin, guardian = await asyncio.gather(
            twin_publish_state(client), guardian_health(client)
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
    return await request.app.state.city_engine.read_current(lambda: snapshot(request))


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


async def _brain_operator_post(request: Request, path: str, payload: dict) -> dict:
    """Use the existing authenticated Brain APIs for dashboard operator actions."""
    settings = request.app.state.settings
    if not settings.brain_base_url or not settings.brain_api_key:
        raise HTTPException(503, "Brain operator API is not configured")
    async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
        try:
            response = await client.post(
                str(settings.brain_base_url).rstrip("/") + path,
                headers={"X-API-Key": settings.brain_api_key.get_secret_value()},
                json=payload,
            )
        except httpx.HTTPError as exc:
            raise HTTPException(502, "Brain operator API unavailable") from exc
    if response.status_code >= 400:
        detail = response.json().get("detail", "operator action rejected")
        raise HTTPException(response.status_code, detail)
    return response.json()


@router.post("/dashboard/api/decisions/evaluate", include_in_schema=False)
async def dashboard_evaluate(request: Request) -> dict:
    session = require_dashboard_role(request, "brain")
    require_csrf(request, session)
    return await _brain_operator_post(request, "/v1/decisions/evaluate", {})


@router.post("/dashboard/api/decisions/{decision_id}/approve", include_in_schema=False)
async def dashboard_approve(decision_id: UUID, request: Request) -> dict:
    session = require_dashboard_role(request, "brain")
    require_csrf(request, session)
    payload = await request.json()
    reason = str(payload.get("reason", "")).strip()
    if len(reason) < 8:
        raise HTTPException(422, "Approval reason must contain at least 8 characters")
    return await _brain_operator_post(
        request,
        "/v1/decisions/evaluate",
        {"approval": {"decision_id": str(decision_id), "reason": reason}},
    )


@router.post("/dashboard/api/decisions/{decision_id}/execute", include_in_schema=False)
async def dashboard_execute(decision_id: UUID, request: Request) -> dict:
    session = require_dashboard_role(request, "brain")
    require_csrf(request, session)
    return await _brain_operator_post(
        request,
        "/v1/actions/execute",
        {"decision_id": str(decision_id)},
    )


@router.get("/dashboard/api/timeline", include_in_schema=False)
async def dashboard_timeline(request: Request, limit: int = Query(200, ge=1, le=1000)) -> list:
    require_dashboard_role(request, "brain", "guardian", "twin")
    return await asyncio.to_thread(timeline, request, limit)


@router.get("/dashboard/events", include_in_schema=False)
async def dashboard_events(request: Request) -> StreamingResponse:
    require_dashboard_role(request, "brain", "guardian", "twin")

    async def stream():
        # Bound each stream so open dashboards cannot stall graceful shutdown.
        # EventSource reconnects automatically and rechecks session authorization.
        for _ in range(20):
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
