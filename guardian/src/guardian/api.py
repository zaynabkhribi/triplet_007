"""AEGIS LOOP Guardian — FastAPI application.

Faces, from the more general to the more specific:
  GET  /healthz                 liveness + policy version
  GET  /describe                dynamic capability card (Interop)
  POST /v1/readings             frame transport (schema + dedup + device gate + audit)
  GET  /v1/verdict?since=       tail the audit stream (feeds the live timeline)
  GET  /v1/verdict/{id}         look up a stored event by passport_id
  POST /v1/passport             mint a signed Evidence Passport for an evidence_digest
                                (SUSPECT/RESTRICT/MALICIOUS passports never contain 'full')
  POST /v1/witness              effect witness (folds the outcome into `history`)
  GET  /ui/                     live timeline screen (static)

Triplet face (orion/orion.py + ngsi.py — how this layer plugs into triplet_007):
  GET  /verdicts                per-device verdict feed, the exact shape the Twin's
                                mock Guardian publishes and the mock Brain consumes:
                                {"us-b-bldg-01": {"verdict", "reason", "checked", ...}}
  POST /v1/ngsi/poll           one manual broker read -> pipeline -> summary
  GET  /orion/status            poller health: cycles, unreachable devices, written verdicts

When run as a service (docker compose / `python -m guardian`), a background
OrionPoller (orion.py) reads every sensor entity from the Orion broker once per
tick, feeds the frames through the unchanged five-stage pipeline, and keeps the
/verdicts feed live without any partner having to call us.
"""
from __future__ import annotations

import json
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import Body, FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .audit import AuditLog
from .config import Settings, load_policy, load_sensor_profiles, load_settings
from .dedup import SeenSet
from .errors import (
    INTERNAL_ERROR, NOT_FOUND, BAD_REQUEST, PASSPORT_ISSUED, WITNESS_RECORDED, GuardianError,
)
from .models import (
    DescribeEndpoints, DescribeResponse, HealthResponse, ReadingAck, VerdictTailResponse,
)
from .passport import build_passport
from .pipeline import Pipeline
from .registry import DeviceRegistry
from .schemas import validate_or_raise


def _orion_startup(app: FastAPI) -> None:
    """Start the background poll loop when `orion.enabled` (config/env).

    The poller is a daemon thread inside THIS process: no partner has to
    call the Guardian, we read the broker ourselves. Disabled in tests so
    the suite never touches a live broker.
    """
    settings, catalog = app.state.settings, app.state.orion_catalog
    if not settings.orion.enabled or catalog is None:
        return
    from .orion import OrionPoller, VerdictWriter

    mapping = app.state.orion_mapping
    writer = None
    if settings.orion.publish_enabled:
        secrets = settings.resolve(settings.orion.secrets_path)
        writer = VerdictWriter(
            base_url=settings.orion.base_url, timeout=settings.orion.timeout_s,
            entity_suffix=settings.orion.entity_suffix, entity_type=settings.orion.entity_type,
            keys_path=str(secrets) if secrets.exists() else None,
        )
        app.state.orion_writer = writer
    poller = OrionPoller(
        app.state.pipeline, mapping, catalog,
        settings.orion.base_url,
        poll_seconds=settings.orion.poll_seconds, timeout=settings.orion.timeout_s,
        stale_after_s=settings.orion.stale_after_s, writer=writer,
    )
    app.state.orion_poller = poller
    poller.start()
    app.state.audit.append({
        "event": "orion.poller.started", "code": "ORION",
        "broker": settings.orion.base_url, "poll_seconds": settings.orion.poll_seconds,
        "devices": len(catalog.sensors()), "publish": settings.orion.publish_enabled,
    })


def _orion_shutdown(app: FastAPI) -> None:
    poller = app.state.orion_poller
    if poller is not None:
        poller.stop(timeout=max(app.state.settings.orion.poll_seconds, 2.0))


@asynccontextmanager
async def _orion_lifespan(app: FastAPI):
    _orion_startup(app)
    yield
    _orion_shutdown(app)


def _load_orion_parts(settings):
    """Catalog + mapping for the Orion face. None-safe: a missing config file
    degrades to a Guardian that only serves the frame API, never crashes boot."""
    from .ngsi import NgsiMapping
    from .orion import DeviceCatalog

    mapping = NgsiMapping.load()
    try:
        catalog = DeviceCatalog(settings.orion.devices_config or None)
    except Exception as exc:      # noqa: BLE001 - surface on /orion/status, don't crash boot
        catalog = None
        catalog_error = f"{type(exc).__name__}: {exc}"
    else:
        catalog_error = ""
    return mapping, catalog, catalog_error


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or load_settings()

    app = FastAPI(
        title="AEGIS LOOP — Guardian",
        version=__version__,
        description="Trust layer for the TSYP14 City Brain Convergence triplet. Every action carries its own proof.",
        lifespan=_orion_lifespan,
    )
    app.state.settings = settings
    app.state.audit = AuditLog(settings.resolve(settings.paths.audit_log))
    app.state.registry = DeviceRegistry.from_keyring(settings.resolve(settings.auth.keyring_path))
    app.state.seen = SeenSet(window_s=settings.ttl.seen_window_s)
    app.state.pipeline = Pipeline(settings, app.state.registry, app.state.seen, app.state.audit)
    app.state.started_at = time.time()

    # ---- Orion face pieces (see orion/orion.py) ----
    mapping, catalog, catalog_error = _load_orion_parts(settings)
    app.state.orion_mapping = mapping
    app.state.orion_catalog = catalog
    app.state.orion_catalog_error = catalog_error
    app.state.orion_poller = None
    app.state.orion_writer = None

    # ---- error handlers: stable codes, never leak stack traces ----
    @app.exception_handler(GuardianError)
    async def _guardian_error(request: Request, exc: GuardianError):
        return JSONResponse(status_code=exc.http_status, content=exc.to_dict())

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        return JSONResponse(status_code=exc.status_code, content={"error": f"HTTP_{exc.status_code}", "message": str(exc.detail)})

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        return JSONResponse(status_code=500, content={"error": INTERNAL_ERROR, "message": "internal error", "details": {}})

    # ---- discovery / health ----
    @app.get("/healthz", response_model=HealthResponse, tags=["ops"])
    def healthz(request: Request):
        s: Settings = request.app.state.settings
        return HealthResponse(
            status="ok",
            layer="guardian",
            version=__version__,
            policy_version=load_policy(s).get("policy_version", "v1.0"),
            uptime_s=round(time.time() - request.app.state.started_at, 3),
        )

    @app.get("/describe", response_model=DescribeResponse, tags=["discovery"])
    def describe(request: Request):
        s: Settings = request.app.state.settings
        profiles = load_sensor_profiles(s)
        policy = load_policy(s)
        return DescribeResponse(
            layer="guardian",
            version=__version__,
            protocol="rest+json",
            optional_faces=["mcp-tools"],
            endpoints=DescribeEndpoints(
                readings="POST /v1/readings",
                passport="POST /v1/passport",
                verdict="GET /v1/verdict/{passport_id}",
                witness="POST /v1/witness",
                healthz="GET /healthz",
            ),
            auth="hmac-sha256 header X-Signature over body; key via config",
            accepts_sensor_types=sorted(profiles.keys()),
            emits_dispositions=policy.get("dispositions", ["TRUSTED", "SUSPECT", "MALICIOUS", "RESTRICT"]),
            max_latency_s=float(s.latency.contractual_floor_s),
            policy_version=policy.get("policy_version", "v1.0"),
        )

    # ---- readings transport (Twin -> Guardian) ----
    def _process_reading(raw: dict) -> ReadingAck:
        # Stage A boundary validation: schema errors raise a clean 400 (never a crash).
        validate_or_raise(raw, "reading")

        # Delegate to the five-stage pipeline. It performs Stage A (charter:
        # dedup -> identity -> provenance -> signature -> freshness/seq) and
        # writes exactly one hash-chained audit record per reading.
        report = app.state.pipeline.process(raw)
        return ReadingAck(
            accepted=report.accepted,
            code=report.code,
            message=report.message,
            reading_id=report.reading_id,
            batch_id=report.batch_id,
            event_id=report.event_id,
        )

    @app.post("/v1/readings", tags=["ingest"])
    def post_readings(payload: dict = Body(...)):
        # Accept a single reading object or {"readings": [...]}.
        readings = payload.get("readings") if isinstance(payload, dict) and "readings" in payload else [payload]
        if not isinstance(readings, list):
            raise GuardianError("BAD_REQUEST", "body must be a reading object or {readings:[...]}")
        acks = [_process_reading(r).model_dump() for r in readings]
        accepted = sum(1 for a in acks if a["accepted"])
        return {"received": len(acks), "accepted": accepted, "results": acks}

    # ---- verdict / audit stream (feeds the timeline) ----
    @app.get("/v1/verdict", response_model=VerdictTailResponse, tags=["verdict"])
    def verdict_tail(since: int = 0):
        events = app.state.audit.read_since(since)
        return VerdictTailResponse(count=len(events), events=events)

    @app.post("/v1/run/new", tags=["verdict"])
    def new_run():
        """Begin a new run: clear run-scoped trust state (R2, one trigger = one run).

        The audit log is untouched - it is the append-only system of record and
        the jury reads it after the event. Only per-run working state (dedup
        window, sequence watermarks, corroboration buffers, history, verdict
        cache) is reset, so `run scenario t5` twice behaves identically instead
        of reporting every frame as DUPLICATE.
        """
        app.state.pipeline.reset_run()
        return {"status": "ok", "run_started_at": time.time()}

    @app.get("/v1/cursor", tags=["verdict"])
    def cursor():
        """Current audit head (max seq).

        A scenario runner records this BEFORE streaming, so the Brain and the
        log summary only ever see this run's events. The audit is append-only
        and survives restarts, so `since=0` would otherwise replay old runs —
        and the mock Brain would act on a stale frame whose in-memory verdict
        no longer exists.
        """
        events = app.state.audit.read_since(0)
        head = max((e.get("seq", 0) for e in events), default=0)
        return {"head_seq": head, "count": len(events)}

    @app.get("/v1/verdict/{passport_id}", tags=["verdict"])
    def verdict_get(passport_id: str):
        for e in app.state.audit.read_since(0):
            if e.get("passport_id") == passport_id:
                return {"passport_id": passport_id, "found": True, "event": e}
        raise GuardianError(NOT_FOUND, f"no verdict for passport {passport_id}",
                            http_status=404,
                            details={"hint": "request POST /v1/passport with evidence_digest"})

    # ---- passport (functional: Stage E verdict -> signed Evidence Passport) ----
    @app.post("/v1/passport", tags=["verdict"])
    def passport_request(payload: dict = Body(...)):
        evidence_digest = payload.get("evidence_digest") or payload.get("digest")
        if not evidence_digest:
            raise GuardianError(
                BAD_REQUEST, "passport request requires 'evidence_digest'",
                http_status=422,
                details={"plan": "PHASE1_IMPLEMENTATION_PLAN.md §6.5"},
            )
        record = app.state.pipeline.get_verdict(str(evidence_digest))
        if record is None:
            raise GuardianError(
                NOT_FOUND,
                f"no verdict for evidence {evidence_digest}",
                http_status=404,
                details={"hint": "ingest the reading that produced this evidence first"},
            )
        passport = build_passport(record, app.state.settings, app.state.pipeline.policy)
        app.state.audit.append({
            "event": "passport.issued", "code": PASSPORT_ISSUED,
            "passport_id": passport["passport_id"],
            "disposition": passport["disposition"], "trust": passport["trust"],
            "evidence_digest": passport["evidence_digest"],
            "zone": passport["zone"], "reason_codes": passport["reason_codes"],
            "allowed_actions": passport["allowed_actions"],
            "note": "Evidence Passport issued on demand (plan §6.5)",
        })
        return passport

    # ---- effect witness (Twin -> Guardian) ----
    @app.post("/v1/witness", tags=["ingest"])
    def post_witness(payload: dict = Body(...)):
        validate_or_raise(payload, "witness")
        # Fold the outcome into the implicated device's `history` factor; enough
        # consecutive MISMATCHes quarantine it (plan §11).
        result = payload.get("result")
        device = payload.get("implicated_device")
        history = app.state.pipeline.note_effect(device, str(result or ""))
        rec = app.state.audit.append({
            "event": "witness.received", "code": WITNESS_RECORDED,
            "action_id": payload.get("action_id"), "result": result,
            "requested": payload.get("requested"), "acknowledged": payload.get("acknowledged"),
            "implicated_device": device, "history_score": history,
            "quarantined": app.state.registry.is_quarantined(str(device)) if device else False,
            "note": "history factor folded; quarantine overlay updated (plan §11)",
        })
        return {"accepted": True, "code": WITNESS_RECORDED, "event_id": rec.get("seq"),
                "history_score": history}

    # ---- decision + action audit trail (R2: Brain/Twin lanes on the timeline) ---

    # The real Brain/Twin POST here; the mock Brain does the same, so the live
    # timeline shows all four lanes (reading -> verdict -> decision -> action)
    # even in a standalone Guardian run. Events are audit-logged, hash-chained
    # and replayable like every other record.
    @app.post("/v1/decision", tags=["timeline"])
    def post_decision(payload: dict = Body(...)):
        rec = app.state.audit.append({
            "event": f"decision.{payload.get('decision', 'proposed')}",
            "code": "DECISION",
            "decision": payload.get("decision"),
            "sensor_id": payload.get("sensor_id"), "zone": payload.get("zone"),
            "passport_id": payload.get("passport_id"),
            "disposition": payload.get("disposition"), "trust": payload.get("trust"),
            "action": payload.get("action"), "reason": payload.get("reason"),
            "fallback": payload.get("fallback"), "target": payload.get("target"),
        })
        return {"accepted": True, "code": "DECISION", "event_id": rec.get("seq")}

    @app.post("/v1/action", tags=["timeline"])
    def post_action(payload: dict = Body(...)):
        rec = app.state.audit.append({
            "event": "action.requested", "code": "ACTION",
            "action_id": payload.get("action_id"), "action": payload.get("action"),
            "target": payload.get("target"), "passport_id": payload.get("passport_id"),
            "evidence_digest": payload.get("evidence_digest"),
            "result": payload.get("result", "requested"),
        })
        return {"accepted": True, "code": "ACTION", "event_id": rec.get("seq")}

    # ---- live timeline UI (R2) ----
    static_dir = settings.resolve(settings.paths.static_dir)
    static_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/ui", StaticFiles(directory=str(static_dir), html=True), name="ui")

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse(url="/ui/")

    # ------------------------------------------------------------------
    # Triplet face. The Twin's mock Brain reads GET /verdicts as
    #   {"us-b-bldg-01": {"verdict": "UNTRUSTED", "reason": "...", "checked": "HH:MM:SS"}}
    # and the root contract (INTEGRATION.md) asks the Guardian to confirm the
    # verdict format; INTERFACE.md documents the exact shape (v2.0).
    # The three contract keys are verbatim mock-compatible; everything else is
    # additive-only evidence for consumers that want to check the verdict.
    # ------------------------------------------------------------------
    def _verdicts_body() -> dict:
        from .ngsi import zone_for
        from .orion import device_face

        s = settings
        verdicts = app.state.pipeline.all_verdicts()
        sensors = app.state.orion_catalog.sensors() if app.state.orion_catalog else {}
        device_rows = device_face(
            verdicts, now=time.time(), stale_after_s=s.orion.stale_after_s,
            sensors=sensors, mapped_kinds=set(mapping.attributes), zone_for=zone_for,
        )
        body = {}
        for device_id, row in sorted(device_rows.items()):
            entry = row.wire()
            # OFFLINE inventory rows carry no per-property detail by definition.
            if row.properties:
                entry["properties"] = row.properties
            body[device_id] = entry
        return body

    @app.get("/verdicts", tags=["triplet"])
    def triplet_verdicts():
        return _verdicts_body()

    @app.get("/orion/status", tags=["triplet"])
    def orion_status():
        """How alive the Orion face is, in one read: poller cycles, unreachable
        devices, published verdicts. A reviewer confirms wiring without tools."""
        from .ngsi import broker_host

        poller = app.state.orion_poller
        writer = app.state.orion_writer
        catalog = app.state.orion_catalog
        return {
            "enabled": settings.orion.enabled,
            "broker": broker_host(settings.orion.base_url),
            "base_url": settings.orion.base_url,
            "poll_seconds": settings.orion.poll_seconds,
            "stale_after_s": settings.orion.stale_after_s,
            "devices_config": (catalog.source if catalog else "") or catalog_error,
            "mapping_broker_label": mapping.broker_label,
            "mapped_kinds": sorted(mapping.attributes.keys()),
            "poller": None if poller is None else {
                "alive": poller.is_alive(),
                "cycles": poller.cycles,
                "last_cycle_at": poller.last_cycle_at and time.strftime(
                    "%H:%M:%S", time.localtime(poller.last_cycle_at)),
                "last_summary": poller.last_summary,
                "errors": poller.errors[-10:],
            },
            "writer": None if writer is None else {
                "active": writer.active, "written": writer.written,
                "errors": writer.last_errors,
            },
        }

    @app.post("/v1/ngsi/poll", tags=["triplet"])
    def ngsi_poll(request: Request, payload: dict = Body(default={})):
        """Read the Orion broker once and feed every frame through the pipeline.

        Body (all optional):
          {"config": "twin/config.json"}   Twin device list + broker base_url
          {"base_url": "...", "devices": {...}}   explicit, for a test
        Returns the per-frame acknowledgement plus a summary, so a reviewer can
        see exactly what was accepted and what the Guardian made of it.
        """
        from .ngsi import NgsiClient, NgsiMapping, broker_host

        mapping = NgsiMapping.load()
        base = payload.get("base_url")
        devices = payload.get("devices")
        if not base or not devices:
            cfg_path = payload.get("config") or "twin/config.json"
            try:
                raw = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise GuardianError(
                    BAD_REQUEST, f"cannot read Twin config '{cfg_path}': {exc}",
                    http_status=422,
                    details={"hint": "POST {\"base_url\": ..., \"devices\": {...}} instead"},
                ) from exc
            orion = raw.get("orion") or {}
            base = base or orion.get("base_url")
            devices = devices or raw.get("devices") or {}
        if not base or not devices:
            raise GuardianError(BAD_REQUEST, "no broker base_url or device list",
                                http_status=422)

        client = NgsiClient(base_url=str(base).rstrip("/"),
                            timeout=float(payload.get("timeout", 10)),
                            keys=payload.get("keys") or {})
        frames = client.poll(devices, mapping)
        acks = []
        for frame in frames:
            rep = app.state.pipeline.process(frame)
            acks.append({"reading_id": rep.reading_id, "accepted": rep.accepted,
                         "code": rep.code, "sensor_id": frame["sensor_id"],
                         "observed_property": frame["observed_property"]})
        app.state.audit.append({
            "event": "ngsi.poll", "broker": broker_host(str(base)),
            "devices": len(devices), "frames": len(frames),
            "accepted": sum(1 for a in acks if a["accepted"]),
        })
        return {"broker": broker_host(str(base)), "devices": len(devices),
                "frames": len(frames),
                "accepted": sum(1 for a in acks if a["accepted"]),
                "results": acks, "verdicts": triplet_verdicts()}

    return app


# Module-level app for `uvicorn guardian.api:app` convenience.
app = create_app()
