import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api import (
    actions,
    city,
    decisions,
    events,
    feedback,
    forecasts,
    health,
    incidents,
    readings,
    scenarios,
    verdicts,
)
from app.core.config import Settings, get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging
from app.dashboard import api as dashboard
from app.dashboard.api import STATIC as DASHBOARD_STATIC
from app.dashboard.security import DashboardSessions
from app.database.session import Database
from app.execution.actuator_manager import ActuatorManager
from app.integration.guardian_compat import (
    AuditTailShadowWorker,
    GuardianShadowWorker,
)
from app.integration.ngsi_twin import NgsiTwinIngestWorker
from app.intelligence.artifacts import ArtifactRegistry
from app.operations import OperationalCoordinator
from app.scenarios import ScenarioRunner
from app.security.validation import RequestLimitMiddleware
from app.state.registry import load_registry
from app.state.state_manager import StateManager
from app.streaming.event_processor import EventProcessor


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or get_settings()
    configure_logging(app_settings.log_level)
    database = Database(app_settings)
    processor = EventProcessor(database, app_settings)
    actuator_manager = ActuatorManager(database, app_settings, processor.city)
    coordinator = OperationalCoordinator(database, app_settings, processor.city, actuator_manager)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        database.initialize()
        application.state.scenarios.recover()
        actuator_manager.recover_startup()
        load_registry(database, app_settings.city_registry_file)
        application.state.artifacts = await asyncio.to_thread(
            ArtifactRegistry,
            app_settings.traffic_model_dir,
            app_settings.water_model_path,
        )
        task = asyncio.create_task(processor.run()) if app_settings.worker_enabled else None

        async def refresh_passports() -> None:
            while True:
                try:
                    await processor.city.read_current(processor.city.snapshot)
                except asyncio.CancelledError:
                    processor.city.eligibility.clear()
                    raise
                except Exception:
                    processor.city.eligibility.clear()
                await asyncio.sleep(1)

        passport_task = (
            asyncio.create_task(refresh_passports())
            if app_settings.worker_enabled and app_settings.guardian_passport_enabled
            else None
        )
        actuator_task = (
            asyncio.create_task(actuator_manager.run())
            if app_settings.worker_enabled and app_settings.actuator_execution_enabled
            else None
        )
        coordinator_task = (
            asyncio.create_task(coordinator.run())
            if app_settings.worker_enabled and app_settings.operational_demo_enabled
            else None
        )
        # Opt-in real Twin ingestion: started only when explicitly configured.
        # Construction is fail-closed (invalid mapping/URL aborts startup); no
        # fallback to mock transport exists.
        twin_worker = None
        if app_settings.snap4city_ingest_enabled and app_settings.worker_enabled:
            try:
                twin_worker = NgsiTwinIngestWorker.from_settings(app_settings, database)
            except Exception as exc:
                raise RuntimeError(f"Snap4City ingestion setup failed: {exc}") from exc
            twin_worker.start()
        # Opt-in Guardian shadow reconciliation: verification and observability
        # only. Constructing it enforces the transport/token preconditions; it
        # never grants trust, so it cannot alter decisions or commands. The
        # evidence source is selected by configuration (integration_verdicts
        # or audit_tail).
        shadow_worker = None
        if app_settings.guardian_shadow_reconciliation_enabled and app_settings.worker_enabled:
            worker_cls = (
                AuditTailShadowWorker
                if app_settings.guardian_evidence_source == "audit_tail"
                else GuardianShadowWorker
            )
            try:
                shadow_worker = worker_cls.from_settings(app_settings, database)
            except Exception as exc:
                raise RuntimeError(f"Guardian shadow reconciliation setup failed: {exc}") from exc
            shadow_worker.start()
        try:
            yield
        finally:
            if passport_task is not None:
                passport_task.cancel()
                with suppress(asyncio.CancelledError):
                    await passport_task
            processor.stop()
            actuator_manager.stop()
            coordinator.stop()
            if twin_worker is not None:
                await twin_worker.stop()
            if shadow_worker is not None:
                await shadow_worker.stop()
            if task is not None:
                await task
            if actuator_task is not None:
                await actuator_task
            if coordinator_task is not None:
                await coordinator_task
            await application.state.scenarios.shutdown()
            database.close()

    application = FastAPI(
        title=app_settings.app_name,
        version="0.1.0",
        docs_url="/docs",
        lifespan=lifespan,
    )
    application.state.settings = app_settings
    application.state.database = database
    application.state.processor = processor
    application.state.city_engine = processor.city
    application.state.actuator_manager = actuator_manager
    application.state.operational_coordinator = coordinator
    application.state.dashboard_sessions = DashboardSessions(
        app_settings.dashboard_session_seconds,
    )
    application.state.scenarios = ScenarioRunner(database, app_settings)
    application.state.state_manager = StateManager(database)
    application.add_middleware(RequestLimitMiddleware, limit=app_settings.max_request_bytes)
    for router in (
        actions.router,
        dashboard.router,
        health.router,
        readings.router,
        scenarios.router,
        verdicts.router,
        incidents.router,
        decisions.router,
        feedback.router,
        events.router,
        city.router,
        forecasts.router,
    ):
        application.include_router(router)
    application.mount(
        "/dashboard/static",
        StaticFiles(directory=DASHBOARD_STATIC),
        name="dashboard-static",
    )
    register_exception_handlers(application)
    return application


app = create_app()
