import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

from fastapi import Depends, FastAPI, HTTPException, Request

from app.core.config import Settings
from app.core.exceptions import register_exception_handlers
from app.integration.http import post_to_brain
from app.schemas.actuator import ActuatorCommand, ActuatorFeedback, FeedbackStatus
from app.schemas.sensor import SensorReading
from app.security.authorization import require_role
from app.security.validation import RequestLimitMiddleware, require_reasonable_timestamp
from mocks.operational_twin import OperationalTwin


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or Settings()
    runtime = OperationalTwin(app_settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        task = asyncio.create_task(runtime.run())
        try:
            yield
        finally:
            runtime.stop_worker()
            await task

    app = FastAPI(title="Mock Twin", lifespan=lifespan)
    app.state.settings = app_settings
    app.state.runtime = runtime
    app.state.commands = {}
    app.state.failed_once = set()
    app.state.actuators = {}
    register_exception_handlers(app)
    app.add_middleware(RequestLimitMiddleware, limit=app.state.settings.max_request_bytes)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/operations", dependencies=[Depends(require_role("brain"))])
    async def operations() -> dict:
        return runtime.status()

    @app.post("/operations/{action}", dependencies=[Depends(require_role("brain"))])
    async def control_operations(action: str, request: Request) -> dict:
        payload = await request.json() if request.headers.get("content-length") != "0" else {}
        try:
            runtime.control(action, payload.get("injection"))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return runtime.status()

    @app.post("/readings", dependencies=[Depends(require_role("brain"))])
    async def publish(reading: SensorReading, request: Request) -> dict:
        return await post_to_brain(request, "twin", "/readings", reading)

    @app.post("/readings/batch", dependencies=[Depends(require_role("brain"))])
    async def publish_batch(readings: list[SensorReading], request: Request) -> list[dict]:
        result = await post_to_brain(request, "twin", "/readings/batch", readings)
        return result if isinstance(result, list) else [result]

    @app.post("/commands", dependencies=[Depends(require_role("brain"))])
    async def command(command: ActuatorCommand, request: Request) -> ActuatorFeedback:
        require_reasonable_timestamp(command.issued_at, app.state.settings.replay_window_seconds)
        if command.expires_at <= datetime.now(UTC):
            raise HTTPException(422, "command expired")
        existing = app.state.commands.get(str(command.command_id))
        if existing:
            if existing["command"] != command.model_dump(mode="json"):
                raise HTTPException(409, "conflicting command ID")
            raise HTTPException(409, "duplicate command")
        allowed = {item.strip() for item in app.state.settings.mock_twin_allowed_actions.split(",")}
        if command.action not in allowed:
            raise HTTPException(422, "operation not allowed")
        if app.state.settings.mock_twin_failure_mode == "always":
            raise HTTPException(503, "simulated actuator failure")
        if (
            app.state.settings.mock_twin_failure_mode == "fail_once"
            and command.actuator_id not in app.state.failed_once
        ):
            app.state.failed_once.add(command.actuator_id)
            raise HTTPException(503, "simulated transient failure")
        if app.state.settings.mock_twin_delay_seconds:
            await asyncio.sleep(app.state.settings.mock_twin_delay_seconds)
        app.state.actuators[command.actuator_id] = {
            "action": command.action,
            "parameters": command.parameters,
            "command_id": str(command.command_id),
            "status": "executed",
        }
        runtime.command_executed(command.action, command.actuator_id, command.parameters)
        feedback = ActuatorFeedback(
            feedback_id=uuid5(NAMESPACE_URL, str(command.command_id)),
            command_id=command.command_id,
            correlation_id=command.correlation_id,
            occurred_at=datetime.now(UTC),
            status=FeedbackStatus.EXECUTED,
            detail="simulated execution",
        )
        app.state.commands[str(command.command_id)] = {
            "command": command.model_dump(mode="json"),
            "feedback": feedback.model_dump(mode="json"),
        }
        await post_to_brain(request, "twin", "/feedback", feedback)
        return feedback

    return app


app = create_app()
