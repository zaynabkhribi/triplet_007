from uuid import NAMESPACE_URL, uuid5

from fastapi import Depends, FastAPI, Request

from app.core.config import Settings
from app.core.exceptions import register_exception_handlers
from app.integration.http import post_to_brain
from app.schemas.guardian import GuardianVerdict, QuarantineNotification, TrustStatus
from app.schemas.sensor import SensorReading
from app.security.authorization import require_role
from app.security.event_hash import event_hash
from app.security.validation import RequestLimitMiddleware


def create_app(settings: Settings | None = None) -> FastAPI:
    app = FastAPI(title="Mock Guardian")
    app.state.settings = settings or Settings()
    register_exception_handlers(app)
    app.add_middleware(RequestLimitMiddleware, limit=app.state.settings.max_request_bytes)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/quarantines", dependencies=[Depends(require_role("brain"))])
    async def quarantine(event: QuarantineNotification, request: Request) -> dict:
        return await post_to_brain(request, "guardian", "/quarantines", event)

    @app.post("/evaluate", dependencies=[Depends(require_role("brain"))])
    async def evaluate(reading: SensorReading, request: Request) -> GuardianVerdict:
        simulated_spoof = reading.attributes.get("simulation_trust") == "spoofed"
        verdict = GuardianVerdict(
            verdict_id=uuid5(NAMESPACE_URL, str(reading.event_id)),
            event_id=reading.event_id,
            event_hash=event_hash(reading),
            correlation_id=reading.correlation_id,
            issued_at=reading.occurred_at,
            status=(
                TrustStatus.REJECTED
                if simulated_spoof
                else TrustStatus(app.state.settings.mock_guardian_default_status)
            ),
            reason_code="simulated_spoof" if simulated_spoof else "mock_only",
            guardian_id=app.state.settings.guardian_identity,
        )
        await post_to_brain(request, "guardian", "/verdicts", verdict)
        return verdict

    @app.post("/evaluate-batch", dependencies=[Depends(require_role("brain"))])
    async def evaluate_batch(
        readings: list[SensorReading], request: Request
    ) -> list[GuardianVerdict]:
        verdicts = []
        for reading in readings:
            simulated_spoof = reading.attributes.get("simulation_trust") == "spoofed"
            verdicts.append(
                GuardianVerdict(
                    verdict_id=uuid5(NAMESPACE_URL, str(reading.event_id)),
                    event_id=reading.event_id,
                    event_hash=event_hash(reading),
                    correlation_id=reading.correlation_id,
                    issued_at=reading.occurred_at,
                    status=(
                        TrustStatus.REJECTED
                        if simulated_spoof
                        else TrustStatus(app.state.settings.mock_guardian_default_status)
                    ),
                    reason_code="simulated_spoof" if simulated_spoof else "mock_only",
                    guardian_id=app.state.settings.guardian_identity,
                )
            )
        await post_to_brain(request, "guardian", "/verdicts/batch", verdicts)
        return verdicts

    return app


app = create_app()
