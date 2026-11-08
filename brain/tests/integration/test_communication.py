from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
from sqlalchemy import func, select

from app.database.models import ActuatorFeedbackRecord, GuardianVerdictRecord, SensorEvent
from app.main import create_app
from app.schemas.actuator import ActuatorCommand
from app.schemas.guardian import QuarantineNotification
from mocks.mock_guardian import create_app as create_guardian
from mocks.mock_twin import create_app as create_twin
from tests.security.test_contracts import reading


async def test_three_service_exchange(settings) -> None:
    brain = create_app(settings)
    twin, guardian = create_twin(settings), create_guardian(settings)
    twin.state.transport = guardian.state.transport = httpx.ASGITransport(brain)
    event = reading()
    headers = {"X-API-Key": settings.brain_api_key.get_secret_value()}
    async with (
        brain.router.lifespan_context(brain),
        httpx.AsyncClient(transport=httpx.ASGITransport(twin), base_url="http://twin") as tc,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(guardian), base_url="http://guardian"
        ) as gc,
        httpx.AsyncClient(transport=httpx.ASGITransport(brain), base_url="http://brain") as bc,
    ):
        payload = event.model_dump(mode="json")
        assert (await tc.post("/readings", json=payload)).status_code == 401
        assert (await gc.post("/evaluate", json=payload)).status_code == 401
        assert (await tc.post("/readings", headers=headers, json=payload)).status_code == 200
        verdict = await gc.post("/evaluate", headers=headers, json=payload)
        assert verdict.status_code == 200
        bad = verdict.json() | {"verdict_id": str(uuid4()), "event_hash": "0" * 64}
        assert (
            await bc.post(
                "/verdicts",
                json=bad,
                headers={
                    "X-API-Key": settings.guardian_api_key.get_secret_value(),
                },
            )
        ).status_code == 409
        now = datetime.now(UTC)
        command = ActuatorCommand(
            command_id=uuid4(),
            decision_id=uuid4(),
            correlation_id=event.correlation_id,
            issued_at=now,
            expires_at=now + timedelta(seconds=60),
            actuator_id="mock",
            action="test",
        )
        assert (
            await tc.post("/commands", headers=headers, json=command.model_dump(mode="json"))
        ).status_code == 200
        assert (
            await tc.post("/commands", headers=headers, json=command.model_dump(mode="json"))
        ).status_code == 409
        await brain.state.processor.tick()
        status = await bc.get(f"/events/{event.event_id}", headers=headers)
        assert status.json()["state"] == "TRUSTED"
        assert status.json()["eligible"]
        state = await bc.get("/state/trusted", headers=headers)
        assert state.json()["sensors"][event.sensor_id]["event_id"] == str(event.event_id)
        quarantine = QuarantineNotification(
            notification_id=uuid4(),
            correlation_id=event.correlation_id,
            guardian_id=settings.guardian_identity,
            issued_at=datetime.now(UTC),
            target_type="sensor",
            target_id=event.sensor_id,
            action="quarantine",
            revision=1,
            reason_code="mock_test",
        )
        assert (
            await gc.post(
                "/quarantines",
                headers=headers,
                json=quarantine.model_dump(mode="json"),
            )
        ).status_code == 200
        state = await bc.get("/state/trusted", headers=headers)
        assert not state.json()["sensors"]
        with brain.state.database.session_factory() as session:
            for table in (SensorEvent, GuardianVerdictRecord, ActuatorFeedbackRecord):
                assert session.scalar(select(func.count()).select_from(table)) == 1
