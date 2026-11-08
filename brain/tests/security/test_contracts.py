from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from app.core.config import Settings
from app.database.models import SensorEvent
from app.main import create_app
from app.schemas.sensor import SensorReading
from app.security.event_hash import event_hash


def reading() -> SensorReading:
    return SensorReading(
        event_id=uuid4(),
        correlation_id=uuid4(),
        occurred_at=datetime.now(UTC),
        sensor_id="sensor",
        sensor_type="traffic",
        value=1.5,
        unit="count",
    )


@pytest.mark.parametrize(
    "change",
    [
        {"value": "1.5"},
        {"value": True},
        {"value": float("inf")},
        {"occurred_at": "2026-01-01T00:00:00"},
        {"schema_version": "1.9.0"},
        {"unknown": 1},
        {"sensor_id": 123},
    ],
)
def test_strict_contract(change) -> None:
    with pytest.raises(ValidationError):
        SensorReading.model_validate(reading().model_dump() | change)


def test_hash_is_stable_and_sensitive() -> None:
    event = reading()
    assert event_hash(event) == event_hash(
        SensorReading.model_validate_json(event.model_dump_json())
    )
    assert event_hash(event) != event_hash(event.model_copy(update={"value": 2.0}))


@pytest.mark.parametrize("role,expected", [(None, 401), ("guardian", 403), ("twin", 202)])
async def test_authentication_and_roles(settings, role, expected) -> None:
    app = create_app(settings)
    headers = {"X-Service-Role": "twin"}
    if role:
        headers["X-API-Key"] = getattr(settings, f"{role}_api_key").get_secret_value()
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://brain") as client,
    ):
        response = await client.post(
            "/readings", json=reading().model_dump(mode="json"), headers=headers
        )
        assert response.status_code == expected


async def test_persistence_duplicate_and_validation(settings) -> None:
    event = reading()
    for attempt in range(2):
        app = create_app(settings)
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app),
                base_url="http://brain",
                headers={"X-API-Key": settings.twin_api_key.get_secret_value()},
            ) as c,
        ):
            result = await c.post("/readings", json=event.model_dump(mode="json"))
            assert result.status_code == (202 if attempt == 0 else 409)
            assert (await c.post("/readings", content="x")).status_code == 415
            assert (
                await c.post("/readings", content="{", headers={"Content-Type": "application/json"})
            ).status_code == 422
            assert (
                await c.post(
                    "/readings", content="x" * 70000, headers={"Content-Type": "application/json"}
                )
            ).status_code == 413
            stale = event.model_copy(
                update={
                    "event_id": uuid4(),
                    "occurred_at": datetime.now(UTC) - timedelta(hours=1),
                }
            )
            assert (
                await c.post("/readings", json=stale.model_dump(mode="json"))
            ).status_code == 422
            with app.state.database.session_factory() as session:
                assert session.scalar(select(func.count()).select_from(SensorEvent)) == 1
                assert session.get(SensorEvent, event.event_id).payload["sha256"] == event_hash(
                    event
                )


def test_missing_credentials_fail_closed() -> None:
    assert Settings(_env_file=None).brain_api_key is None


def test_short_keys_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, twin_api_key="short")
