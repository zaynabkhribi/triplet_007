from datetime import timedelta
from uuid import uuid4

import httpx
import pytest
from pydantic import ValidationError

from app.database.models import CityRegistryRecord
from app.main import create_app
from app.state.fusion import correlation, statistics
from app.state.registry import Registry
from tests.integration.test_trust_pipeline import post, verdict
from tests.security.test_contracts import reading


def test_fusion_statistics():
    result = statistics([(0, 2), (2, 4)], 0.5)
    assert result == {"count": 2, "mean": 3, "stddev": 1, "ema": 3, "rate_per_second": 1}
    assert correlation({0: 2, 1: 4}, {0: 3, 1: 6}) == 1
    assert correlation({0: 2}, {1: 3}) is None
    assert statistics([], 0.5)["mean"] is None


def test_invalid_registry():
    with pytest.raises(ValidationError):
        Registry.model_validate(
            {
                "sensors": [
                    {
                        "sensor_id": "x",
                        "zone_id": "absent",
                        "measurement": "temperature",
                        "unit": "ppm",
                    }
                ]
            }
        )


async def test_city_fusion_recovery_and_revocation(settings):
    settings.worker_enabled = False
    event = reading().model_copy(update={"sensor_type": "temperature", "unit": "degC"})
    config = Registry.model_validate(
        {
            "zones": ["zone"],
            "sensors": [
                {"sensor_id": sid, "zone_id": "zone", "measurement": "temperature", "unit": "degC"}
                for sid in [event.sensor_id, "second", "missing"]
            ],
        }
    )
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://brain") as client,
    ):
        with app.state.database.transaction() as session:
            session.merge(CityRegistryRecord(id=1, payload=config.model_dump()))
        events = [
            event,
            reading().model_copy(
                update={
                    "sensor_id": "second",
                    "sensor_type": "temperature",
                    "unit": "degC",
                    "value": 4.5,
                }
            ),
        ]
        for item in events:
            await post(client, settings, "/readings", item, "twin")
            await post(client, settings, "/verdicts", verdict(item), "guardian")
        await app.state.processor.tick()
        state = app.state.city_engine.snapshot()
        assert state["zones"]["zone"]["measurements"]["temperature:degC"]["value"] == 3
        assert state["sensors"]["missing"]["availability"] == "missing"
        pending = event.model_copy(
            update={"event_id": uuid4(), "occurred_at": event.occurred_at + timedelta(seconds=1)}
        )
        await post(client, settings, "/readings", pending, "twin")
        await app.state.processor.tick()
        pending_state = app.state.city_engine.snapshot()
        assert pending_state["sensors"][event.sensor_id]["value"] == event.value
        assert pending_state["sensors"][event.sensor_id]["availability"] == "available"
        version = state["version"]
        assert app.state.city_engine.snapshot()["version"] >= version
        assert (await client.get("/v1/city/state")).status_code == 401
        headers = {"X-API-Key": settings.brain_api_key.get_secret_value()}
        for path in [
            "state",
            "zones",
            "zones/zone",
            "sensors",
            f"sensors/{event.sensor_id}",
            "history",
        ]:
            assert (await client.get("/v1/city/" + path, headers=headers)).status_code == 200
        revoked = verdict(event, revision=1, status="revoked")
        await post(client, settings, "/verdicts", revoked, "guardian")
        assert app.state.city_engine.snapshot()["sensors"][event.sensor_id]["value"] is None
        await app.state.processor.tick(event.occurred_at + timedelta(seconds=400))
    restored = create_app(settings)
    async with restored.router.lifespan_context(restored):
        state = restored.state.city_engine.snapshot()
        assert state["version"] > version
        assert state["sensors"][event.sensor_id]["value"] is None
