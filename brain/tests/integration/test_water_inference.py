from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest

from app.database.models import CityRegistryRecord, GuardianVerdictRecord, SensorEvent
from app.intelligence.artifacts import LoadedArtifact
from app.intelligence.water_features import WATER_FEATURES
from app.main import create_app
from app.schemas.guardian import QuarantineNotification
from app.security.event_hash import event_hash
from app.state.registry import Registry
from tests.integration.test_trust_pipeline import post, verdict
from tests.security.test_contracts import reading


class FixtureDeltaModel:
    """Explicit test double; not a production forecasting model."""

    def predict(self, values, **kwargs):
        assert values.shape == (1, 40)
        return [0.5]


@pytest.mark.parametrize("invalidator", ["revoked", "quarantined"])
async def test_water_inference_persistence_and_invalidation(settings, invalidator):
    settings.worker_enabled = False
    settings.event_freshness_seconds = 86400
    app = create_app(settings)
    origin = datetime.now(UTC).replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    metadata = {
        "feature_names": WATER_FEATURES,
        "site_index": {"fixture": 0},
        "site_stats": {
            "fixture": {
                "stage_median_ft": 2,
                "stage_scale_ft": 2,
                "flow_log_median": 1,
            }
        },
    }
    registry = Registry.model_validate(
        {
            "zones": ["test"],
            "sensors": [
                {
                    "sensor_id": "test-stage",
                    "zone_id": "test",
                    "measurement": "water_level",
                    "unit": "ft",
                    "training_source": "USGS",
                    "training_id": "fixture",
                    "training_compatible": True,
                    "freshness_seconds": 86400,
                }
            ],
        }
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://brain") as client,
    ):
        app.state.artifacts = SimpleNamespace(
            artifacts=[
                LoadedArtifact(
                    "water", horizon, FixtureDeltaModel(), "fixture", WATER_FEATURES, metadata
                )
                for horizon in (60, 180, 360)
            ]
        )
        samples = []
        with app.state.database.transaction() as session:
            session.merge(CityRegistryRecord(id=1, payload=registry.model_dump()))
            for lag in (0, 1, 2, 3, 6):
                event = reading().model_copy(
                    update={
                        "sensor_id": "test-stage",
                        "sensor_type": "water_level",
                        "unit": "ft",
                        "occurred_at": origin - timedelta(hours=lag),
                        "value": 10.0 - lag,
                    }
                )
                samples.append(event)
                session.add(
                    SensorEvent(
                        id=event.event_id,
                        correlation_id=event.correlation_id,
                        occurred_at=event.occurred_at,
                        sensor_id=event.sensor_id,
                        payload={
                            "event": event.model_dump(mode="json"),
                            "sha256": event_hash(event),
                        },
                    )
                )
                decision = verdict(event)
                session.add(
                    GuardianVerdictRecord(
                        id=decision.verdict_id,
                        event_id=event.event_id,
                        correlation_id=event.correlation_id,
                        occurred_at=decision.issued_at,
                        status="trusted",
                        payload={"event": decision.model_dump(mode="json")},
                    )
                )
        await app.state.processor.tick()
        headers = {"X-API-Key": settings.brain_api_key.get_secret_value()}
        request = {
            "sensor_id": "test-stage",
            "horizons_minutes": [60, 180, 360],
            "origin": origin.isoformat(),
        }
        response = await client.post("/v1/forecasts/water", headers=headers, json=request)
        assert response.status_code == 200, response.text
        assert [item["value"] for item in response.json()["predictions"]] == [11, 11, 11]
        assert len(response.json()["evidence"]) == 5
        assert response.json()["features"][30] is None
        if invalidator == "revoked":
            await post(
                client,
                settings,
                "/verdicts",
                verdict(samples[0], status="revoked", revision=1),
                "guardian",
            )
        else:
            notice = QuarantineNotification(
                notification_id=uuid4(),
                correlation_id=uuid4(),
                guardian_id=settings.guardian_identity,
                issued_at=datetime.now(UTC),
                target_type="sensor",
                target_id="test-stage",
                action="quarantine",
                revision=1,
                reason_code="test",
            )
            await post(client, settings, "/quarantines", notice, "guardian")
        response = await client.post("/v1/forecasts/water", headers=headers, json=request)
        assert response.status_code == 503
        history = await client.get("/v1/forecasts/history", headers=headers)
        assert len(history.json()) == 2
        assert all(not item["currently_eligible"] for item in history.json())
