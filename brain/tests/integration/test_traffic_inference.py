import os
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import numpy as np
from sqlalchemy import insert, select

from app.database.models import (
    CityRegistryRecord,
    EventLifecycle,
    ForecastRecord,
    GuardianVerdictRecord,
    QuarantineRecord,
    SensorEvent,
)
from app.intelligence.artifacts import ArtifactRegistry, LoadedArtifact
from app.intelligence.traffic_features import TRAFFIC_FEATURES, traffic_features
from app.main import create_app
from app.schemas.guardian import GuardianVerdict, TrustStatus
from app.schemas.sensor import SensorReading
from app.security.event_hash import event_hash
from app.state.registry import Registry


class FixtureTrafficModel:
    """Test-only model; predictions are not production results."""

    def attr(self, name):
        assert name == "best_iteration"
        return "1"

    def predict(self, matrix, iteration_range):
        assert iteration_range == (0, 2)
        assert matrix.num_col() == 24
        return np.array([42.0])


def preparation():
    return {
        "sensor_train_mean": np.full(207, 50, dtype=np.float32),
        "sensor_train_std": np.full(207, 5, dtype=np.float32),
        "neighbor_ids": np.zeros((207, 2), dtype=np.int32),
        "train_weekly_mean": np.ones((2016, 207), dtype=np.float32),
    }


def test_exact_traffic_features():
    grid = np.tile(np.arange(289, dtype=float)[:, None] + 1, (1, 207))
    prep = preparation()
    prep["train_weekly_mean"][:, 0] = np.arange(2016)
    origin = datetime(2026, 1, 5, 23, 55)
    for horizon in (15, 30, 60):
        row = dict(
            zip(TRAFFIC_FEATURES, traffic_features(grid, 0, origin, horizon, prep)[0], strict=True)
        )
        target = origin + timedelta(minutes=horizon)
        assert row["yesterday_same_target_time"] == horizon // 5 + 1
        assert (
            row["train_weekly_mean"]
            == target.weekday() * 288 + (target.hour * 60 + target.minute) // 5
        )
        assert row["lag_36"] == 253
        assert row["mean_3"] == 288
        np.testing.assert_allclose(row["std_12"], np.std(grid[-12:, 0], ddof=1), rtol=1e-6)
    grid[3, 0] = 0
    assert traffic_features(grid, 0, origin, 15, prep)[0][22] == grid[-1, 0]


async def test_full_grid_api_security_persistence_restart(settings):
    settings.worker_enabled = False
    settings.event_freshness_seconds = 172800
    settings.verdict_ttl_seconds = 3600
    app = create_app(settings)
    now = datetime.now(UTC)
    origin = now.replace(minute=now.minute // 5 * 5, second=0, microsecond=0)
    ids = [f"fixture-{i}" for i in range(207)]
    native = None
    if directory := os.environ.get("TRAFFIC_TEST_ARTIFACT_DIR"):
        native = ArtifactRegistry(directory, None)
        native.artifacts = [item for item in native.artifacts if item.family == "traffic"]
        assert all(item.status()["inference_ready"] for item in native.artifacts)
        ids = native.artifacts[0].metadata["sensor_ids"]
    registry = Registry.model_validate(
        {
            "zones": ["fixture-zone"],
            "sensors": [
                {
                    "sensor_id": sid,
                    "zone_id": "fixture-zone",
                    "measurement": "traffic",
                    "unit": "METR-LA_native_speed",
                    "freshness_seconds": 172800,
                    "training_source": "METR-LA",
                    "training_id": sid,
                    "training_compatible": True,
                    "training_timezone": "UTC",
                }
                for sid in ids
            ],
        }
    )
    artifacts = SimpleNamespace(
        artifacts=[
            LoadedArtifact(
                "traffic",
                horizon,
                FixtureTrafficModel(),
                "test-only",
                TRAFFIC_FEATURES,
                {"sensor_ids": ids},
                None,
                preparation(),
                "test-only",
            )
            for horizon in (15, 30, 60)
        ]
    )
    headers = {"X-API-Key": settings.brain_api_key.get_secret_value()}
    body = {"sensor_id": ids[0], "origin": origin.isoformat(), "horizons_minutes": [15, 30, 60]}
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://brain") as client,
    ):
        app.state.artifacts = native or artifacts
        with app.state.database.transaction() as session:
            session.merge(CityRegistryRecord(id=1, payload=registry.model_dump()))
        assert (await client.post("/v1/forecasts/traffic", json=body)).status_code == 401
        assert (
            await client.post(
                "/v1/forecasts/traffic", headers=headers, json=body | {"sensor_id": "unknown"}
            )
        ).status_code == 503
        response = await client.post("/v1/forecasts/traffic", headers=headers, json=body)
        assert response.status_code == 503
        assert "history_required" in response.json()["detail"]["reason"]
        first_id = None
        with app.state.database.transaction() as session:
            for sensor_id in ids:
                readings, verdicts, lifecycles = [], [], []
                for step in range(289):
                    event = SensorReading(
                        event_id=uuid4(),
                        correlation_id=uuid4(),
                        sensor_id=sensor_id,
                        sensor_type="traffic",
                        unit="METR-LA_native_speed",
                        value=50.0,
                        occurred_at=origin - timedelta(minutes=5 * (288 - step)),
                    )
                    first_id = first_id or event.event_id
                    digest = event_hash(event)
                    decision = GuardianVerdict(
                        verdict_id=uuid4(),
                        event_id=event.event_id,
                        correlation_id=event.correlation_id,
                        event_hash=digest,
                        issued_at=now,
                        status=TrustStatus.TRUSTED,
                        guardian_id=settings.guardian_identity,
                        reason_code="fixture",
                    )
                    readings.append(
                        dict(
                            id=event.event_id,
                            correlation_id=event.correlation_id,
                            sensor_id=sensor_id,
                            occurred_at=event.occurred_at,
                            payload={"event": event.model_dump(mode="json"), "sha256": digest},
                        )
                    )
                    verdicts.append(
                        dict(
                            id=decision.verdict_id,
                            event_id=event.event_id,
                            correlation_id=event.correlation_id,
                            occurred_at=now,
                            status="trusted",
                            payload={"event": decision.model_dump(mode="json")},
                        )
                    )
                    lifecycles.append(
                        dict(
                            event_id=event.event_id,
                            state="TRUSTED",
                            processing="acknowledged",
                            received_at=now,
                            eligible=True,
                            eligible_until=now + timedelta(hours=1),
                            verdict_id=decision.verdict_id,
                        )
                    )
                session.execute(insert(SensorEvent), readings)
                session.execute(insert(GuardianVerdictRecord), verdicts)
                session.execute(insert(EventLifecycle), lifecycles)
        response = await client.post("/v1/forecasts/traffic", headers=headers, json=body)
        assert response.status_code == 200, response.text
        assert [item["horizon_minutes"] for item in response.json()["predictions"]] == [15, 30, 60]
        if native:
            assert all(np.isfinite(item["value"]) for item in response.json()["predictions"])
            assert [item["best_iteration"] for item in response.json()["predictions"]] == [
                int(item.model.attr("best_iteration")) for item in native.artifacts
            ]
        else:
            assert all(item["value"] == 42 for item in response.json()["predictions"])
        assert len(response.json()["evidence"]) == 207 * 289
        settings.event_freshness_seconds = 1
        response = await client.post("/v1/forecasts/traffic", headers=headers, json=body)
        assert response.status_code == 503
        assert response.json()["detail"]["reason"] == "evidence_not_currently_trusted"
        settings.event_freshness_seconds = 172800
        with app.state.database.transaction() as session:
            session.get(EventLifecycle, first_id).eligible = False
        response = await client.post("/v1/forecasts/traffic", headers=headers, json=body)
        assert response.status_code == 503
        assert response.json()["detail"]["reason"] == "evidence_not_currently_trusted"
        with app.state.database.transaction() as session:
            lifecycle = session.get(EventLifecycle, first_id)
            lifecycle.eligible = True
            record = session.get(GuardianVerdictRecord, lifecycle.verdict_id)
            original_payload = record.payload
            record.payload = {"event": original_payload["event"] | {"status": "revoked"}}
        response = await client.post("/v1/forecasts/traffic", headers=headers, json=body)
        assert response.status_code == 503
        with app.state.database.transaction() as session:
            session.get(GuardianVerdictRecord, lifecycle.verdict_id).payload = original_payload
            session.add(
                QuarantineRecord(
                    id=uuid4(),
                    correlation_id=uuid4(),
                    occurred_at=now,
                    target_type="sensor",
                    target_id=ids[0],
                    payload={"event": {"action": "quarantine", "revision": 1}},
                )
            )
        response = await client.post("/v1/forecasts/traffic", headers=headers, json=body)
        assert response.status_code == 503
        assert response.json()["detail"]["reason"] == "sensor_quarantined"
        with app.state.database.transaction() as session:
            current = session.get(CityRegistryRecord, 1)
            invalid = registry.model_dump()
            invalid["sensors"][0]["unit"] = "vehicles/min"
            current.payload = invalid
        response = await client.post("/v1/forecasts/traffic", headers=headers, json=body)
        assert response.status_code == 503
        assert response.json()["detail"]["reason"] == "incompatible_traffic_mapping_or_units"
    restarted = create_app(settings)
    async with restarted.router.lifespan_context(restarted):
        with restarted.state.database.transaction() as session:
            result = session.scalar(
                select(ForecastRecord).where(ForecastRecord.status == "succeeded")
            )
            assert len(result.payload["predictions"]) == 3
