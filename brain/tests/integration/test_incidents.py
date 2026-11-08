"""Synthetic simulation fixtures only; thresholds are not operational guidance."""

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select

from app.database.models import CityRegistryRecord, ForecastRecord, IncidentRecord, IncidentRevision
from app.intelligence.incident_rules import IncidentRule, load_rules
from app.main import create_app
from app.schemas.guardian import QuarantineNotification
from app.schemas.sensor import SensorReading
from app.state.registry import Registry
from tests.integration.test_trust_pipeline import post, verdict


def rule(**changes):
    return {
        "id": "simulation",
        "incident_type": "abnormal_temperature",
        "measurement": "temperature",
        "unit": "degC",
        "thresholds": {"medium": 10, "high": 20},
        "persistence_seconds": 5,
        "min_samples": 2,
        "recovery_seconds": 5,
        "recovery_samples": 2,
        "cooldown_seconds": 30,
        **changes,
    }


@asynccontextmanager
async def setup(settings, tmp_path, configured=None, count=1):
    configured = configured or rule()
    path = tmp_path / "simulation-rules.json"
    path.write_text(
        json.dumps({"version": "1.0.0", "simulation_only": True, "rules": [configured]})
    )
    settings.incident_rules_file = str(path)
    settings.worker_enabled = False
    app = create_app(settings)
    registry = Registry.model_validate(
        {
            "zones": ["simulation"],
            "sensors": [
                {
                    "sensor_id": f"fixture-{i}",
                    "zone_id": "simulation",
                    "measurement": configured["measurement"],
                    "unit": configured["unit"],
                }
                for i in range(count)
            ],
        }
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app),
            base_url="http://brain",
        ) as client,
    ):
        with app.state.database.transaction() as session:
            session.merge(CityRegistryRecord(id=1, payload=registry.model_dump()))
        yield app, client, registry


async def sample(app, client, settings, registry, value, stamp, index=0, trusted=True):
    sensor = registry.sensors[index]
    event = SensorReading(
        event_id=uuid4(),
        correlation_id=uuid4(),
        occurred_at=stamp,
        sensor_id=sensor.sensor_id,
        sensor_type=sensor.measurement,
        unit=sensor.unit,
        value=float(value),
    )
    assert (await post(client, settings, "/readings", event, "twin")).status_code == 202
    if trusted:
        assert (
            await post(client, settings, "/verdicts", verdict(event), "guardian")
        ).status_code == 202
    await app.state.processor.tick()
    return event


def rows(app):
    with app.state.database.transaction() as session:
        return list(session.scalars(select(IncidentRecord).order_by(IncidentRecord.occurred_at)))


@pytest.mark.parametrize(
    "kind,measurement,unit,mode,values,threshold",
    [
        ("traffic_congestion", "traffic", "METR-LA_native_speed", "below", [5, 4], 10),
        ("traffic_speed_drop", "traffic", "METR-LA_native_speed", "fall", [30, 20, 10], 1),
        ("rapid_water_rise", "water_level", "m", "rise", [1, 11, 21], 1),
        ("high_water", "water_level", "m", "above", [11, 12], 10),
        ("abnormal_power_load", "power_load", "kW", "above", [11, 12], 10),
        ("power_overload", "power_load", "kW", "above", [11, 12], 10),
        ("air_pollution", "air_quality", "ug/m3", "above", [11, 12], 10),
        ("abnormal_temperature", "temperature", "degC", "above", [11, 12], 10),
        ("smoke_alert", "smoke", "ppm", "above", [11, 12], 10),
    ],
)
async def test_incident_types(settings, tmp_path, kind, measurement, unit, mode, values, threshold):
    configured = rule(
        incident_type=kind,
        measurement=measurement,
        unit=unit,
        mode=mode,
        thresholds={"medium": threshold},
    )
    async with setup(settings, tmp_path, configured) as (app, client, registry):
        now = datetime.now(UTC)
        for i, value in enumerate(values):
            await sample(
                app, client, settings, registry, value, now - timedelta(seconds=30 - i * 5)
            )
        result = rows(app)
        assert len(result) == 1
        assert result[0].payload["status"] == "ACTIVE"
        assert result[0].payload["incident_type"] == kind
        assert result[0].payload["confidence"] == "rule_confirmed"


async def test_lifecycle_concurrency_recovery_restart_and_api(settings, tmp_path):
    async with setup(settings, tmp_path) as (app, client, registry):
        now = datetime.now(UTC)
        await sample(app, client, settings, registry, 11, now - timedelta(seconds=30))
        assert rows(app)[0].payload["status"] == "DETECTED"
        await asyncio.gather(*(app.state.processor.tick() for _ in range(3)))
        assert rows(app)[0].payload["status"] == "DETECTED"
        await sample(app, client, settings, registry, 12, now - timedelta(seconds=25))
        assert rows(app)[0].payload["status"] == "ACTIVE"
        await sample(app, client, settings, registry, 25, now - timedelta(seconds=20))
        assert rows(app)[0].payload["status"] == "ESCALATED"
        headers = {"X-API-Key": settings.brain_api_key.get_secret_value()}
        identifier = rows(app)[0].id
        for route in ("", "/active", "/history", f"/{identifier}"):
            assert (await client.get("/v1/incidents" + route)).status_code == 401
            assert (await client.get("/v1/incidents" + route, headers=headers)).status_code == 200
        assert (await client.get(f"/v1/incidents/{uuid4()}", headers=headers)).status_code == 404
        await sample(app, client, settings, registry, 0, now - timedelta(seconds=15))
        assert rows(app)[0].payload["status"] == "ESCALATED"
        await sample(app, client, settings, registry, 0, now - timedelta(seconds=10))
        assert rows(app)[0].payload["resolution"] == "observed_recovery"
        await sample(app, client, settings, registry, 25, now - timedelta(seconds=5))
        await sample(app, client, settings, registry, 25, now)
        assert len(rows(app)) == 1
        with app.state.database.transaction() as session:
            states = [r.payload["status"] for r in session.scalars(select(IncidentRevision))]
        assert states == ["DETECTED", "ACTIVE", "ESCALATED", "RESOLVED"]
    restarted = create_app(settings)
    async with restarted.router.lifespan_context(restarted):
        await restarted.state.processor.tick()
        assert len(rows(restarted)) == 1
        assert rows(restarted)[0].id == identifier


@pytest.mark.parametrize("invalidity", ["revoked", "quarantine", "stale", "untrusted"])
async def test_invalid_evidence(settings, tmp_path, invalidity):
    async with setup(settings, tmp_path) as (app, client, registry):
        now = datetime.now(UTC)
        await sample(
            app,
            client,
            settings,
            registry,
            11,
            now - timedelta(seconds=10),
            trusted=invalidity != "untrusted",
        )
        event = await sample(
            app,
            client,
            settings,
            registry,
            12,
            now - timedelta(seconds=5),
            trusted=invalidity != "untrusted",
        )
        if invalidity == "untrusted":
            assert rows(app) == []
            return
        if invalidity == "revoked":
            await post(
                client,
                settings,
                "/verdicts",
                verdict(event, revision=1, status="revoked"),
                "guardian",
            )
        elif invalidity == "quarantine":
            notification = QuarantineNotification(
                notification_id=uuid4(),
                correlation_id=uuid4(),
                issued_at=datetime.now(UTC),
                guardian_id=settings.guardian_identity,
                target_type="sensor",
                target_id=event.sensor_id,
                action="quarantine",
                revision=1,
                reason_code="fixture",
            )
            response = await post(client, settings, "/quarantines", notification, "guardian")
            assert response.status_code == 202
        await app.state.processor.tick(
            now + timedelta(seconds=400) if invalidity == "stale" else None
        )
        assert rows(app)[0].payload["status"] == "RESOLVED"
        assert not rows(app)[0].payload["evidence_eligible"]


async def test_multisensor_confirmation_and_false_alarm(settings, tmp_path):
    async with setup(settings, tmp_path, rule(min_sensors=2), count=2) as (app, client, registry):
        now = datetime.now(UTC)
        for i in range(2):
            await sample(app, client, settings, registry, 11, now - timedelta(seconds=20), i)
        assert rows(app)[0].payload["status"] == "DETECTED"
        for i in range(2):
            await sample(app, client, settings, registry, 0, now - timedelta(seconds=15), i)
            await sample(app, client, settings, registry, 0, now - timedelta(seconds=10), i)
        assert rows(app)[0].payload["status"] == "RESOLVED"
        assert all(r.payload["status"] != "ACTIVE" for r in rows(app))


@pytest.mark.parametrize("failure", ["failed_forecast", "revoked", "expired"])
async def test_forecast_warning_and_failure(settings, tmp_path, failure):
    configured = rule(
        incident_type="high_water",
        measurement="water_level",
        unit="ft",
        source="forecast",
        min_samples=1,
        persistence_seconds=0,
    )
    async with setup(settings, tmp_path, configured) as (app, client, registry):
        event = await sample(
            app, client, settings, registry, 1, datetime.now(UTC) - timedelta(seconds=5)
        )
        assert not rows(app)
        state = app.state.city_engine.snapshot()
        sensor = state["sensors"][event.sensor_id]
        with app.state.database.transaction() as session:
            prediction = ForecastRecord(
                id=uuid4(),
                correlation_id=uuid4(),
                occurred_at=datetime.now(UTC),
                family="water",
                status="succeeded",
                payload={
                    "request": {"sensor_id": event.sensor_id},
                    "sensor_mappings": [registry.sensors[0].model_dump()],
                    "evidence": sensor["evidence"],
                    "predictions": [
                        {
                            "unit": "ft",
                            "value": 12,
                            "horizon_minutes": 60,
                            "forecast_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                        }
                    ],
                    "fixture": "synthetic forecast, not model inference",
                },
            )
            session.add(prediction)
        await app.state.processor.tick()
        assert rows(app)[0].payload["classification"] == "early_warning"
        assert rows(app)[0].payload["status"] == "ACTIVE"
        if failure == "revoked":
            await post(
                client,
                settings,
                "/verdicts",
                verdict(event, revision=1, status="revoked"),
                "guardian",
            )
        elif failure == "failed_forecast":
            with app.state.database.transaction() as session:
                session.add(
                    ForecastRecord(
                        id=uuid4(),
                        correlation_id=uuid4(),
                        occurred_at=datetime.now(UTC),
                        family="water",
                        status="failed",
                        payload={"request": {"sensor_id": event.sensor_id}},
                    )
                )
        await app.state.processor.tick(
            datetime.now(UTC) + timedelta(hours=2) if failure == "expired" else None,
        )
        assert rows(app)[0].payload["resolution"] == "evidence_invalidated"


async def test_correlation_and_cooldown(settings, tmp_path):
    configured = rule(
        min_sensors=2,
        min_samples=1,
        persistence_seconds=0,
        recovery_samples=1,
        recovery_seconds=0,
        correlation_seconds=2,
        cooldown_seconds=1,
    )
    async with setup(settings, tmp_path, configured, count=2) as (app, client, registry):
        now = datetime.now(UTC)
        for i in range(2):
            await sample(app, client, settings, registry, 11, now - timedelta(seconds=10), i)
        assert rows(app)[0].payload["confidence"] == "corroborated"
        await sample(app, client, settings, registry, 11, now - timedelta(seconds=5))
        assert rows(app)[0].payload["status"] == "RESOLVED"
        assert rows(app)[0].payload["resolution"] == "evidence_invalidated"
        await sample(app, client, settings, registry, 11, now - timedelta(seconds=5), 1)
        assert len(rows(app)) == 1
        await app.state.processor.tick(datetime.now(UTC) + timedelta(seconds=2))
        assert len(rows(app)) == 2
        assert rows(app)[1].payload["status"] == "ACTIVE"


async def test_revoke_old_support_during_recovery(settings, tmp_path):
    async with setup(settings, tmp_path) as (app, client, registry):
        now = datetime.now(UTC)
        old = await sample(app, client, settings, registry, 11, now - timedelta(seconds=20))
        await sample(app, client, settings, registry, 11, now - timedelta(seconds=15))
        await sample(app, client, settings, registry, 0, now - timedelta(seconds=10))
        assert rows(app)[0].payload["status"] == "ACTIVE"
        await post(
            client, settings, "/verdicts", verdict(old, revision=1, status="revoked"), "guardian"
        )
        app.state.city_engine.snapshot()
        assert rows(app)[0].payload["resolution"] == "evidence_invalidated"


def test_rule_validation(tmp_path):
    with pytest.raises(ValueError):
        IncidentRule.model_validate(rule(unit="ppm"))
    with pytest.raises(ValueError):
        IncidentRule.model_validate(rule(thresholds={"medium": 20, "high": 10}))
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"version": "1.0.0", "simulation_only": True, "rules": [rule()]}))
    with pytest.raises(ValueError, match="simulation"):
        load_rules(str(path), "production")
    assert len(load_rules("config/incidents.simulation.yaml", "development").rules) == 10


async def test_missing_history_gap_and_removed_rules(settings, tmp_path):
    async with setup(settings, tmp_path, rule(max_gap_seconds=6)) as (app, client, registry):
        await app.state.processor.tick()
        assert rows(app) == []
        now = datetime.now(UTC)
        await sample(app, client, settings, registry, 11, now - timedelta(seconds=20))
        await sample(app, client, settings, registry, 11, now - timedelta(seconds=10))
        assert rows(app)[0].payload["status"] == "DETECTED"
        await sample(app, client, settings, registry, 11, now - timedelta(seconds=5))
        assert rows(app)[0].payload["status"] == "ACTIVE"
        app.state.city_engine.incidents.rules.rules = []
        await app.state.processor.tick()
        assert rows(app)[0].payload["resolution"] == "rule_or_zone_removed"
