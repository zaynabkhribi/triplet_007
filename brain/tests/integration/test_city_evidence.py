import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.database.models import CityRegistryRecord, CitySnapshot
from app.schemas.guardian import QuarantineNotification
from app.state.engine import CityEngine
from app.state.registry import Registry
from tests.integration.test_trust_pipeline import pipeline as pipeline
from tests.integration.test_trust_pipeline import post, verdict
from tests.security.test_contracts import reading


def register(app) -> None:
    registry = Registry.model_validate(
        {
            "zones": ["test-zone"],
            "ema_alpha": 0.5,
            "sensors": [
                {
                    "sensor_id": sid,
                    "zone_id": "test-zone",
                    "measurement": "temperature",
                    "unit": "degC",
                    "weight": weight,
                    "freshness_seconds": 60,
                }
                for sid, weight in (("first", 1), ("second", 3))
            ],
        }
    )
    with app.state.database.transaction() as session:
        session.merge(CityRegistryRecord(id=1, payload=registry.model_dump()))


async def ingest(app, client, settings, sensor_id, value, at, trusted=True):
    event = reading().model_copy(
        update={
            "sensor_id": sensor_id,
            "sensor_type": "temperature",
            "unit": "degC",
            "value": value,
            "occurred_at": at,
        }
    )
    assert (await post(client, settings, "/readings", event, "twin")).status_code == 202
    decision = verdict(event, status="trusted" if trusted else "rejected")
    assert (await post(client, settings, "/verdicts", decision, "guardian")).status_code == 202
    await app.state.processor.tick()
    return event


async def test_window_weighting_out_of_order_and_concurrent_snapshots(pipeline):
    app, client, settings = pipeline
    register(app)
    now = datetime.now(UTC) - timedelta(seconds=1)
    await ingest(app, client, settings, "first", 4.0, now)
    await ingest(app, client, settings, "first", 2.0, now - timedelta(seconds=2))
    await ingest(app, client, settings, "second", 8.0, now)
    await ingest(app, client, settings, "second", 4.0, now - timedelta(seconds=2))
    engine = CityEngine(app.state.database, settings)
    snapshots = await asyncio.gather(*[asyncio.to_thread(engine.snapshot) for _ in range(4)])
    assert len({snapshot["version"] for snapshot in snapshots}) == 1
    state = snapshots[0]
    assert state["sensors"]["first"]["statistics"] == {
        "count": 2,
        "mean": 3,
        "stddev": 1,
        "ema": 3,
        "rate_per_second": 1,
    }
    fused = state["zones"]["test-zone"]["measurements"]["temperature:degC"]
    assert fused["value"] == 7
    assert fused["correlations"][0]["value"] == 1
    with app.state.database.transaction() as session:
        expired = engine.rebuild(session, now + timedelta(seconds=70))
        assert expired["sensors"]["first"]["availability"] == "stale"
        assert expired["zones"]["test-zone"]["measurements"]["temperature:degC"]["value"] is None
        history = session.scalars(select(CitySnapshot).order_by(CitySnapshot.version)).all()
        assert any(row.payload["sensors"]["first"]["value"] == 4 for row in history)


@pytest.mark.parametrize("change", ["rejected", "quarantined", "revoked"])
async def test_invalid_evidence_excluded_and_history_preserved(pipeline, change):
    app, client, settings = pipeline
    register(app)
    now = datetime.now(UTC) - timedelta(seconds=1)
    event = await ingest(app, client, settings, "first", 2.0, now)
    engine = CityEngine(app.state.database, settings)
    original = engine.snapshot()
    if change == "quarantined":
        notice = QuarantineNotification(
            notification_id=uuid4(),
            correlation_id=event.correlation_id,
            guardian_id=settings.guardian_identity,
            issued_at=datetime.now(UTC),
            target_type="sensor",
            target_id="first",
            action="quarantine",
            revision=1,
            reason_code="test",
        )
        await post(client, settings, "/quarantines", notice, "guardian")
    else:
        await post(
            client, settings, "/verdicts", verdict(event, revision=1, status=change), "guardian"
        )
    current = engine.snapshot()
    assert current["sensors"]["first"]["value"] is None
    assert current["version"] > original["version"]
    with app.state.database.transaction() as session:
        historical = session.get(CitySnapshot, original["version"])
        assert historical.payload["sensors"]["first"]["value"] == 2


@pytest.mark.parametrize(
    "changes",
    [
        {"unit": "ppm"},
        {"sensor_type": "smoke"},
        {"attributes": {"zone_id": "other"}},
    ],
)
async def test_registry_rejects_mismatched_reading(pipeline, changes):
    app, client, settings = pipeline
    register(app)
    event = reading().model_copy(
        update={
            "sensor_id": "first",
            "sensor_type": "temperature",
            "unit": "degC",
            **changes,
        }
    )
    assert (await post(client, settings, "/readings", event, "twin")).status_code == 422
