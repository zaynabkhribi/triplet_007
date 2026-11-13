"""Offline tests for the Snap4City NGSI read-side ingestion adapter.

All transport interactions use injected httpx transports; no live network
calls are made. Guardian trust is fail-closed by construction: an observation
without a matching verdict stays untrusted (verified via the real pipeline).
"""

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select

from app.core.config import Settings
from app.database.models import SensorEvent
from app.integration.ngsi_twin import (
    NgsiTwinPoller,
    PollError,
    TwinDeviceMap,
    poll_and_post,
)
from app.main import create_app
from tests.integration.test_trust_pipeline import status
from tests.security.test_contracts import reading as _reading


def entity(
    values: dict, entity_type: str = "BuildingSensor", entity_id: str = "us-b-bldg-01"
) -> dict:
    return {
        "id": entity_id,
        "type": entity_type,
        **{
            k: {"type": "string" if isinstance(v, str) else "float", "value": v}
            for k, v in values.items()
        },
    }


def transport_with(entities: dict[str, dict], status_codes: dict[str, int] | None = None):
    codes = status_codes or {}

    def handler(request: httpx.Request) -> httpx.Response:
        entity_id = request.url.path.rsplit("/", 1)[-1]
        if entity_id in codes:
            return httpx.Response(codes[entity_id], text="boom")
        if entity_id not in entities:
            return httpx.Response(404, text="not found")
        return httpx.Response(200, json=entities[entity_id])

    return httpx.MockTransport(handler)


def broken_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    return httpx.MockTransport(handler)


@pytest.fixture
def mapping() -> TwinDeviceMap:
    return TwinDeviceMap.model_validate(
        {
            "version": 1,
            "sensors": [
                {
                    "entity_id": "us-b-bldg-01",
                    "ngsi_type": "BuildingSensor",
                    "attribute": "smokeLevel",
                    "sensor_id": "us-b-bldg-01:fire_smoke",
                    "measurement": "smoke",
                    "unit": "ppm",
                },
                {
                    "entity_id": "us-b-bldg-01",
                    "ngsi_type": "BuildingSensor",
                    "attribute": "temperature",
                    "sensor_id": "us-b-bldg-01:temperature",
                    "measurement": "temperature",
                    "unit": "degC",
                },
            ],
        }
    )


def fresh_stamp(offset_seconds: int = 0) -> str:
    """Timezone-aware, dynamic UTC stamp within the freshness window.

    Fixed absolute timestamps go stale as wall-clock advances (the freshness
    window is 300 s), so valid-observation fixtures must be relative to now.
    """
    moment = datetime.now(UTC) + timedelta(seconds=offset_seconds)
    return moment.isoformat()


def building_entity(
    smoke=2.2, temp=21.7, stamp=None, etype="BuildingSensor"
):
    return entity(
        {"smokeLevel": smoke, "temperature": temp, "timestamp": stamp or fresh_stamp()},
        entity_type=etype,
    )


@pytest.fixture
def settings(tmp_path):
    mapping_path = tmp_path / "devices.yaml"
    mapping_path.write_text(
        """
version: 1
sensors:
  - entity_id: us-b-bldg-01
    ngsi_type: BuildingSensor
    attribute: smokeLevel
    sensor_id: us-b-bldg-01:fire_smoke
    measurement: smoke
    unit: ppm
""",
        encoding="utf-8",
    )
    return Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'events.db'}",
        brain_api_key="b" * 48,
        twin_api_key="t" * 48,
        guardian_api_key="g" * 48,
        brain_base_url="http://brain",
        orion_base_url="http://orion",
        snap4city_ingest_enabled=True,
        snap4city_devices_file=str(mapping_path),
        worker_enabled=False,
    )


def poller(settings, transport, mapping):
    return NgsiTwinPoller(settings, mapping, transport=transport)


async def test_valid_observation_produces_reading(settings, mapping):
    stamp = fresh_stamp()
    p = poller(settings, transport_with({"us-b-bldg-01": building_entity(stamp=stamp)}), mapping)
    readings, stats = await p.poll()
    assert stats.emitted == 2 and not stats.errors
    smoke = next(r for r in readings if r.sensor_id.endswith(":fire_smoke"))
    assert smoke.value == 2.2 and smoke.unit == "ppm"
    assert smoke.attributes["entity_timestamp"] == stamp
    assert smoke.attributes["source"] == "snap4city"
    assert smoke.attributes["entity_id"] == "us-b-bldg-01"


async def test_deterministic_identity_and_duplicate_suppression(settings, mapping):
    transport = transport_with({"us-b-bldg-01": building_entity()})
    p = poller(settings, transport, mapping)
    first, _ = await p.poll()
    assert len(first) == 2
    assert len({r.event_id for r in first}) == 2
    # Unchanged entities are suppressed entirely: poll() returns no readings,
    # and each remapped attribute counts as one duplicate.
    again, stats = await p.poll()
    assert again == []
    assert stats.duplicates == 2
    assert stats.emitted == 0
    # Identities remain deterministic across polls (stable for restarts).
    fresh = poller(settings, transport, mapping)
    third, third_stats = await fresh.poll()
    by_sensor = {r.sensor_id: r for r in third}
    for original in first:
        repeat = by_sensor[original.sensor_id]
        assert repeat.event_id == original.event_id
        assert repeat.correlation_id == original.correlation_id
    assert third_stats.duplicates == 0  # new poller instance, so first sighting


async def test_value_change_with_new_timestamp_emits_new_event(settings, mapping):
    base = fresh_stamp(-30)
    p = poller(settings, transport_with({"us-b-bldg-01": building_entity(stamp=base)}), mapping)
    await p.poll()
    stamp2 = fresh_stamp(0)
    p.transport = transport_with({"us-b-bldg-01": building_entity(smoke=88.0, stamp=stamp2)})
    second, stats = await p.poll()
    assert stats.emitted == 2
    assert all(r.occurred_at.isoformat() == stamp2 for r in second)
    assert any(r.value == 88.0 for r in second)


async def test_invalid_entity_type_rejected(settings, mapping):
    p = poller(
        settings, transport_with({"us-b-bldg-01": building_entity(etype="Imposter")}), mapping
    )
    readings, stats = await p.poll()
    assert readings == [] and stats.skipped_invalid >= 1


async def test_unmapped_attribute_ignored(settings, mapping):
    p = poller(
        settings,
        transport_with({"us-b-bldg-01": building_entity() | {"hackerField": 1}}),
        mapping,
    )
    readings, _ = await p.poll()
    assert all("hackerField" not in r.attributes.values() for r in readings)
    assert all(r.attributes["attribute"] in {"smokeLevel", "temperature"} for r in readings)


async def test_missing_timestamp_rejected(settings, mapping):
    bad = entity({"smokeLevel": 2.2, "temperature": 21.7})  # no timestamp at all
    p = poller(settings, transport_with({"us-b-bldg-01": bad}), mapping)
    readings, stats = await p.poll()
    assert readings == [] and stats.skipped_invalid >= 1


async def test_stale_timestamp_rejected(settings, mapping):
    stale = building_entity(stamp="2020-01-01T00:00:00+00:00")
    p = poller(settings, transport_with({"us-b-bldg-01": stale}), mapping)
    readings, stats = await p.poll()
    assert readings == [] and stats.skipped_invalid >= 1


async def test_naive_timestamp_rejected(settings, mapping):
    naive = building_entity(stamp="2026-11-11T10:00:00")  # no timezone
    p = poller(settings, transport_with({"us-b-bldg-01": naive}), mapping)
    readings, _ = await p.poll()
    assert readings == []


async def test_future_timestamp_rejected(settings, mapping):
    future = building_entity(stamp=fresh_stamp(600))
    p = poller(settings, transport_with({"us-b-bldg-01": future}), mapping)
    readings, stats = await p.poll()
    assert readings == [] and stats.skipped_invalid >= 1


async def test_network_failure_raises_poll_error(settings, mapping):
    p = poller(settings, broken_transport(), mapping)
    with pytest.raises(PollError):
        await p.poll()


async def test_http_error_recorded_not_fatal_for_others(settings, mapping):
    p = poller(
        settings,
        transport_with({"us-b-bldg-01": building_entity()}, status_codes={"us-b-bldg-01": 503}),
        mapping,
    )
    readings, stats = await p.poll()
    assert readings == []
    assert any("503" in e for e in stats.errors)


async def test_non_json_response_rejected(settings, mapping):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="<html>oops</html>"))
    p = poller(settings, transport, mapping)
    readings, stats = await p.poll()
    assert readings == [] and stats.errors


async def test_disabled_by_configuration(tmp_path):
    minimal = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'events.db'}",
        brain_api_key="b" * 48,
        twin_api_key="t" * 48,
        guardian_api_key="g" * 48,
        brain_base_url="http://brain",
    )
    from app.integration.ngsi_twin import poller_from_settings

    with pytest.raises(PollError):
        poller_from_settings(minimal)


async def test_enabled_requires_orion_url_and_mapping(tmp_path):
    with pytest.raises(ValueError):
        Settings(
            _env_file=None,
            database_url=f"sqlite:///{tmp_path / 'events.db'}",
            brain_api_key="b" * 48,
            twin_api_key="t" * 48,
            guardian_api_key="g" * 48,
            brain_base_url="http://brain",
            snap4city_ingest_enabled=True,
        )


async def test_duplicate_poll_posts_through_pipeline_without_duplicates(settings, mapping):
    """End-to-end offline: poll → Brain ingest API → second poll is deduped."""
    app = create_app(settings)
    async with app.router.lifespan_context(app), httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="http://brain"
    ) as client:
        p = poller(settings, transport_with({"us-b-bldg-01": building_entity()}), mapping)
        result = await poll_and_post(p, client, settings.twin_api_key.get_secret_value())
        # Sibling attributes of one entity tick are independent observations
        # with distinct event identities: both must ingest as 202.
        assert result["posted"] == 2 and result["duplicates"] == 0
        with app.state.database.transaction() as session:
            stored = session.scalars(select(SensorEvent.sensor_id)).all()
            assert sorted(stored) == [
                "us-b-bldg-01:fire_smoke",
                "us-b-bldg-01:temperature",
            ]
        result2 = await poll_and_post(p, client, settings.twin_api_key.get_secret_value())
        # Unchanged entities are suppressed by the poller itself.
        assert result2["posted"] == 0
        assert result2["duplicates"] >= 2


async def test_no_guardian_verdict_leaves_observation_untrusted(settings, mapping):
    """Fail-closed: ingested real observations stay UNTRUSTED without verdicts."""
    app = create_app(settings)
    async with app.router.lifespan_context(app), httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="http://brain"
    ) as client:
        p = poller(settings, transport_with({"us-b-bldg-01": building_entity()}), mapping)
        await poll_and_post(p, client, settings.twin_api_key.get_secret_value())
        await app.state.processor.tick()
        with app.state.database.transaction() as session:
            event = session.scalars(
                select(SensorEvent).where(SensorEvent.sensor_id == "us-b-bldg-01:fire_smoke")
            ).first()
            assert event is not None
        from tests.integration.test_trust_pipeline import post

        probe = _reading()
        assert (
            await post(client, settings, "/readings", probe, "twin")
        ).status_code == 202
        await app.state.processor.tick()
        result = await status(client, settings, probe)
        assert result["state"] == "PENDING_VERDICT"  # no verdict was ingested
        # And the real observation likewise never leaves PENDING_VERDICT.
        from app.database.models import EventLifecycle

        with app.state.database.transaction() as session:
            life = session.get(EventLifecycle, event.id)
            assert life.state == "PENDING_VERDICT"


async def test_conflicting_value_under_same_identity_is_fatal(settings, mapping):
    """Same timestamp with a different value must not pass as a duplicate."""
    stamp = fresh_stamp()
    p = poller(settings, transport_with({"us-b-bldg-01": building_entity(stamp=stamp)}), mapping)
    first, _ = await p.poll()
    assert first
    conflicting = building_entity(smoke=88.0, stamp=stamp)
    p.transport = transport_with({"us-b-bldg-01": conflicting})
    with pytest.raises(PollError, match="conflicting value"):
        await p.poll()


async def test_no_actuator_dispatch_on_real_ingest(settings, mapping):
    """Real ingestion must never trigger actuator dispatch (flag stays False)."""
    assert settings.actuator_execution_enabled is False
    app = create_app(settings)
    async with app.router.lifespan_context(app), httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="http://brain"
    ) as client:
        p = poller(settings, transport_with({"us-b-bldg-01": building_entity()}), mapping)
        await poll_and_post(p, client, settings.twin_api_key.get_secret_value())
        assert await app.state.actuator_manager.tick() == 0
