"""Offline tests for Guardian verification-only compatibility (Tasks 7.3C-1/-2A).

All interactions use injected httpx transports; no live calls are made. These
tests prove binding of REAL-SHAPED Guardian verdict rows (vocabulary from
guardian/ngsi.yaml and guardian/ngsi.py::zone_for: zones ZONE-A/B/C, property
names like fire_smoke, unit spellings like "C") to Brain observations WITHOUT
granting trust — no GuardianVerdict is emitted anywhere in this module.
"""

import asyncio
import hashlib
import json

import httpx
import pytest

from app.core.config import Settings
from app.integration.guardian_compat import (
    GuardianCompatError,
    GuardianVerifier,
    evidence_body,
    evidence_digest,
    match_row_to_reading,
    verification_summary,
)
from app.integration.ngsi_twin import (
    NgsiTwinIngestWorker,
    NgsiTwinPoller,
    PollError,
    TwinDeviceMap,
)
from app.main import create_app
from app.security.event_hash import event_hash
from tests.integration.test_ngsi_twin import (
    broken_transport,
    building_entity,
    fresh_stamp,
    transport_with,
)

GUARDIAN_ZONE = "ZONE-B"  # Guardian's literal (ngsi.py ZONE_NAMES)
BRAIN_ZONE = "B"  # Brain's internal zone (ngsi_twin.py zone_id derivation)
TRAFFIC_ENTITY = "us-a-traf-01"
BIN_ENTITY = "us-c-bin-01"


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
                    "guardian_zone": GUARDIAN_ZONE,
                    "guardian_property": "fire_smoke",
                    "guardian_unit": "ppm",
                },
                {
                    "entity_id": "us-b-bldg-01",
                    "ngsi_type": "BuildingSensor",
                    "attribute": "temperature",
                    "sensor_id": "us-b-bldg-01:temperature",
                    "measurement": "temperature",
                    "unit": "degC",
                    "guardian_zone": GUARDIAN_ZONE,
                    "guardian_property": "temperature",
                    "guardian_unit": "C",  # Guardian's spelling, mapped explicitly
                },
                {
                    "entity_id": TRAFFIC_ENTITY,
                    "ngsi_type": "TrafficSensor",
                    "attribute": "congestionLevel",
                    "sensor_id": "us-a-traf-01:congestion",
                    "measurement": "traffic_congestion",
                    "unit": "%",
                    "guardian_zone": "ZONE-A",
                    "guardian_property": "congestion",
                    "guardian_unit": "%",
                },
            ],
        }
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
    guardian_zone: ZONE-B
    guardian_property: fire_smoke
    guardian_unit: ppm
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
        guardian_base_url="https://guardian",
        guardian_integration_token="token-123",
    )


def poller(settings, transport, mapping):
    return NgsiTwinPoller(settings, mapping, transport=transport)


def by_entity(mapping) -> dict:
    """Entity-keyed mapping index, exactly as GuardianVerifier builds it."""
    return {(m.entity_id, m.attribute): m for m in mapping.sensors}


def guardian_frame(
    sensor_id: str = "us-b-bldg-01",
    zone: str = GUARDIAN_ZONE,
    property_name: str = "fire_smoke",
    value: float = 2.2,
    unit: str = "ppm",
    stamp: str | None = None,
    digest_over: dict | None = None,
) -> dict:
    """Row exactly as Guardian's /v1/integration/verdicts emits it (api.py:325-338)."""
    body = digest_over or evidence_body(sensor_id, zone, property_name, stamp, value, unit)
    return {
        "reading_id": f"{sensor_id}:{property_name}:{stamp}",
        "sensor_id": sensor_id,
        "zone": zone,
        "observed_property": property_name,
        "phenomenon_time": stamp,
        "value": value,
        "unit": unit,
        "evidence_digest": evidence_digest(body),
        "disposition": "TRUSTED",
        "trust": 0.9,
        "reason_codes": [],
        "policy_version": "v1.0",
    }


def test_evidence_digest_matches_guardian_canonicalization():
    body = evidence_body(
        "us-b-bldg-01", "ZONE-B", "fire_smoke", "2026-01-01T00:00:00+00:00", 2.2, "ppm"
    )
    expected = "sha256:" + hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert evidence_digest(body) == expected


async def _poll_readings(settings, mapping, stamp=None):
    poll = poller(settings, transport_with({"us-b-bldg-01": building_entity(stamp=stamp)}), mapping)
    readings, _ = await poll.poll()
    return readings


async def test_matching_smoke_row_binds_to_observation(settings, mapping):
    stamp = fresh_stamp()
    readings = await _poll_readings(settings, mapping, stamp=stamp)
    smoke = next(r for r in readings if r.attributes["attribute"] == "smokeLevel")
    row = guardian_frame(stamp=stamp)
    verified = match_row_to_reading(row, by_entity(mapping), {(smoke.sensor_id, stamp): smoke})
    assert verified is not None
    assert verified.event_id == str(smoke.event_id)
    assert verified.brain_event_hash == event_hash(smoke)
    assert verified.guardian_digest == row["evidence_digest"]
    # Brain's internal zone stays its own vocabulary, distinct from Guardian's.
    assert smoke.attributes["zone_id"] == BRAIN_ZONE
    assert row["zone"] == GUARDIAN_ZONE


async def test_temperature_matches_with_mapped_unit_labels(settings, mapping):
    stamp = fresh_stamp()
    readings = await _poll_readings(settings, mapping, stamp=stamp)
    temp = next(r for r in readings if r.attributes["attribute"] == "temperature")
    assert temp.unit == "degC"  # Brain-side unit untouched
    row = guardian_frame(property_name="temperature", value=21.7, unit="C", stamp=stamp)
    verified = match_row_to_reading(row, by_entity(mapping), {(temp.sensor_id, stamp): temp})
    assert verified is not None  # Guardian "C" vs Brain "degC" — explicit mapping


async def test_wrong_guardian_zone_rejected(settings, mapping):
    stamp = fresh_stamp()
    readings = await _poll_readings(settings, mapping, stamp=stamp)
    smoke = next(r for r in readings if r.attributes["attribute"] == "smokeLevel")
    row = guardian_frame(zone="ZONE-C", stamp=stamp)
    assert match_row_to_reading(row, by_entity(mapping), {(smoke.sensor_id, stamp): smoke}) is None


async def test_wrong_property_rejected(settings, mapping):
    stamp = fresh_stamp()
    readings = await _poll_readings(settings, mapping, stamp=stamp)
    smoke = next(r for r in readings if r.attributes["attribute"] == "smokeLevel")
    row = guardian_frame(property_name="air_quality", stamp=stamp)
    assert match_row_to_reading(row, by_entity(mapping), {(smoke.sensor_id, stamp): smoke}) is None


async def test_wrong_guardian_unit_rejected(settings, mapping):
    stamp = fresh_stamp()
    readings = await _poll_readings(settings, mapping, stamp=stamp)
    smoke = next(r for r in readings if r.attributes["attribute"] == "smokeLevel")
    row = guardian_frame(unit="mg/m3", stamp=stamp)
    assert match_row_to_reading(row, by_entity(mapping), {(smoke.sensor_id, stamp): smoke}) is None


async def test_wrong_value_rejected(settings, mapping):
    stamp = fresh_stamp()
    readings = await _poll_readings(settings, mapping, stamp=stamp)
    smoke = next(r for r in readings if r.attributes["attribute"] == "smokeLevel")
    row = guardian_frame(value=99.9, stamp=stamp)
    assert match_row_to_reading(row, by_entity(mapping), {(smoke.sensor_id, stamp): smoke}) is None


async def test_wrong_timestamp_rejected(settings, mapping):
    stamp = fresh_stamp()
    readings = await _poll_readings(settings, mapping, stamp=stamp)
    smoke = next(r for r in readings if r.attributes["attribute"] == "smokeLevel")
    row = guardian_frame(stamp=fresh_stamp(-60))
    assert match_row_to_reading(row, by_entity(mapping), {(smoke.sensor_id, stamp): smoke}) is None


async def test_tampered_digest_rejected(settings, mapping):
    stamp = fresh_stamp()
    readings = await _poll_readings(settings, mapping, stamp=stamp)
    smoke = next(r for r in readings if r.attributes["attribute"] == "smokeLevel")
    row = guardian_frame(stamp=stamp)
    row["evidence_digest"] = "sha256:" + "0" * 64
    assert match_row_to_reading(row, by_entity(mapping), {(smoke.sensor_id, stamp): smoke}) is None


async def test_unknown_mapping_is_skipped(mapping):
    row = guardian_frame(sensor_id="us-x-unknown-99", stamp=fresh_stamp())
    assert match_row_to_reading(row, {}, {}) is None


def test_ambiguous_guardian_property_mapping_rejected():
    """vehicleCount and occupancy collapse to Guardian traffic_camera: invalid."""
    with pytest.raises(ValueError, match="ambiguous"):
        TwinDeviceMap.model_validate(
            {
                "version": 1,
                "sensors": [
                    {
                        "entity_id": TRAFFIC_ENTITY,
                        "ngsi_type": "TrafficSensor",
                        "attribute": "vehicleCount",
                        "sensor_id": "us-a-traf-01:vehicles",
                        "measurement": "traffic",
                        "unit": "car/h",
                        "guardian_property": "traffic_camera",
                    },
                    {
                        "entity_id": TRAFFIC_ENTITY,
                        "ngsi_type": "TrafficSensor",
                        "attribute": "occupancy",
                        "sensor_id": "us-a-traf-01:occupancy",
                        "measurement": "traffic",
                        "unit": "%",
                        "guardian_property": "traffic_camera",
                    },
                ],
            }
        )


async def test_event_identity_and_correlation_stable(settings, mapping):
    stamp = fresh_stamp()
    readings = await _poll_readings(settings, mapping, stamp=stamp)
    smoke = next(r for r in readings if r.attributes["attribute"] == "smokeLevel")
    again = await _poll_readings(settings, mapping, stamp=stamp)
    repeat = next(r for r in again if r.attributes["attribute"] == "smokeLevel")
    assert repeat.event_id == smoke.event_id
    assert repeat.correlation_id == smoke.correlation_id


def guardian_transport(status: int, body: dict) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("X-Integration-Token") == "token-123"
        return httpx.Response(status, json=body if isinstance(body, dict) else {})

    return httpx.MockTransport(handler)


def verifier(settings, transport, mapping) -> GuardianVerifier:
    return GuardianVerifier(settings, list(mapping.sensors), transport=transport)


async def test_unreachable_guardian_fails_closed(settings, mapping):
    transport = httpx.MockTransport(
        lambda request: (_ for _ in ()).throw(httpx.ConnectError("down", request=request))
    )
    v = verifier(settings, transport, mapping)
    with pytest.raises(GuardianCompatError):
        await v.fetch_rows()


async def test_unauthenticated_guardian_fails_closed(settings, mapping):
    v = verifier(settings, guardian_transport(401, {}), mapping)
    with pytest.raises(GuardianCompatError):
        await v.fetch_rows()


async def test_https_enforced(settings):
    plain = settings.model_copy(
        update={"guardian_base_url": "http://guardian", "guardian_integration_token": "token-123"}
    )
    v = GuardianVerifier(plain, [])
    with pytest.raises(GuardianCompatError, match="HTTPS"):
        async with httpx.AsyncClient() as client:
            await v.fetch_rows(client)


async def test_missing_token_fails_closed(settings):
    bare = settings.model_copy(update={"guardian_integration_token": None})
    v = GuardianVerifier(bare, [])
    with pytest.raises(GuardianCompatError, match="token"):
        async with httpx.AsyncClient() as client:
            await v.fetch_rows(client)


async def test_empty_rows_verify_to_nothing(settings, mapping):
    v = verifier(settings, guardian_transport(200, {"verdicts": []}), mapping)
    rows = await v.fetch_rows()
    assert await v.verify_against(rows, []) == []


async def test_verification_never_grants_trust(settings, mapping):
    """The summary proves binding but records zero granted trust."""
    stamp = fresh_stamp()
    readings = await _poll_readings(settings, mapping, stamp=stamp)
    rows = [guardian_frame(stamp=stamp)]
    verified = await verifier(
        settings, guardian_transport(200, {"verdicts": rows}), mapping
    ).verify_against(rows, readings)
    summary = verification_summary(verified)
    assert summary["mode"] == "verification_only"
    assert summary["trusted_granted"] == 0
    assert len(summary["observations"]) == 1


async def test_worker_disabled_requires_explicit_flag(tmp_path):
    minimal = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'events.db'}",
        brain_api_key="b" * 48,
        twin_api_key="t" * 48,
        guardian_api_key="g" * 48,
        brain_base_url="http://brain",
    )
    with pytest.raises(PollError):
        NgsiTwinIngestWorker.from_settings(minimal, database=None)


async def test_worker_cycle_posts_and_survives_failure(settings, mapping):
    worker = NgsiTwinIngestWorker(
        poller(settings, transport_with({"us-b-bldg-01": building_entity()}), mapping),
        "http://brain",
        settings.twin_api_key.get_secret_value(),
        database=None,
        poll_seconds=0.05,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        worker.transport = httpx.ASGITransport(app)
        worker.brain_base_url = "http://brain"
        result = await worker.cycle()
        assert result["posted"] == 2
        # Failure cycle: cycle() propagates PollError (fail-closed); the
        # background _loop() is the component that absorbs it and records
        # last_error, so the worker survives broker outages.
        worker.poller.transport = broken_transport()
        with pytest.raises(PollError):
            await worker.cycle()
        worker.start()
        for _ in range(100):
            if worker.last_error is not None:
                break
            await asyncio.sleep(0.05)
        assert worker.last_error is not None
        await worker.stop()
        assert worker._task is None


async def test_worker_start_stop_lifecycle(settings, mapping):
    worker = NgsiTwinIngestWorker(
        poller(settings, transport_with({}, status_codes={"us-b-bldg-01": 503}), mapping),
        "http://brain",
        settings.twin_api_key.get_secret_value(),
        database=None,
        poll_seconds=0.05,
        transport=httpx.MockTransport(lambda request: httpx.Response(404, text="x")),
    )
    worker.start()
    assert worker._task is not None and not worker._task.done()
    await worker.stop()
    assert worker._task is None
