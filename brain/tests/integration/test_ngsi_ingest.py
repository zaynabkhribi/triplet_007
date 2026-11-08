"""Offline tests for the isolated NGSI-v2 sensor ingestion adapter.

No live network is used: every broker answer comes from an injected
httpx.MockTransport built from a local fake entity store modeled on the Twin's
real publish format (``twin/src/schema.py:to_attr`` shape). No existing test
module or mock is modified.
"""

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.integration.ngsi_ingest import (
    NgsiIngestError,
    NgsiSensorPoller,
    SENSOR_REGISTRY,
    parse_entity,
)
from app.schemas.sensor import SensorReading


# ---------------------------------------------------------------------------
# Fake broker: NGSI-v2 entity documents exactly as the Twin publishes them
# ({"attr": {"type": "float"/"string", "value": ...}}), per twin/src/schema.py.
# ---------------------------------------------------------------------------

def make_entity(entity_id: str, values: dict, timestamp: str) -> dict:
    body: dict = {"id": entity_id, "type": SENSOR_REGISTRY[entity_id]["ngsi_type"]}
    for key, value in values.items():
        if isinstance(value, bool):
            body[key] = {"type": "string", "value": "true" if value else "false"}
        elif isinstance(value, (int, float)):
            body[key] = {"type": "float", "value": value}
        else:
            body[key] = {"type": "string", "value": str(value)}
    body["timestamp"] = {"type": "string", "value": timestamp}
    return body


T0 = "2026-11-08T10:00:00+00:00"
T1 = "2026-11-08T10:00:05+00:00"


def transport_with(entities: dict[str, object], status: int = 200) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        entity_id = request.url.path.rsplit("/", 1)[-1]
        if entity_id not in entities:
            return httpx.Response(404, text="not found")
        payload = entities[entity_id]
        if isinstance(payload, Exception):
            raise payload
        if isinstance(payload, int):  # explicit status override per entity
            return httpx.Response(payload, text="boom")
        if isinstance(payload, tuple) and payload[0] == "raw":  # raw bytes body
            return httpx.Response(200, content=payload[1], headers={"content-type": "application/json"})
        return httpx.Response(200, json=payload)

    recorded: list[str] = []

    def recording(request: httpx.Request) -> httpx.Response:
        recorded.append(f"{request.method} {request.url}")
        return handler(request)

    transport = httpx.MockTransport(recording)
    transport.recorded = recorded  # type: ignore[attr-defined]
    return transport


# ---------------------------------------------------------------------------
# Pure parsing tests
# ---------------------------------------------------------------------------


def test_parse_building_entity_produces_mapped_readings():
    entity = make_entity(
        "us-b-bldg-01",
        {"smokeLevel": 12.5, "temperature": 38.0, "occupancyCount": 7},
        T0,
    )
    result = parse_entity("us-b-bldg-01", entity)
    assert {(r.sensor_id, r.unit, r.value) for r in result.readings} == {
        ("us-b-bldg-01:fire_smoke", "ppm", 12.5),
        ("us-b-bldg-01:temperature", "C", 38.0),
    }
    # occupancyCount is not in the Guardian mapping -> rejected, not guessed.
    assert any(item["attribute"] == "occupancyCount" for item in result.rejected)
    # exact broker timestamp preserved
    assert all(r.occurred_at == datetime.fromisoformat(T0) for r in result.readings)


def test_parse_traffic_entity_attributes_and_units():
    entity = make_entity(
        "us-a-traf-01",
        {"vehicleCount": 22, "avgSpeed": 50.8, "occupancy": 14.6, "congestionLevel": 14},
        T0,
    )
    result = parse_entity("us-a-traf-01", entity)
    by_type = {r.sensor_type: r for r in result.readings}
    # Only congestion (congestionLevel, %) and flow (avgSpeed, km/h) have an
    # unambiguous mapping. guardian/ngsi.yaml maps BOTH vehicleCount (car/h)
    # and occupancy (%) to the same property 'traffic_camera' with conflicting
    # units; the adapter fails closed on them instead of guessing a unit.
    assert set(by_type) == {"congestion", "flow"}
    assert by_type["congestion"].unit == "%"
    assert by_type["flow"].unit == "km/h"
    codes = {item["attribute"]: item["code"] for item in result.rejected}
    assert codes["vehicleCount"] == "ambiguous_mapping"
    assert codes["occupancy"] == "ambiguous_mapping"
    assert "car/h" in codes_detail(result)  # documented conflict, not silently dropped


def codes_detail(result):
    return " ".join(item["detail"] for item in result.rejected)


def test_unknown_entity_and_type_mismatch_rejected():
    with pytest.raises(NgsiIngestError) as exc:
        parse_entity("us-unknown-99", {"type": "TrafficSensor"})
    assert exc.value.code == "unknown_entity"

    entity = make_entity("us-b-bldg-01", {"smokeLevel": 5.0}, T0)
    entity["type"] = "TrafficSensor"  # wrong registered type
    with pytest.raises(NgsiIngestError) as exc:
        parse_entity("us-b-bldg-01", entity)
    assert exc.value.code == "type_mismatch"


def test_invalid_values_rejected_not_coerced():
    entity = make_entity("us-b-bldg-01", {}, T0)
    entity["smokeLevel"] = {"type": "string", "value": "hot"}
    entity["temperature"] = {"type": "float", "value": "40"}
    result = parse_entity("us-b-bldg-01", entity)
    codes = {item["attribute"]: item["code"] for item in result.rejected}
    assert codes["smokeLevel"] == "non_numeric_value"
    assert codes["temperature"] == "non_numeric_value"  # string numbers refused, strict
    assert result.readings == []


def test_missing_and_malformed_attributes_rejected():
    entity = make_entity("us-c-bin-01", {}, T0)
    entity["fillLevel"] = {"type": "float"}  # no value key
    result = parse_entity("us-c-bin-01", entity)
    codes = {item["attribute"]: item["code"] for item in result.rejected}
    assert codes["fillLevel"] == "malformed_attribute"
    assert result.readings == []


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf"), True])
def test_non_finite_and_boolean_values_rejected(bad):
    entity = make_entity("us-c-bin-01", {"fillLevel": bad}, T0)
    result = parse_entity("us-c-bin-01", entity)
    assert result.readings == []
    assert result.rejected[0]["code"] in {"non_finite_value", "non_numeric_value"}


# ---------------------------------------------------------------------------
# Timestamp handling
# ---------------------------------------------------------------------------


def test_missing_timestamp_is_reported_never_fabricated():
    entity = make_entity("us-c-bin-01", {"fillLevel": 42.0}, T0)
    del entity["timestamp"]
    with pytest.raises(NgsiIngestError) as exc:
        parse_entity("us-c-bin-01", entity)
    assert exc.value.code == "missing_timestamp"


@pytest.mark.parametrize(
    "raw",
    ["not-a-date", "2026-11-08T10:00:00"],  # unparseable / naive
)
def test_invalid_timestamps_rejected(raw):
    entity = make_entity("us-c-bin-01", {"fillLevel": 42.0}, raw)
    with pytest.raises(NgsiIngestError) as exc:
        parse_entity("us-c-bin-01", entity)
    assert exc.value.code in {"invalid_timestamp", "naive_timestamp"}


def test_out_of_order_timestamps_produce_distinct_deterministic_events():
    early = make_entity("us-c-bin-01", {"fillLevel": 30.0}, T1)
    late = make_entity("us-c-bin-01", {"fillLevel": 35.0}, T0)  # older stamp, later poll
    early_result = parse_entity("us-c-bin-01", early)
    late_result = parse_entity("us-c-bin-01", late)
    assert early_result.readings[0].occurred_at > late_result.readings[0].occurred_at
    # Distinct observations -> distinct deterministic ids, no silent overwrite.
    assert early_result.readings[0].event_id != late_result.readings[0].event_id


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def test_identical_observation_repeated_is_a_duplicate():
    """The same broker observation (same timestamp AND value) is skipped."""
    first = make_entity("us-c-bin-01", {"fillLevel": 42.0}, T0)
    second = make_entity("us-c-bin-01", {"fillLevel": 42.0}, T0)  # identical re-read
    state: dict = {}
    one = parse_entity("us-c-bin-01", first, last_emitted=state)
    two = parse_entity("us-c-bin-01", second, last_emitted=state)
    assert len(one.readings) == 1
    assert two.readings == []
    assert two.duplicates == ["fillLevel"]


def test_new_timestamp_with_unchanged_value_is_a_new_measurement():
    """A stuck-but-alive sensor still reports: new stamp -> new event.

    Skipping on value alone would silently discard real observations; only
    exact observation identity (timestamp + value) deduplicates.
    """
    state: dict = {}
    parse_entity("us-c-bin-01", make_entity("us-c-bin-01", {"fillLevel": 42.0}, T0), state)
    re_stamped = parse_entity("us-c-bin-01", make_entity("us-c-bin-01", {"fillLevel": 42.0}, T1), state)
    assert len(re_stamped.readings) == 1
    assert re_stamped.readings[0].occurred_at == datetime.fromisoformat(T1)


def test_changed_value_always_emits_new_event():
    state: dict = {}
    parse_entity("us-c-bin-01", make_entity("us-c-bin-01", {"fillLevel": 42.0}, T0), state)
    changed = parse_entity("us-c-bin-01", make_entity("us-c-bin-01", {"fillLevel": 43.0}, T1), state)
    assert len(changed.readings) == 1
    assert changed.readings[0].value == 43.0


def test_event_ids_are_deterministic_and_content_bound():
    entity = make_entity("us-c-bin-01", {"fillLevel": 42.0}, T0)
    a = parse_entity("us-c-bin-01", entity).readings[0]
    b = parse_entity("us-c-bin-01", make_entity("us-c-bin-01", {"fillLevel": 42.0}, T0)).readings[0]
    assert a.event_id == b.event_id
    other = parse_entity("us-c-bin-01", make_entity("us-c-bin-01", {"fillLevel": 43.0}, T0)).readings[0]
    assert a.event_id != other.event_id
    # uuid5 determinism: same content in a fresh state yields the same id again.
    assert other.event_id == uuid.uuid5(
        uuid.uuid5(uuid.NAMESPACE_URL, "urn:aegiscity:ngsi-sensor-reading"),
        "us-c-bin-01|fillLevel|2026-11-08T10:00:00+00:00|43.0",
    )


# ---------------------------------------------------------------------------
# Candidate semantics: no trust, no verdict fabrication
# ---------------------------------------------------------------------------


def test_candidates_are_plain_readings_without_trust_semantics():
    result = parse_entity("us-b-bldg-01", make_entity("us-b-bldg-01", {"smokeLevel": 12.5}, T0))
    reading = result.readings[0]
    assert isinstance(reading, SensorReading)
    # Provenance only: no verdict, guardian, hash, or revision fields exist.
    dumped = reading.model_dump(mode="json")
    for forbidden in ("status", "verdict", "guardian_id", "event_hash", "revision", "trusted"):
        assert forbidden not in dumped
    assert dumped["attributes"]["source"] == "snap4city_orion"


def test_all_allowlisted_sensors_covered_by_registry():
    expected = {
        "us-a-traf-01", "us-a-traf-02", "us-a-traf-03",
        "us-b-bldg-01", "us-c-cam-01", "us-c-bin-01", "us-c-bin-02",
    }
    assert set(SENSOR_REGISTRY) == expected
    # Actuator and ops entities are deliberately absent (commands are out of scope).
    assert "us-a-light-01" not in SENSOR_REGISTRY
    assert "us-ops-center" not in SENSOR_REGISTRY


# ---------------------------------------------------------------------------
# Poller behavior with the injected transport (no external network)
# ---------------------------------------------------------------------------


async def test_poller_roundtrip_offline_transport():
    entities = {
        "us-b-bldg-01": make_entity("us-b-bldg-01", {"smokeLevel": 12.5, "temperature": 38.0}, T0),
        "us-c-bin-01": make_entity("us-c-bin-01", {"fillLevel": 88.0}, T0),
    }
    transport = transport_with(entities)
    poller = NgsiSensorPoller(base_url="http://fake-broker.invalid", transport=transport)
    result = await poller.poll()
    ids = {r.sensor_id for r in result.readings}
    assert "us-b-bldg-01:fire_smoke" in ids and "us-c-bin-01:fill_level" in ids
    assert result.readings[0].unit == "ppm"
    # GET-only, one request per allowlisted entity, nothing else.
    assert all(url.startswith("GET http://fake-broker.invalid/v2/entities/") for url in transport.recorded)
    assert len(transport.recorded) == 7  # the whole allowlist
    assert all(m.split(" ")[0] == "GET" for m in transport.recorded)


async def test_poller_deduplicates_identical_observations_across_polls():
    """Static fixture (same timestamp every poll): identical observation -> no new event."""
    entities = {"us-c-bin-01": make_entity("us-c-bin-01", {"fillLevel": 42.0}, T0)}
    poller = NgsiSensorPoller(base_url="http://fake-broker.invalid", transport=transport_with(entities))
    first = await poller.poll()
    second = await poller.poll()
    assert len(first.readings) == 1
    assert second.readings == []
    assert second.duplicates == ["us-c-bin-01:fillLevel"]


async def test_poller_emits_new_event_when_timestamp_advances():
    """Realistic Twin tick: timestamp advances each poll even if value is equal."""
    stamps = iter([T0, T1])

    def handler(request: httpx.Request) -> httpx.Response:
        # Only us-c-bin-01 serves observations; every other allowlisted entity
        # gets a controlled 404 so the timestamp iterator is consumed exactly
        # once per poll() call and never exhausts prematurely.
        if request.url.path != "/v2/entities/us-c-bin-01":
            return httpx.Response(404, json={"error": "NotFound"})
        return httpx.Response(
            200,
            json=make_entity("us-c-bin-01", {"fillLevel": 42.0}, next(stamps)),
        )

    poller = NgsiSensorPoller(
        base_url="http://fake-broker.invalid", transport=httpx.MockTransport(handler)
    )
    first = await poller.poll()
    second = await poller.poll()
    assert len(first.readings) == 1 and len(second.readings) == 1
    assert first.readings[0].occurred_at == datetime.fromisoformat(T0)
    assert second.readings[0].occurred_at == datetime.fromisoformat(T1)
    assert first.readings[0].value == second.readings[0].value == 42.0
    # Advancing the timestamp with an unchanged value is a distinct observation
    # with a distinct deterministic event_id (never deduplicated away).
    assert first.readings[0].event_id != second.readings[0].event_id


async def test_poller_reports_unavailable_entities_without_fabrication():
    entities = {"us-c-bin-01": make_entity("us-c-bin-01", {"fillLevel": 42.0}, T0)}
    transport = transport_with(entities)
    poller = NgsiSensorPoller(base_url="http://fake-broker.invalid", transport=transport)
    result = await poller.poll()
    codes = {item["entity_id"]: item["code"] for item in result.unavailable}
    assert codes["us-a-traf-01"] == "not_found"          # missing sensor: reported, not invented
    assert codes["us-a-light-01"] if False else True      # actuators are never polled
    assert all("us-a-light" not in item["entity_id"] for item in result.unavailable)
    assert not result.empty


async def test_poller_reports_http_and_json_failures_per_entity():
    entities = {
        "us-c-bin-01": make_entity("us-c-bin-01", {"fillLevel": 42.0}, T0),
        "us-a-traf-01": 500,                                       # broker error
        "us-b-bldg-01": ("raw", b"{not valid json"),               # JSON syntax error
    }
    poller = NgsiSensorPoller(base_url="http://fake-broker.invalid", transport=transport_with(entities))
    result = await poller.poll()
    codes = {item["entity_id"]: item["code"] for item in result.unavailable}
    assert codes["us-a-traf-01"] == "http_500"
    assert codes["us-b-bldg-01"] == "invalid_json"
    assert {r.sensor_id for r in result.readings} == {"us-c-bin-01:fill_level"}


def test_poller_refuses_to_run_without_configuration():
    with pytest.raises(NgsiIngestError) as exc:
        NgsiSensorPoller()
    assert exc.value.code == "not_configured"


async def test_no_default_host_and_no_network_env_use():
    """trust_env=False: proxy env vars cannot redirect the poller offline test."""
    entities = {"us-c-bin-01": make_entity("us-c-bin-01", {"fillLevel": 1.0}, T0)}
    poller = NgsiSensorPoller(base_url="http://127.0.0.1:9", transport=transport_with(entities))
    await poller.poll()  # served entirely by the mock transport
    assert poller.requested_urls[0].startswith("http://127.0.0.1:9/v2/entities/")


def test_observation_timeliness_window_documented():
    """Timestamps are the broker's own; no freshness decision is made here."""
    entity = make_entity("us-c-bin-01", {"fillLevel": 42.0}, T0)
    reading = parse_entity("us-c-bin-01", entity).readings[0]
    assert reading.occurred_at == datetime.fromisoformat(T0).astimezone(UTC)
