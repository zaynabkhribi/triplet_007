"""Tests for GET /describe — the dynamic capability card (Interop core, plan §7.1)."""
from guardian.schemas import validate

REQUIRED_SENSORS = {"water_level", "air_quality", "power_load", "traffic_camera", "emergency_call"}
EXPECTED_DISPOSITIONS = {"TRUSTED", "SUSPECT", "MALICIOUS", "RESTRICT"}


def test_describe_shape_and_contract(client):
    r = client.get("/describe")
    assert r.status_code == 200
    body = r.json()

    assert body["layer"] == "guardian"
    assert body["protocol"] == "rest+json"
    assert body["policy_version"] == "v1.0"
    # 10s contractual floor advertised
    assert float(body["max_latency_s"]) == 10.0

    # capability card itself validates against the shared describe schema
    ok, errors = validate(body, "describe")
    assert ok, [e.message for e in errors]


def test_describe_covers_required_sensors(client):
    body = client.get("/describe").json()
    accepted = set(body["accepts_sensor_types"])
    assert REQUIRED_SENSORS.issubset(accepted), REQUIRED_SENSORS - accepted


def test_describe_emits_canonical_dispositions(client):
    body = client.get("/describe").json()
    assert set(body["emits_dispositions"]) == EXPECTED_DISPOSITIONS


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["layer"] == "guardian"
    assert body["policy_version"] == "v1.0"
