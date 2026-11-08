"""Triplet ingest: NGSI v2 -> Guardian readings -> verdict, end to end.

These tests pin the behaviour the *other two teams'* Test Book asserts, using
their scenario ids and their pass criteria, so a jury can see the Guardian
answer the triplet's own g1/b1/a1 questions rather than a city of our own
invention.

The mapping under test is `ngsi.yaml`; the profiles are `sensor_profiles.yaml`;
the physics is `detectors.py`. If any of the three drifts, one of these fails.
"""
from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from guardian.api import create_app
from guardian.config import load_settings
from guardian.ngsi import NgsiMapping, to_readings, zone_for

GUARDIAN = Path(__file__).resolve().parents[1]
TWIN_CONFIG = GUARDIAN.parent / "twin" / "config.json"


@pytest.fixture()
def mapping():
    return NgsiMapping.load()


@pytest.fixture()
def ngsi_client(tmp_path):
    s = load_settings()
    s = dataclasses.replace(
        s, paths=dataclasses.replace(s.paths, audit_log=str(tmp_path / "ngsi.jsonl"))
    )
    return TestClient(create_app(s))


def _entity(**attrs):
    return {k: {"type": "float", "value": v} for k, v in attrs.items()}


def _stream(client, device, ngsi_type, kind, series, mapping, step=5):
    """Push `series` (list of attr dicts) oldest-first, then read /verdicts."""
    client.post("/v1/run/new", json={})
    now = datetime.now(timezone.utc)
    for i, attrs in enumerate(series):
        stamp = (now - timedelta(seconds=(len(series) - i) * step)).isoformat(timespec="seconds")
        entity = _entity(**attrs)
        entity["timestamp"] = {"type": "string", "value": stamp}
        for frame in to_readings(device, ngsi_type, entity, kind, mapping):
            resp = client.post("/v1/readings", json=frame)
            assert resp.status_code == 200, resp.text
    return client.get("/verdicts").json().get(device, {})


# --------------------------------------------------------------------------
# Mapping: the Twin's wire shape becomes a Guardian frame without loss.
# --------------------------------------------------------------------------
def test_zone_is_derived_from_the_twin_device_id():
    assert zone_for("us-a-traf-01") == "ZONE-A"
    assert zone_for("us-b-bldg-01") == "ZONE-B"
    assert zone_for("us-c-bin-02") == "ZONE-C"
    assert zone_for("us-ops-center") == "ZONE-UNMAPPED"


def test_one_entity_yields_one_frame_per_mapped_attribute(mapping):
    frames = to_readings(
        "us-b-bldg-01", "BuildingSensor",
        _entity(smokeLevel=400, temperature=22), "building", mapping)
    props = {f["observed_property"] for f in frames}
    assert props == {"fire_smoke", "temperature"}
    assert all(f["zone"] == "ZONE-B" for f in frames)


def test_unmapped_attribute_is_not_guessed(mapping):
    """A property the mapping does not know is dropped, never invented.

    Scoring an unknown attribute against a guessed profile would produce a
    confidently wrong verdict, which is worse than no verdict.
    """
    frames = to_readings(
        "us-b-bldg-01", "BuildingSensor",
        _entity(smokeLevel=400, mysteryReading=99), "building", mapping)
    assert [f["observed_property"] for f in frames] == ["fire_smoke"]


def test_frame_satisfies_the_reading_contract(mapping):
    from guardian.schemas import validate_or_raise

    frame = to_readings(
        "us-a-traf-01", "TrafficSensor",
        _entity(congestionLevel=88), "traffic", mapping)[0]
    validate_or_raise(frame, "reading")          # raises if the contract is broken
    assert isinstance(frame["provenance"]["seq"], int)


def test_sequence_is_stable_for_the_same_timestamp(mapping):
    entity = _entity(congestionLevel=88)
    entity["timestamp"] = {"type": "string", "value": "2026-11-04T21:20:07+00:00"}
    a = to_readings("us-a-traf-01", "TrafficSensor", entity, "traffic", mapping)
    b = to_readings("us-a-traf-01", "TrafficSensor", entity, "traffic", mapping)
    assert [f["provenance"]["seq"] for f in a] == [f["provenance"]["seq"] for f in b]


# --------------------------------------------------------------------------
# The triplet's own Test Book, answered by our engine.
# --------------------------------------------------------------------------
def test_g1_spoofed_smoke_is_untrusted(ngsi_client, mapping):
    """triplet_07 g1: smoke 400 ppm with a normal temperature -> UNTRUSTED.

    Pass criterion, verbatim from scenarios/g1.md: "Guardian verdict for
    us-b-bldg-01 is UNTRUSTED."
    """
    v = _stream(ngsi_client, "us-b-bldg-01", "BuildingSensor", "building",
                [{"smokeLevel": s, "temperature": 22} for s in (20, 60, 120, 200, 300, 400)],
                mapping)
    assert v["verdict"] == "UNTRUSTED", v
    assert v["disposition"] in {"SUSPECT", "RESTRICT", "MALICIOUS"}, v
    assert "CONFLICT" in v["reason"], v


def test_b1_real_fire_stays_trusted(ngsi_client, mapping):
    """triplet_07 b1: smoke AND heat rise together -> TRUSTED, so the Brain may act.

    This is the half that stops the Guardian from being a brick wall: if a real
    fire were refused, the Brain could never sound the alarm and the triplet's
    b1 scenario would fail.
    """
    v = _stream(ngsi_client, "us-b-bldg-01", "BuildingSensor", "building",
                [{"smokeLevel": sm, "temperature": tp}
                 for sm, tp in ((20, 24), (45, 30), (70, 42), (85, 55), (95, 66), (100, 70))],
                mapping)
    assert v["verdict"] == "TRUSTED", v
    assert v["disposition"] == "TRUSTED", v


def test_a1_traffic_jam_is_trusted(ngsi_client, mapping):
    """triplet_07 a1: roads 1 AND 2 jam together -> both TRUSTED.

    Pushing one sensor alone is not the scenario: a1 says "roads 1 and 2 start to
    jam". With both rising, the upward trend is corroborated across devices and
    DRIFT correctly does not fire. (A single device climbing while its
    neighbours stay flat is the S1 signature, and does flag.)
    """
    ngsi_client.post("/v1/run/new", json={})
    now = datetime.now(timezone.utc)
    series = (10, 30, 55, 70, 80, 88)
    for i, level in enumerate(series):
        stamp = (now - timedelta(seconds=(len(series) - i) * 5)).isoformat(timespec="seconds")
        for device in ("us-a-traf-01", "us-a-traf-02"):
            entity = _entity(congestionLevel=level)
            entity["timestamp"] = {"type": "string", "value": stamp}
            for frame in to_readings(device, "TrafficSensor", entity, "traffic", mapping):
                assert ngsi_client.post("/v1/readings", json=frame).status_code == 200
    body = ngsi_client.get("/verdicts").json()
    for device in ("us-a-traf-01", "us-a-traf-02"):
        assert body[device]["disposition"] == "TRUSTED", (device, body[device])


def test_c1_full_bin_is_trusted(ngsi_client, mapping):
    """triplet_07 c1: the bin fills; filling is the incident, not an attack."""
    c1 = _stream(ngsi_client, "us-c-bin-01", "WasteBin", "bin",
                 [{"fillLevel": f} for f in (40, 55, 70, 82, 90, 97)], mapping)
    assert c1["disposition"] == "TRUSTED", c1


def test_verdicts_endpoint_serves_the_twin_mock_shape(ngsi_client, mapping):
    """The Brain reads {device: {verdict, reason, checked}} — keep those three keys.

    They are the contract twin/mocks/mock_guardian.py publishes, so a Brain that
    already works against the mock works against us unchanged.
    """
    _stream(ngsi_client, "us-b-bldg-01", "BuildingSensor", "building",
            [{"smokeLevel": s, "temperature": 22} for s in (20, 60, 120, 200, 300, 400)],
            mapping)
    body = ngsi_client.get("/verdicts").json()
    assert "us-b-bldg-01" in body
    entry = body["us-b-bldg-01"]
    for key in ("verdict", "reason", "checked"):
        assert key in entry, f"missing {key} — the Twin's mock Brain reads it"
    assert entry["verdict"] in {"TRUSTED", "UNTRUSTED"}
    # and the evidence behind it, for a reviewer who wants to check
    assert entry["trust"] is not None
    assert entry["evidence_digest"].startswith("sha256:")


def test_verdict_is_per_property_not_per_device(ngsi_client, mapping):
    """A building sensor publishes two measures; they must not share a history.

    Regression: the rate and drift detectors compared ppm against degrees
    Celsius because the history window was keyed by device only. That produced
    a RATE_ANOMALY on every second frame of a perfectly ordinary fire.
    """
    v = _stream(ngsi_client, "us-b-bldg-01", "BuildingSensor", "building",
                [{"smokeLevel": sm, "temperature": tp}
                 for sm, tp in ((20, 24), (45, 30), (70, 42), (85, 55), (95, 66), (100, 70))],
                mapping)
    assert "RATE_ANOMALY" not in v["reason"], v


@pytest.mark.skipif(not TWIN_CONFIG.exists(), reason="triplet_07 twin/config.json not present")
def test_poll_accepts_the_twins_own_device_list(ngsi_client):
    """The device list is read from the Twin's config, not copied into our code."""
    body = json.loads(TWIN_CONFIG.read_text(encoding="utf-8"))
    resp = ngsi_client.post("/v1/ngsi/poll", json={
        "base_url": "http://127.0.0.1:9",     # deliberately unreachable
        "devices": body["devices"],
    })
    assert resp.status_code == 200, resp.text
    # Nothing readable, nothing invented: zero frames, and the only device rows
    # are OFFLINE COMM_LOSS — inventory honesty, never a fabricated verdict.
    assert resp.json()["frames"] == 0
    rows = resp.json()["verdicts"]
    assert rows, "mapped devices must still be inventories as OFFLINE"
    assert all(r["verdict"] == "OFFLINE" and r["reason"] == "COMM_LOSS" for r in rows.values()), rows
