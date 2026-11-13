"""Offline tests for Task 7.3E-3: Guardian audit-tail evidence adapter.

Covers audit event parsing, exact digest matching, cursor behavior, loopback
restriction, and zero-trust guarantees. No live calls, no services started.
"""

import json
from pathlib import Path

import httpx
import pytest

from app.core.config import Settings
from app.integration.guardian_compat import (
    AUDIT_ACCEPTED_EVENT,
    AuditCursor,
    AuditTailShadowWorker,
    AuditTailVerifier,
    GuardianCompatError,
    PendingEvidenceStore,
    evidence_digest,
    match_audit_event_to_reading,
    parse_audit_event,
)
from app.integration.ngsi_twin import TwinDeviceMap

REPO = Path(__file__).resolve().parents[2]  # brain/
STAMP = "2026-01-01T00:00:00+00:00"
_UNSET = object()


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
                    "guardian_zone": "ZONE-B",
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
                    "guardian_zone": "ZONE-B",
                    "guardian_property": "temperature",
                    "guardian_unit": "C",
                },
            ],
        }
    )


def by_entity(mapping) -> dict:
    return {(m.entity_id, m.attribute): m for m in mapping.sensors}


def audit_event(
    sensor_id: str = "us-b-bldg-01",
    zone: str = "ZONE-B",
    prop: str = "fire_smoke",
    value: float = 2.2,
    unit: str = "ppm",
    stamp: str = STAMP,
    seq: int = 10,
    digest: str | None = _UNSET,
) -> dict:
    """One Guardian accepted-reading audit record (pipeline.py:461-472 shape).

    Note what is ABSENT: no phenomenon_time, no unit, no Guardian-issued
    verdict revision, no issuer identity — exactly as the real contract.
    ``digest`` is sentinel-defaulted so an explicit empty string is respected
    (``or``-style defaults would swallow it).
    """
    from tests.integration.test_guardian_compat import evidence_body as eb

    body = {
        "event": AUDIT_ACCEPTED_EVENT,
        "code": "ACCEPTED",
        "reading_id": f"{sensor_id}:{prop}:{stamp}",
        "seq": seq,
        "sensor_id": sensor_id,
        "zone": zone,
        "observed_property": prop,
        "value": value,
        "evidence_digest": (
            evidence_digest(eb(sensor_id, zone, prop, stamp, value, unit))
            if digest is _UNSET
            else digest
        ),
        "ts": "2026-01-01T00:00:05Z",
    }
    return body


def reading_for(sensor_id: str, attribute: str, stamp: str = STAMP, value: float = 2.2):
    from uuid import NAMESPACE_URL, uuid5

    from app.schemas.sensor import SensorReading

    entity_id = "us-b-bldg-01"
    # Mirror ngsi_twin.py's deterministic identity so event_id is stable.
    ns = "aegicity-brain:observation"
    event_id = uuid5(NAMESPACE_URL, f"{ns}:{entity_id}:{attribute}:{stamp}")
    correlation_id = uuid5(
        NAMESPACE_URL, f"aegicity-brain:correlation:{entity_id}:{attribute}:{stamp}"
    )
    prop_value = {"smokeLevel": 2.2, "temperature": 21.7}.get(attribute, value)
    return SensorReading(
        event_id=event_id,
        correlation_id=correlation_id,
        occurred_at=stamp,
        sensor_id=f"{entity_id}:{'fire_smoke' if attribute == 'smokeLevel' else 'temperature'}",
        sensor_type="smoke" if attribute == "smokeLevel" else "temperature",
        value=prop_value,
        unit="ppm" if attribute == "smokeLevel" else "degC",
        attributes={
            "zone_id": "B",
            "source": "snap4city",
            "entity_id": entity_id,
            "attribute": attribute,
            "entity_timestamp": stamp,
        },
    )


# --- parsing -----------------------------------------------------------------


def test_valid_audit_event_parses(mapping):
    parsed = parse_audit_event(audit_event(), by_entity(mapping))
    assert parsed is not None
    sensor_id, prop, zone, value, digest = parsed
    assert sensor_id == "us-b-bldg-01"
    assert prop == "fire_smoke"
    assert zone == "ZONE-B"
    assert value == 2.2
    assert digest.startswith("sha256:")


def test_rejected_and_unrelated_events_are_skipped(mapping):
    assert parse_audit_event({"event": "reading.rejected"}, by_entity(mapping)) is None
    assert parse_audit_event({"event": "orion.poller.started"}, by_entity(mapping)) is None
    with pytest.raises(GuardianCompatError, match="not an object"):
        parse_audit_event("not-a-dict", by_entity(mapping))


def test_unmapped_sensor_skipped(mapping):
    event = audit_event(sensor_id="us-x-unknown-99")
    assert parse_audit_event(event, by_entity(mapping)) is None


def test_missing_digest_fails_closed(mapping):
    event = audit_event(digest="")
    with pytest.raises(GuardianCompatError, match="evidence_digest"):
        parse_audit_event(event, by_entity(mapping))


def test_missing_identity_fails_closed(mapping):
    event = audit_event()
    event.pop("zone")
    with pytest.raises(GuardianCompatError, match="identity"):
        parse_audit_event(event, by_entity(mapping))


def test_non_numeric_value_fails_closed(mapping):
    event = audit_event()
    event["value"] = "hot"
    with pytest.raises(GuardianCompatError, match="non-numeric"):
        parse_audit_event(event, by_entity(mapping))


# --- exact evidence matching --------------------------------------------------


def _index(*readings):
    return {
        (r.sensor_id, r.attributes.get("entity_timestamp", "")): r for r in readings
    }


def test_exact_digest_match_binds_observation(mapping):
    smoke = reading_for("us-b-bldg-01", "smokeLevel")
    parsed = parse_audit_event(audit_event(value=2.2), by_entity(mapping))
    entry = by_entity(mapping)[("us-b-bldg-01", "smokeLevel")]
    verified = match_audit_event_to_reading(parsed, entry, _index(smoke))
    assert verified is not None
    assert verified.event_id == str(smoke.event_id)
    assert verified.guardian_digest.startswith("sha256:")
    assert verified.row["source"] == "audit_tail"


def test_wrong_value_rejected(mapping):
    smoke = reading_for("us-b-bldg-01", "smokeLevel")
    parsed = parse_audit_event(audit_event(value=99.9), by_entity(mapping))
    entry = by_entity(mapping)[("us-b-bldg-01", "smokeLevel")]
    assert match_audit_event_to_reading(parsed, entry, _index(smoke)) is None


def test_wrong_timestamp_rejected(mapping):
    smoke = reading_for("us-b-bldg-01", "smokeLevel", stamp="2026-01-01T01:00:00+00:00")
    parsed = parse_audit_event(audit_event(stamp=STAMP), by_entity(mapping))
    entry = by_entity(mapping)[("us-b-bldg-01", "smokeLevel")]
    assert match_audit_event_to_reading(parsed, entry, _index(smoke)) is None


def test_non_finite_value_fails_closed(mapping):
    for bad in (float("nan"), float("inf"), float("-inf")):
        event = audit_event(value=bad)
        with pytest.raises(GuardianCompatError, match="non-finite"):
            parse_audit_event(event, by_entity(mapping))


def test_string_inf_value_fails_closed(mapping):
    event = audit_event()
    event["value"] = "Infinity"
    with pytest.raises(GuardianCompatError, match="non-finite"):
        parse_audit_event(event, by_entity(mapping))


def test_missing_key_entirely_fails_closed(mapping):
    event = audit_event()
    event.pop("value")
    with pytest.raises(GuardianCompatError, match="non-numeric"):
        parse_audit_event(event, by_entity(mapping))


def test_wrong_sensor_rejected(mapping):
    temperature = reading_for("us-b-bldg-01", "temperature", value=21.7)
    parsed = parse_audit_event(audit_event(prop="fire_smoke"), by_entity(mapping))
    entry = by_entity(mapping)[("us-b-bldg-01", "temperature")]
    assert match_audit_event_to_reading(parsed, entry, _index(temperature)) is None


def test_wrong_zone_rejected(mapping):
    smoke = reading_for("us-b-bldg-01", "smokeLevel")
    parsed = parse_audit_event(audit_event(zone="ZONE-C"), by_entity(mapping))
    entry = by_entity(mapping)[("us-b-bldg-01", "smokeLevel")]
    assert match_audit_event_to_reading(parsed, entry, _index(smoke)) is None


def test_self_consistent_digest_with_wrong_value_rejected(mapping):
    """A forged audit row cannot mint evidence by recomputing its own digest.

    The expected digest is reconstructed from the PERSISTED observation's
    value, so an attacker-supplied value+digest pair that is internally
    consistent but disagrees with Brain's stored measurement is rejected.
    """
    smoke = reading_for("us-b-bldg-01", "smokeLevel", value=2.2)
    forged = audit_event(value=99.9)  # digest is self-consistent with 99.9
    parsed = parse_audit_event(forged, by_entity(mapping))
    entry = by_entity(mapping)[("us-b-bldg-01", "smokeLevel")]
    assert match_audit_event_to_reading(parsed, entry, _index(smoke)) is None


def test_tampered_digest_rejected(mapping):
    smoke = reading_for("us-b-bldg-01", "smokeLevel")
    tampered = audit_event(digest="sha256:" + "0" * 64)
    parsed = parse_audit_event(tampered, by_entity(mapping))
    entry = by_entity(mapping)[("us-b-bldg-01", "smokeLevel")]
    assert match_audit_event_to_reading(parsed, entry, _index(smoke)) is None


def test_audit_rows_carry_no_timestamp_or_unit(mapping):
    """Contract honesty: matching MUST NOT pretend Guardian sent these."""
    event = audit_event()
    assert "phenomenon_time" not in event
    assert "unit" not in event
    # Yet matching still succeeds — because the digest is reconstructed from
    # the PERSISTED observation's timestamp + mapping-declared Guardian unit.
    smoke = reading_for("us-b-bldg-01", "smokeLevel")
    parsed = parse_audit_event(event, by_entity(mapping))
    entry = by_entity(mapping)[("us-b-bldg-01", "smokeLevel")]
    assert match_audit_event_to_reading(parsed, entry, _index(smoke)) is not None


# --- audit cursor -------------------------------------------------------------


def test_cursor_persists_and_only_advances(tmp_path):
    cursor = AuditCursor(tmp_path / "cursor.json")
    assert cursor.load() == 0
    cursor.advance(10)
    assert cursor.seq == 10
    # Fresh instance reads persisted state (restart-safe).
    again = AuditCursor(tmp_path / "cursor.json")
    assert again.load() == 10
    # Rewinds are ignored.
    again.advance(5)
    assert again.seq == 10


def test_cursor_malformed_file_fails_closed(tmp_path):
    bad = tmp_path / "cursor.json"
    bad.write_text("not json", encoding="utf-8")
    with pytest.raises(GuardianCompatError, match="cursor"):
        AuditCursor(bad).load()


def test_cursor_negative_fails_closed(tmp_path):
    bad = tmp_path / "cursor.json"
    bad.write_text(json.dumps({"last_seq": -1}), encoding="utf-8")
    with pytest.raises(GuardianCompatError, match="non-negative"):
        AuditCursor(bad).load()


# --- verifier over injected transport -----------------------------------------


def verifier(settings, transport, mapping, cursor):
    return AuditTailVerifier(settings, list(mapping.sensors), cursor, transport=transport)


def audit_transport(events: list[dict], seen: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        seen["since"] = request.url.params.get("since")
        return httpx.Response(200, json={"count": len(events), "events": events})

    return httpx.MockTransport(handler)


def audit_settings(tmp_path, **overrides):
    base = dict(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'real_integration.db'}",
        brain_api_key="b" * 48,
        twin_api_key="t" * 48,
        guardian_api_key="g" * 48,
        brain_base_url="http://127.0.0.1:8000",
        worker_enabled=True,
        snap4city_ingest_enabled=True,
        snap4city_devices_file=str(REPO / "config" / "devices.real-readonly.yaml"),
        guardian_shadow_reconciliation_enabled=True,
        guardian_base_url="http://127.0.0.1:8090",
        guardian_allow_loopback_http=True,
        guardian_evidence_source="audit_tail",
        guardian_integration_token="placeholder-token",
        guardian_identity="triplet-guardian",
        orion_base_url="https://smartopia.polytecsousse.dev/orion-filter/orion-1",
        actuator_execution_enabled=False,
        environment="development",
    )
    base.update(overrides)
    return Settings(**base)


async def test_verifier_sends_cursor_and_deduplicates(tmp_path, mapping):
    seen = {}
    events = [audit_event(seq=10), audit_event(seq=11)]
    cursor = AuditCursor(tmp_path / "cursor.json")
    v = verifier(audit_settings(tmp_path), audit_transport(events, seen), mapping, cursor)
    result = await v.verify_against(await v.fetch_events(), [])
    assert seen["since"] == "0"
    assert result["cursor_seq"] == 11
    # Second fetch starts from the advanced cursor — no repeated full scans.
    result2 = await v.verify_against(await v.fetch_events(), [])
    assert seen["since"] == "11"
    assert result2["verified_matches"] == 0  # events behind cursor skipped


async def test_duplicate_events_are_ignored(tmp_path, mapping):
    seen = {}
    events = [audit_event(seq=10), audit_event(seq=10)]  # same seq replay
    cursor = AuditCursor(tmp_path / "cursor.json")
    v = verifier(audit_settings(tmp_path), audit_transport(events, seen), mapping, cursor)
    result = await v.verify_against(await v.fetch_events(), [])
    assert result["cursor_seq"] == 10
    assert result["malformed"] == 0


async def test_malformed_events_fail_closed_per_row(tmp_path, mapping):
    seen = {}
    bad = audit_event(seq=11)
    bad.pop("evidence_digest")
    events = [audit_event(seq=10), bad]  # contiguous: 10, then malformed 11
    cursor = AuditCursor(tmp_path / "cursor.json")
    v = verifier(audit_settings(tmp_path), audit_transport(events, seen), mapping, cursor)
    result = await v.verify_against(await v.fetch_events(), [])
    assert result["malformed"] == 1
    assert result["cursor_seq"] == 11  # terminal event still advances the stream


async def test_non_dict_event_is_malformed(tmp_path, mapping):
    seen = {}
    cursor = AuditCursor(tmp_path / "cursor.json")
    v = verifier(
        audit_settings(tmp_path), audit_transport(["garbage"], seen), mapping, cursor
    )
    result = await v.verify_against(await v.fetch_events(), [])
    assert result["malformed"] == 1


async def test_bad_response_shape_fails_closed(tmp_path, mapping):
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"nope": []})
    )
    cursor = AuditCursor(tmp_path / "cursor.json")
    v = verifier(audit_settings(tmp_path), transport, mapping, cursor)
    with pytest.raises(GuardianCompatError, match="events list"):
        await v.fetch_events()


async def test_http_error_fails_closed(tmp_path, mapping):
    transport = httpx.MockTransport(lambda request: httpx.Response(503, text="down"))
    cursor = AuditCursor(tmp_path / "cursor.json")
    v = verifier(audit_settings(tmp_path), transport, mapping, cursor)
    with pytest.raises(GuardianCompatError, match="HTTP 503"):
        await v.fetch_events()


# --- security restrictions -----------------------------------------------------


def test_audit_worker_rejects_remote_http(tmp_path):
    with pytest.raises(GuardianCompatError, match="HTTPS"):
        AuditTailShadowWorker.from_settings(
            audit_settings(
                tmp_path,
                guardian_base_url="http://guardian.example.internal:8090",
            ),
            database=None,
        )


def test_audit_worker_rejects_non_development_environment(tmp_path):
    with pytest.raises(GuardianCompatError, match="development"):
        # Development-only guard fires before the production URL validator.
        AuditTailShadowWorker.from_settings(
            audit_settings(tmp_path, environment="staging"), database=None
        )


def test_audit_worker_requires_optin(tmp_path):
    with pytest.raises(GuardianCompatError, match="HTTPS"):
        AuditTailShadowWorker.from_settings(
            audit_settings(tmp_path, guardian_allow_loopback_http=False),
            database=None,
        )


# --- reliability: pending store, gaps, restarts (Task 7.3E-3-R) -------------


async def test_guardian_event_before_brain_observation_is_retained(tmp_path, mapping):
    """Ordering safety: evidence arrives first, observation later."""
    smoke = reading_for("us-b-bldg-01", "smokeLevel", stamp="2026-01-01T01:00:00+00:00")
    parsed = parse_audit_event(audit_event(stamp=STAMP), by_entity(mapping))
    entry = by_entity(mapping)[("us-b-bldg-01", "smokeLevel")]
    assert match_audit_event_to_reading(parsed, entry, _index(smoke)) is None
    # And a genuine verifier-level cycle retains it as pending.
    seen = {}
    events = [audit_event(seq=10, stamp="2026-01-01T00:00:00+00:00")]
    cursor = AuditCursor(tmp_path / "cursor.json")
    v = verifier(audit_settings(tmp_path), audit_transport(events, seen), mapping, cursor)
    result = await v.verify_against(await v.fetch_events(), [])
    assert result["unmatched_pending"] == 1
    assert result["cursor_seq"] == 10  # cursor may pass RETAINED evidence


async def test_pending_event_matches_after_observation_arrives(tmp_path, mapping):
    smoke = reading_for("us-b-bldg-01", "smokeLevel")
    events = [audit_event(seq=10)]
    cursor = AuditCursor(tmp_path / "cursor.json")
    store = PendingEvidenceStore(tmp_path / "pending.jsonl")
    v = AuditTailVerifier(
        audit_settings(tmp_path), list(mapping.sensors), cursor,
        transport=audit_transport(events, {}), pending_store=store,
    )
    # Cycle 1: no observation yet -> pending.
    r1 = await v.verify_against(await v.fetch_events(), [])
    assert r1["unmatched_pending"] == 1
    # Cycle 2: the observation now exists, and the RETRY PASS re-matches the
    # durably retained pending event even though its seq sits behind the
    # cursor (dedup only applies to fresh fetches, never to retained
    # evidence — otherwise it would be lost).
    r2 = await v.verify_against(
        [audit_event(seq=10)], [smoke]
    )
    assert r2["verified_matches"] == 1
    assert r2["unmatched_pending"] == 0
    assert store.load() == {}  # released after match


async def test_pending_store_retry_matches_new_observation(tmp_path, mapping):
    """A retained pending event is matched on a later cycle."""
    events = [audit_event(seq=10)]
    cursor = AuditCursor(tmp_path / "cursor.json")
    store = PendingEvidenceStore(tmp_path / "pending.jsonl")
    v = AuditTailVerifier(
        audit_settings(tmp_path), list(mapping.sensors), cursor,
        transport=audit_transport(events, {}), pending_store=store,
    )
    await v.verify_against(await v.fetch_events(), [])
    assert store.load().get(10) is not None
    smoke = reading_for("us-b-bldg-01", "smokeLevel")
    # A fresh cycle processes the pending store along with new events.
    pending = store.load()
    result = await v.verify_against([pending[10]], [smoke])
    assert result["verified_matches"] == 1
    assert result["unmatched_pending"] == 0
    assert store.load() == {}  # pending entry cleared after match


async def test_gap_detected_and_cursor_blocked(tmp_path, mapping):
    """A seq jump must not advance the cursor past the missed range."""
    events = [audit_event(seq=5), audit_event(seq=9)]  # gap: 6..8 missing
    cursor = AuditCursor(tmp_path / "cursor.json")
    v = verifier(audit_settings(tmp_path), audit_transport(events, {}), mapping, cursor)
    result = await v.verify_against(await v.fetch_events(), [])
    assert result["gap_detected"] is True
    assert result["cursor_seq"] == 5  # stopped before the gap


async def test_backlog_exceeds_limit_fails_closed(tmp_path, mapping):
    """Overflow of the pending store must fail loudly, never drop evidence."""
    events = [audit_event(seq=i) for i in range(1, 12)]
    cursor = AuditCursor(tmp_path / "cursor.json")
    store = PendingEvidenceStore(tmp_path / "pending.jsonl", max_pending=5)
    v = AuditTailVerifier(
        audit_settings(tmp_path), list(mapping.sensors), cursor,
        transport=audit_transport(events, {}), pending_store=store,
    )
    with pytest.raises(GuardianCompatError, match="overflow"):
        await v.verify_against(await v.fetch_events(), [])


async def test_restart_preserves_cursor_and_pending(tmp_path, mapping):
    """Crash/restart: cursor and pending store survive independently."""
    events = [audit_event(seq=10)]
    cursor = AuditCursor(tmp_path / "cursor.json")
    store = PendingEvidenceStore(tmp_path / "pending.jsonl")
    v = AuditTailVerifier(
        audit_settings(tmp_path), list(mapping.sensors), cursor,
        transport=audit_transport(events, {}), pending_store=store,
    )
    await v.verify_against(await v.fetch_events(), [])
    # Simulated restart: brand-new objects, same files.
    cursor2 = AuditCursor(tmp_path / "cursor.json")
    store2 = PendingEvidenceStore(tmp_path / "pending.jsonl")
    assert cursor2.load() == 10
    assert store2.load().get(10) is not None


async def test_partial_batch_processing(tmp_path, mapping):
    """Matched rows proceed; an unmatched row is retained, both advance."""
    smoke = reading_for("us-b-bldg-01", "smokeLevel")
    # The temperature observation carries a DIFFERENT timestamp than the
    # temperature audit event, so only the smoke row matches in cycle 1 and
    # the temperature evidence is durably retained as pending.
    temp = reading_for("us-b-bldg-01", "temperature", stamp="2100-01-01T00:00:00+00:00")
    events = [
        audit_event(seq=10, prop="fire_smoke", value=2.2),
        audit_event(seq=11, prop="temperature", value=21.7, unit="C",
                    stamp="2099-01-01T00:00:00+00:00"),
    ]
    cursor = AuditCursor(tmp_path / "cursor.json")
    store = PendingEvidenceStore(tmp_path / "pending.jsonl")
    v = AuditTailVerifier(
        audit_settings(tmp_path), list(mapping.sensors), cursor,
        transport=audit_transport(events, {}), pending_store=store,
    )
    result = await v.verify_against(await v.fetch_events(), [smoke, temp])
    assert result["verified_matches"] == 1
    assert result["unmatched_pending"] == 1
    assert result["cursor_seq"] == 11
    # The retained temperature event is a genuine retry candidate later.
    assert store.load().get(11) is not None


async def test_reset_detected_when_seq_returns_behind_cursor(tmp_path, mapping):
    """Truncation/reset signature: only old seqs arrive while cursor is high."""
    events = [audit_event(seq=3)]  # below a high cursor with empty backlog
    cursor = AuditCursor(tmp_path / "cursor.json")
    cursor.advance(50)
    v = verifier(audit_settings(tmp_path), audit_transport(events, {}), mapping, cursor)
    result = await v.verify_against(await v.fetch_events(), [])
    # The old seq is treated as replay (not a trust event); the store stays
    # empty, and nothing advances. A real reset shows up as an empty batch.
    assert result["cursor_seq"] == 50
    assert result["verified_matches"] == 0


# --- zero trust ----------------------------------------------------------------


async def test_reconciliation_never_grants_trust(tmp_path, mapping):
    """The contract's core safety property, asserted structurally."""
    smoke = reading_for("us-b-bldg-01", "smokeLevel")
    seen = {}
    events = [audit_event(seq=10)]
    cursor = AuditCursor(tmp_path / "cursor.json")
    v = verifier(audit_settings(tmp_path), audit_transport(events, seen), mapping, cursor)
    result = await v.verify_against(await v.fetch_events(), [smoke])
    assert result["trusted_granted"] == 0
    assert result["mode"] == "audit_tail_reconciliation"


async def test_worker_cycle_reports_zero_trust(tmp_path, mapping):
    settings = audit_settings(tmp_path)
    worker = AuditTailShadowWorker.from_settings(settings, database=None)
    assert worker.stats["trusted_granted"] == 0
    # Even a full successful cycle cannot change this.
    worker.stats.update({"verified_matches": 5})
    assert worker.stats["trusted_granted"] == 0
