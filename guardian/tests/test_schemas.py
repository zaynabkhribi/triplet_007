"""Contract tests: every shared schema loads and validates a canonical example.

This is our Interoperability + Documentation evidence (plan §12): the schemas are
real, loadable, and enforce the contract partners code against.
"""
from pathlib import Path


from guardian.schemas import SCHEMA_NAMES, load_schema, validate

SHARED = Path(__file__).resolve().parents[1] / "shared"


def test_all_schemas_load():
    for name in SCHEMA_NAMES:
        schema = load_schema(name)
        assert schema.get("$id", "").endswith(f"{name}.json"), name


def test_golden_fixture_validates(golden):
    for r in golden:
        ok, errors = validate(r, "reading")
        assert ok, [e.message for e in errors]


def test_reading_missing_required_field_fails(golden):
    bad = dict(golden[0])
    bad.pop("result")
    ok, _ = validate(bad, "reading")
    assert not ok


def test_reading_bad_digest_pattern_fails(golden):
    bad = dict(golden[0])
    bad["digest"] = "not-a-sha256"
    ok, _ = validate(bad, "reading")
    assert not ok


def test_passport_example_valid():
    passport = {
        "passport_id": "psp-042", "issued_at": "2026-10-20T10:03:12.400Z", "ttl_s": 6,
        "zone": "Z-RIVER_UNDERPASS", "disposition": "SUSPECT", "trust": 0.52,
        "reason_codes": ["CONFLICT", "DRIFT"], "evidence_digest": "sha256:" + "a" * 64,
        "source_ids": ["river-gauge-1"], "policy_version": "v1.0",
        "allowed_actions": ["barrier.partial_close", "pump.standby"],
        "conditions": ["require_second_source"], "signature": "ed25519:x",
    }
    ok, errors = validate(passport, "passport")
    assert ok, [e.message for e in errors]


def test_passport_bad_disposition_fails():
    passport = {
        "passport_id": "p", "issued_at": "2026-10-20T10:03:12.400Z", "ttl_s": 6,
        "zone": "z", "disposition": "MAYBE", "trust": 0.5, "reason_codes": [],
        "evidence_digest": "sha256:" + "a" * 64, "source_ids": ["s"], "policy_version": "v1.0",
        "allowed_actions": [], "signature": "x",
    }
    ok, _ = validate(passport, "passport")
    assert not ok


def test_action_example_valid():
    action = {
        "action_id": "a-900", "idempotency_key": "a-900", "passport_id": "psp-042",
        "evidence_digest": "sha256:" + "b" * 64, "target": "valve-1", "target_version": "v3",
        "action": "valve.partial_close", "params": {"fraction": 0.3},
    }
    ok, errors = validate(action, "action")
    assert ok, [e.message for e in errors]


def test_witness_example_valid():
    witness = {
        "action_id": "a-900", "requested": "pump.on", "acknowledged": "applied",
        "observed": {"flow_sensor": "flat"}, "result": "MISMATCH", "implicated_device": "pump-1",
    }
    ok, errors = validate(witness, "witness")
    assert ok, [e.message for e in errors]


def test_witness_bad_result_fails():
    ok, _ = validate({"action_id": "a", "requested": "x", "acknowledged": "y", "result": "SOMETIMES"}, "witness")
    assert not ok
