"""Unit tests for reading integrity + signing (plan §8 — Security & Trust).

Covers the HMAC-SHA256 integrity model: content digest binds the reading body,
the MAC binds that digest to the device key. Proves tamper / wrong-key / missing-key
are all detected, and that the wire format is stable and deterministic.
"""
from guardian.signing import (
    canonical_body,
    compute_digest,
    derive_reading_id,
    hmac_signature,
    parse_iso,
    verify_reading_integrity,
)

SECRET = "dev-secret-river-gauge-1"


def _unsigned():
    return {
        "batch_id": "b-042", "reading_id": "r-001", "sensor_id": "river-gauge-1",
        "zone": "Z-RIVER_UNDERPASS", "observed_property": "water_level",
        "phenomenon_time": "2026-10-20T10:03:11.900Z",
        "result": {"value": 0.82, "unit": "m"},
        "provenance": {"firmware": "1.4", "cal": "CAL-07", "seq": 1},
    }


def _signed(secret=SECRET):
    r = _unsigned()
    r["digest"] = compute_digest(r)
    r["signature"] = hmac_signature(secret, r["digest"])
    return r


# --- digest ---
def test_canonical_body_excludes_digest_and_signature():
    r = _signed()
    body = canonical_body(r)
    assert b"digest" not in body and b"signature" not in body


def test_compute_digest_stable_and_prefixed():
    a, b = compute_digest(_unsigned()), compute_digest(_unsigned())
    assert a == b
    assert a.startswith("sha256:") and len(a) == len("sha256:") + 64


def test_compute_digest_changes_with_value():
    r1, r2 = _unsigned(), _unsigned()
    r2["result"]["value"] = 9.9
    assert compute_digest(r1) != compute_digest(r2)


# --- signature ---
def test_hmac_signature_deterministic_and_prefixed():
    a = hmac_signature(SECRET, "sha256:deadbeef")
    assert a == hmac_signature(SECRET, "sha256:deadbeef")
    assert a.startswith("hmac-sha256:")


def test_verify_roundtrip_ok():
    ok, reason = verify_reading_integrity(_signed(), SECRET)
    assert ok and reason == "OK"


def test_verify_tampered_value_fails_digest():
    r = _signed()
    r["result"]["value"] = 99.0          # value changed, digest/signature stale
    ok, reason = verify_reading_integrity(r, SECRET)
    assert not ok and reason == "DIGEST_MISMATCH"


def test_verify_wrong_secret_fails_sig():
    ok, reason = verify_reading_integrity(_signed(), "wrong-key")
    assert not ok and reason == "SIG_MISMATCH"


def test_verify_missing_secret():
    ok, reason = verify_reading_integrity(_signed(), None)
    assert not ok and reason == "NO_SECRET"


def test_verify_replayed_signature_on_new_body_fails():
    # attacker lifts a valid (digest, signature) pair but swaps the body for a
    # different value -> the recomputed digest no longer matches the copied one.
    good = _signed()
    forged = _unsigned()
    forged["result"]["value"] = 99.0                     # different body
    forged["digest"] = good["digest"]                    # but old digest
    forged["signature"] = good["signature"]              # and old signature
    ok, reason = verify_reading_integrity(forged, SECRET)
    assert not ok and reason == "DIGEST_MISMATCH"


# --- helpers ---
def test_parse_iso_z_and_offset():
    assert parse_iso("2026-10-20T10:03:11.900Z") == parse_iso("2026-10-20T10:03:11.900+00:00")


def test_derive_reading_id_explicit_and_derived():
    r = _unsigned()
    assert derive_reading_id(r) == "r-001"
    no_id = {k: v for k, v in r.items() if k != "reading_id"}
    assert derive_reading_id(no_id).startswith("rid-")
