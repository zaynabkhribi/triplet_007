"""Evidence Passport build / verify / expiry / scope (plan §6.5, §8).

A passport is bound to (zone, evidence_digest, policy_version), signed with the
Guardian service HMAC, and short-TTL. These tests pin the non-repudiation surface
the Twin relies on before acting on a Proof-Carrying Action.
"""
import time

from guardian.config import load_settings, load_policy
from guardian.passport import (VerdictRecord, build_passport, sign_passport,
                               verify_passport, is_expired)
from guardian.signing import iso_from_epoch, parse_iso

SETTINGS = load_settings()
POLICY = load_policy(SETTINGS)


def _record(disposition="TRUSTED", trust=0.91, allowed=None, evidence="sha256:abc"):
    return VerdictRecord(
        evidence_digest=evidence, reading_id="r-1", zone="Z-RIVER_UNDERPASS",
        sensor_id="river-gauge-1", observed_property="water_level",
        disposition=disposition, trust=trust, reason_codes=[], factors={"c": 1.0},
        conflict=0.0, verified_at=parse_iso("2026-10-20T10:03:13.000Z"),
        policy_version="v1.0", allowed_actions=allowed if allowed is not None
        else ["full", "reversible", "precautionary"], conditions=[], source_ids=["river-gauge-1"],
    )


def test_build_and_verify_roundtrip():
    p = build_passport(_record(), SETTINGS, POLICY)
    ok, reason = verify_passport(p, SETTINGS)
    assert ok and reason == "OK"


def test_signature_binds_body_so_tampering_is_rejected():
    p = build_passport(_record(), SETTINGS, POLICY)
    p["trust"] = 0.99                       # tamper AFTER signing
    ok, reason = verify_passport(p, SETTINGS)
    assert not ok and reason == "SIG_INVALID"


def test_passport_bound_to_zone_evidence_and_policy():
    rec = _record(evidence="sha256:ev-99")
    p = build_passport(rec, SETTINGS, POLICY)
    assert p["zone"] == "Z-RIVER_UNDERPASS"
    assert p["evidence_digest"] == "sha256:ev-99"
    assert p["policy_version"] == "v1.0"
    assert p["ttl_s"] == SETTINGS.ttl.passport_s
    assert p["passport_id"].startswith("psp-")


def test_verify_rejects_expired_passport():
    p = build_passport(_record(), SETTINGS, POLICY)
    # back-date issued_at beyond TTL and re-sign so the signature stays valid but it is expired
    p["issued_at"] = utcnow_iso_backdated(seconds=SETTINGS.ttl.passport_s + 5)
    p["signature"] = sign_passport(p, SETTINGS)
    ok, reason = verify_passport(p, SETTINGS)
    assert not ok and reason == "EXPIRED"
    assert is_expired(p)


def test_passport_expires_exactly_at_ttl():
    """Validity is the half-open interval [issued, issued+ttl): at exactly ttl it is expired."""
    issued = parse_iso("2026-10-20T10:00:00Z")
    p = {"issued_at": iso_from_epoch(issued), "ttl_s": 6}
    assert is_expired(p, now=issued + 5.999) is False
    assert is_expired(p, now=issued + 6.0) is True
    assert is_expired(p, now=issued + 6.001) is True


def test_build_passport_honours_injected_now():
    """REGRESSION: the `now` parameter was accepted and then ignored."""
    from guardian.signing import iso_from_epoch
    now = parse_iso("2026-10-20T10:00:00Z")
    p = build_passport(_record(), SETTINGS, POLICY, now=now)
    assert p["issued_at"] == iso_from_epoch(now)
    assert verify_passport(p, SETTINGS, now=now) == (True, "OK")


def test_malicious_passport_has_no_actions():
    rec = _record(disposition="MALICIOUS", trust=0.0, allowed=[])
    p = build_passport(rec, SETTINGS, POLICY)
    assert p["disposition"] == "MALICIOUS"
    assert p["allowed_actions"] == []


def utcnow_iso_backdated(seconds: int) -> str:
    t = time.time() - seconds
    import datetime as dt
    return dt.datetime.fromtimestamp(t, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + "000Z"
