"""Stage A + pipeline-skeleton tests (plan §6.1, §8, §11).

These flip the config gates ON for the duration of a test (verify_signatures /
enforce_freshness) so we exercise the *real* Stage-A signature and freshness/seq
code paths through the public /v1/readings surface. Freshness tests use utcnow_iso()
timestamps (never the fixed-date golden fixtures) so the wall-clock gate is honest.
"""
import copy
import dataclasses

import pytest

from guardian.config import load_settings
from guardian.signing import compute_digest, hmac_signature, utcnow_iso
from guardian.api import create_app
from guardian.audit import AuditLog
from guardian.dedup import SeenSet
from guardian.pipeline import Pipeline
from guardian.registry import DeviceRegistry

SECRET = "dev-secret-river-gauge-1"


def _fresh_reading(seq=1):
    """A fresh, well-formed water_level reading for river-gauge-1 (known device)."""
    return {
        "batch_id": "b-100", "reading_id": f"r-fresh-{seq}",
        "sensor_id": "river-gauge-1", "zone": "Z-RIVER_UNDERPASS",
        "observed_property": "water_level", "phenomenon_time": utcnow_iso(),
        "result": {"value": 0.8, "unit": "m"},
        "provenance": {"firmware": "1.4", "cal": "CAL-07", "seq": seq},
        "digest": "sha256:" + "0" * 64, "signature": "hmac-sha256:x",
    }


def _sign(r):
    r["digest"] = compute_digest(r)
    r["signature"] = hmac_signature(SECRET, r["digest"])
    return r


# ---- app-level Stage A behaviours ----
def _client(tmp_path, *, verify_sig=False, enforce_fresh=False):
    s = load_settings()
    s = dataclasses.replace(
        s,
        auth=dataclasses.replace(s.auth, verify_signatures=verify_sig),
        ttl=dataclasses.replace(s.ttl, enforce_freshness=enforce_fresh),
        paths=dataclasses.replace(s.paths, audit_log=str(tmp_path / "audit.jsonl")),
    )
    from fastapi.testclient import TestClient
    return TestClient(create_app(s))


def test_signature_valid_accepted(tmp_path):
    c = _client(tmp_path, verify_sig=True)
    r = c.post("/v1/readings", json=_sign(_fresh_reading()))
    assert r.status_code == 200
    assert r.json()["results"][0]["code"] == "ACCEPTED"


def test_signature_tampered_value_rejected(tmp_path):
    c = _client(tmp_path, verify_sig=True)
    reading = _sign(_fresh_reading())
    reading["result"]["value"] = 5.0          # tamper after signing
    r = c.post("/v1/readings", json=reading)
    assert r.json()["results"][0]["code"] == "SIG_INVALID"


def test_signature_wrong_key_rejected(tmp_path):
    c = _client(tmp_path, verify_sig=True)
    r = _fresh_reading()
    r["digest"] = compute_digest(r)
    r["signature"] = hmac_signature("not-the-device-key", r["digest"])
    resp = c.post("/v1/readings", json=r)
    assert resp.json()["results"][0]["code"] == "SIG_INVALID"


def test_fresh_reading_accepted_with_freshness_on(tmp_path):
    c = _client(tmp_path, enforce_fresh=True)
    r = c.post("/v1/readings", json=_fresh_reading(seq=1))
    assert r.json()["results"][0]["code"] == "ACCEPTED"


def test_stale_reading_rejected_with_freshness_on(tmp_path):
    c = _client(tmp_path, enforce_fresh=True)
    stale = _fresh_reading()
    stale["phenomenon_time"] = "2000-01-01T00:00:00.000Z"   # far in the past
    r = c.post("/v1/readings", json=stale)
    assert r.json()["results"][0]["code"] == "STALE"


def test_future_reading_rejected_with_freshness_on(tmp_path):
    c = _client(tmp_path, enforce_fresh=True)
    future = _fresh_reading()
    future["phenomenon_time"] = "2099-01-01T00:00:00.000Z"
    r = c.post("/v1/readings", json=future)
    assert r.json()["results"][0]["code"] == "STALE"


def test_sequence_gap_rejected(tmp_path):
    c = _client(tmp_path, enforce_fresh=True)
    first = c.post("/v1/readings", json=_fresh_reading(seq=10)).json()["results"][0]
    assert first["code"] == "ACCEPTED"
    gap = c.post("/v1/readings", json=_fresh_reading(seq=14)).json()["results"][0]  # 10 -> 14
    assert gap["code"] == "STALE"


def test_rejected_replay_does_not_roll_back_sequence_watermark(tmp_path):
    """REGRESSION: the watermark was mutated before validation, so one rejected replayed
    frame rolled it back and let the next old frames through as 'monotonic'."""
    c = _client(tmp_path, enforce_fresh=True)
    assert c.post("/v1/readings", json=_fresh_reading(seq=10)).json()["results"][0]["code"] == "ACCEPTED"
    replay = c.post("/v1/readings", json=_fresh_reading(seq=3)).json()["results"][0]
    assert replay["code"] == "STALE"                     # rejected as non-monotonic
    # watermark must still be 10 -> 4/5/6 stay rejected
    for stale_seq in (4, 5, 6):
        res = c.post("/v1/readings", json=_fresh_reading(seq=stale_seq)).json()["results"][0]
        assert res["code"] == "STALE", f"seq {stale_seq} wrongly accepted after a rollback"


def test_sequence_gap_recovers_after_the_missing_frame_arrives(tmp_path):
    c = _client(tmp_path, enforce_fresh=True)
    c.post("/v1/readings", json=_fresh_reading(seq=10))
    assert c.post("/v1/readings", json=_fresh_reading(seq=14)).json()["results"][0]["code"] == "STALE"
    # the dropped 11 lands -> 11 is accepted and the watermark advances
    assert c.post("/v1/readings", json=_fresh_reading(seq=11)).json()["results"][0]["code"] == "ACCEPTED"


def test_unknown_device_still_rejected(tmp_path):
    c = _client(tmp_path, verify_sig=True)
    r = _fresh_reading()
    r["sensor_id"] = "ghost-1"
    resp = c.post("/v1/readings", json=r)
    assert resp.json()["results"][0]["code"] == "UNKNOWN_DEVICE"


# ---- pipeline skeleton: Stages B-E report pending / determinism ----
def _pipeline(tmp_path):
    s = load_settings()
    s = dataclasses.replace(s, paths=dataclasses.replace(s.paths, audit_log=str(tmp_path / "a.jsonl")))
    return Pipeline(s, DeviceRegistry.from_keyring(s.resolve(s.auth.keyring_path)),
                    SeenSet(s.ttl.seen_window_s), AuditLog(s.resolve(s.paths.audit_log)))


def test_stages_b_to_e_run_and_verdict(tmp_path):
    pipe = _pipeline(tmp_path)
    report = pipe.process(_fresh_reading(seq=1))
    assert report.accepted
    by_stage = {s.stage: s for s in report.stages}
    assert by_stage["A"].status == "ok"
    assert by_stage["B"].status == "ok"
    assert by_stage["C"].status == "ok"
    assert by_stage["D"].status == "ok"
    assert by_stage["E"].status == "ok"
    # Stage E produced a TRUSTED verdict, and a TRUSTED passport may authorize full-commit.
    verdict = report.verdict
    assert verdict is not None
    assert verdict.disposition == "TRUSTED"
    assert verdict.trust >= 0.80
    assert "full" in verdict.allowed_actions
    assert verdict.policy_version == "v1.0"


def test_determinism_same_input_same_verdict(tmp_path):
    """Same reading through two independent pipelines -> identical accept/code."""
    reading = _fresh_reading(seq=1)
    r1 = _pipeline(tmp_path / "p1").process(copy.deepcopy(reading))
    r2 = _pipeline(tmp_path / "p2").process(copy.deepcopy(reading))
    assert (r1.accepted, r1.code) == (r2.accepted, r2.code) == (True, "ACCEPTED")


def test_concurrent_readings_are_serialised_safely(tmp_path):
    """FastAPI dispatches these sync endpoints on a threadpool, so the pipeline must be
    safe under concurrent POSTs: every reading accepted, and no lost verdicts."""
    from concurrent.futures import ThreadPoolExecutor
    pipe = _pipeline(tmp_path)
    readings = [_fresh_reading(seq=i) for i in range(1, 41)]
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(pipe.process, readings))
    assert all(r.accepted for r in results)
    assert len({r.reading_id for r in results}) == len(readings)
    assert sum(1 for r in results if pipe.get_verdict(r.verdict.evidence_digest)) == len(readings)


def test_concurrent_duplicate_submissions_accept_exactly_once(tmp_path):
    """REGRESSION: `seen_before()` + `add()` is a check-then-act pair, and FastAPI
    dispatches these sync endpoints on a threadpool. Without the pipeline lock, 16
    concurrent posts of the SAME reading were all accepted (dedup raced); with it,
    exactly one wins. The sleep widens the window so the race is deterministic
    rather than a rare flake.
    """
    import time
    from concurrent.futures import ThreadPoolExecutor
    pipe = _pipeline(tmp_path)
    original = pipe.seen.seen_before

    def slow_seen(key):          # yield the GIL between the check and the add
        result = original(key)
        time.sleep(0.02)
        return result

    pipe.seen.seen_before = slow_seen
    reading = _fresh_reading(seq=1)
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: pipe.process(copy.deepcopy(reading)), range(16)))
    accepted = [r for r in results if r.accepted]
    assert len(accepted) == 1, f"{len(accepted)}/16 accepted - dedup raced"
    assert all(r.code == "DUPLICATE" for r in results if not r.accepted)


def test_concurrent_witness_feedback_is_serialised(tmp_path):
    """Witness folds must not interleave and lose a decay step."""
    from concurrent.futures import ThreadPoolExecutor
    pipe = _pipeline(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        scores = list(pool.map(lambda _: pipe.note_effect("river-gauge-1", "MISMATCH"), range(16)))
    assert scores.count(None) == 0
    # 16 halvings from 1.0 -> 0.5**16; deterministic regardless of interleaving order
    assert pipe._device_history["river-gauge-1"] == pytest.approx(0.5 ** 16)


def test_verdict_cache_is_bounded(tmp_path):
    """REGRESSION: the in-memory verdict map grew without limit on a long-running server."""
    from guardian.pipeline import _MAX_VERDICTS
    pipe = _pipeline(tmp_path)
    # push far past the cap
    for i in range(_MAX_VERDICTS + 25):
        pipe._verdicts[f"sha256:{i}"] = object()
    pipe._evict_verdicts()
    assert len(pipe._verdicts) <= _MAX_VERDICTS
    # oldest evicted, newest retained
    assert "sha256:0" not in pipe._verdicts
    assert f"sha256:{_MAX_VERDICTS + 24}" in pipe._verdicts


def test_source_ids_are_deduplicated(tmp_path, drift_attack):
    """The passport must name each corroborating source once, not once per sibling tick."""
    from guardian.signing import parse_iso
    s = load_settings()
    s = dataclasses.replace(s, paths=dataclasses.replace(s.paths, audit_log=str(tmp_path / "a.jsonl")))
    pipe = Pipeline(s, DeviceRegistry.from_keyring(s.resolve(s.auth.keyring_path)),
                    SeenSet(s.ttl.seen_window_s), AuditLog(s.resolve(s.paths.audit_log)),
                    now=parse_iso(drift_attack[-1]["phenomenon_time"]))
    reports = [pipe.process(dict(r)) for r in drift_attack]
    g1 = [r for r in reports if r.sensor_id == "river-gauge-1"][-1]
    ids = g1.verdict.source_ids
    assert ids == ["river-gauge-1", "rain-gauge-2"], ids
    assert len(ids) == len(set(ids))


def test_s1_flagship_drift_suspect(tmp_path, drift_attack):
    """S1 (plan §7.1): a validly-signed river gauge drifts +6cm/tick, reporting falsely
    low while heavy rain corroborates a flood. Guardian verdict = SUSPECT, and a SUSPECT
    passport can never authorize a full-commit.

    Runs with signature verification ON — the posture S1 was designed for (its HMACs are
    valid) and the production posture. With verification off, provenance is honestly
    scored at 0.5 and S1 lands lower, which is correct, not a regression.
    """
    from guardian.signing import parse_iso
    s = load_settings()
    s = dataclasses.replace(
        s,
        auth=dataclasses.replace(s.auth, verify_signatures=True),
        paths=dataclasses.replace(s.paths, audit_log=str(tmp_path / "a.jsonl")),
    )
    now = parse_iso(drift_attack[-1]["phenomenon_time"])
    pipe = Pipeline(s, DeviceRegistry.from_keyring(s.resolve(s.auth.keyring_path)),
                    SeenSet(s.ttl.seen_window_s), AuditLog(s.resolve(s.paths.audit_log)),
                    now=now)
    reports = [pipe.process(dict(r)) for r in drift_attack]
    assert all(r.accepted for r in reports), "every S1 frame is validly signed"
    g1 = [r for r in reports if r.sensor_id == "river-gauge-1"]
    verdict = g1[-1].verdict
    assert verdict is not None
    assert verdict.disposition == "SUSPECT", verdict
    assert verdict.trust == pytest.approx(0.54, abs=0.002)
    assert {"DRIFT", "CONFLICT"}.issubset(set(verdict.reason_codes))
    assert "full" not in verdict.allowed_actions        # non-bypassable: no full-commit
    assert "reversible" in verdict.allowed_actions      # reversible road closure still allowed
    # the published formula reproduces the verdict exactly
    assert verdict.trust == pytest.approx(
        sum(verdict.factors[k] * w for k, w in
            {"corroboration": 0.30, "consistency": 0.20, "plausibility": 0.18,
             "provenance": 0.12, "freshness": 0.10, "history": 0.10}.items())
        - 0.25 * verdict.conflict, abs=0.002)


def test_s1_signature_check_is_real(tmp_path, drift_attack):
    """A single flipped byte in the flagship fixture must be rejected at Stage A."""
    import copy as _copy
    s = load_settings()
    s = dataclasses.replace(
        s, auth=dataclasses.replace(s.auth, verify_signatures=True),
        paths=dataclasses.replace(s.paths, audit_log=str(tmp_path / "a.jsonl")))
    from guardian.signing import parse_iso
    pipe = Pipeline(s, DeviceRegistry.from_keyring(s.resolve(s.auth.keyring_path)),
                    SeenSet(s.ttl.seen_window_s), AuditLog(s.resolve(s.paths.audit_log)),
                    now=parse_iso(drift_attack[-1]["phenomenon_time"]))
    forged = _copy.deepcopy(drift_attack[0])
    forged["result"]["value"] = 5.99          # tamper after signing
    report = pipe.process(forged)
    assert report.accepted is False
    assert report.code == "SIG_INVALID"


# ---- witness feedback: history decay + quarantine overlay (plan §11) ----
def test_mismatch_witness_decays_history_factor(tmp_path):
    from guardian.pipeline import HISTORY_INIT
    pipe = _pipeline(tmp_path)
    assert pipe._device_history.get("river-gauge-1", HISTORY_INIT) == 1.0
    after = pipe.note_effect("river-gauge-1", "MISMATCH")
    assert after == pytest.approx(0.5)
    assert pipe.note_effect("river-gauge-1", "MISMATCH") == pytest.approx(0.25)


def test_clean_witness_lets_history_recover(tmp_path):
    pipe = _pipeline(tmp_path)
    pipe.note_effect("river-gauge-1", "MISMATCH")
    recovered = pipe.note_effect("river-gauge-1", "MATCH")
    assert recovered > 0.5


def test_consecutive_mismatches_quarantine_the_device(tmp_path):
    from guardian.pipeline import QUARANTINE_AFTER_MISMATCHES
    pipe = _pipeline(tmp_path)
    for _ in range(QUARANTINE_AFTER_MISMATCHES):
        pipe.note_effect("river-gauge-1", "MISMATCH")
    assert pipe.registry.is_quarantined("river-gauge-1") is True
    # a quarantined device loses provenance and can never authorise a full-commit
    reading = _fresh_reading(seq=1)
    verdict = pipe.process(reading).verdict
    assert verdict.disposition in ("RESTRICT", "SUSPECT")
    assert "full" not in verdict.allowed_actions


def test_witness_for_unknown_device_is_a_noop(tmp_path):
    pipe = _pipeline(tmp_path)
    assert pipe.note_effect("ghost-1", "MISMATCH") is None
    assert pipe.note_effect("", "MISMATCH") is None


# ---- anti-replay: Stage A dedup keys on reading_id, so the digest check must hold ----
def test_replayed_frame_with_fresh_reading_id_is_caught(tmp_path):
    """An attacker re-sends an old signed frame under a NEW reading_id: Stage A dedup
    misses it, so the detector-level digest replay check is the only remaining gate."""
    pipe = _pipeline(tmp_path)
    original = _fresh_reading(seq=1)
    pipe.process(dict(original))
    replay = dict(original)
    replay["reading_id"] = "r-fresh-replayed"      # bypass the reading_id dedup
    verdict = pipe.process(replay).verdict
    assert verdict is not None
    assert verdict.disposition == "MALICIOUS"
    assert "REPLAY" in verdict.reason_codes
    assert verdict.allowed_actions == []
