"""18-case adversarial matrix (Phase 1 Security 10pts + Test Book depth).

Every attack must end in a STABLE code or a contained verdict — never a 500,
never a trusted verdict, never a full-commit on false evidence. Runs against
the real HTTP surface (TestClient) and the real Twin-side passport check, so
the jury's `run scenario` story and these assertions test the same code.

Attacks: forged signature, tampered value, duplicate replay, fresh-id replay,
stale frame, future stamp, sequence gap, unknown device, out-of-range value,
missing provenance, malformed body, expired passport, tampered passport,
out-of-scope action, witness-lie quarantine. Plus: p95 latency probe, audit
chain intact + tamper-evident, and a no-500 sweep.
"""
import dataclasses
import time
from pathlib import Path

from fastapi.testclient import TestClient

from guardian.api import create_app
from guardian.audit import AuditLog
from guardian.config import load_settings
from guardian.mock import mock_twin
from guardian.mock.mock_brain import decide
from guardian.passport import VerdictRecord, build_passport, verify_passport
from guardian.signing import compute_digest, hmac_signature, utcnow_iso

RIVER_SECRET = "dev-secret-river-gauge-1"
RAIN_SECRET = "dev-secret-rain-gauge-2"


def _client(tmp_path, *, verify_sig=False, enforce_fresh=False):
    s = load_settings()
    s = dataclasses.replace(
        s,
        auth=dataclasses.replace(s.auth, verify_signatures=verify_sig),
        ttl=dataclasses.replace(s.ttl, enforce_freshness=enforce_fresh),
        paths=dataclasses.replace(s.paths, audit_log=str(tmp_path / "adv.jsonl")),
    )
    return TestClient(create_app(s))


def _reading(rid="adv-1", sensor="river-gauge-1", prop="water_level",
             value=0.82, unit="m", seq=1, when=None):
    return {
        "batch_id": "b-adv", "reading_id": rid,
        "sensor_id": sensor, "zone": "Z-RIVER_UNDERPASS",
        "observed_property": prop, "phenomenon_time": when or utcnow_iso(),
        "result": {"value": value, "unit": unit},
        "provenance": {"firmware": "1.4", "cal": "CAL-07", "seq": seq},
        "digest": "sha256:" + "0" * 64, "signature": "hmac-sha256:x",
    }


def _sign(r, secret=RIVER_SECRET):
    r["digest"] = compute_digest(r)
    r["signature"] = hmac_signature(secret, r["digest"])
    return r


# --- 1-2: signature forgeries -------------------------------------------
def test_forged_signature_rejected(tmp_path):
    c = _client(tmp_path, verify_sig=True)
    r = _sign(_reading(), secret="attacker-key")  # noqa: S106 - deliberately wrong key
    assert c.post("/v1/readings", json=r).json()["results"][0]["code"] == "SIG_INVALID"


def test_tampered_value_after_signing_rejected(tmp_path):
    c = _client(tmp_path, verify_sig=True)
    r = _sign(_reading())
    r["result"]["value"] = 5.0          # tamper after signing
    assert c.post("/v1/readings", json=r).json()["results"][0]["code"] == "SIG_INVALID"


# --- 3-4: replay ----------------------------------------------------------
def test_duplicate_reading_id_rejected(tmp_path):
    c = _client(tmp_path, verify_sig=True)
    r = _sign(_reading(rid="dup-1"))
    assert c.post("/v1/readings", json=r).json()["results"][0]["code"] == "ACCEPTED"
    assert c.post("/v1/readings", json=r).json()["results"][0]["code"] == "DUPLICATE"


def test_replay_under_fresh_id_is_malicious(tmp_path):
    c = _client(tmp_path)               # detector-level gate, no signature gate needed
    r = _sign(_reading(rid="orig-1"))
    assert c.post("/v1/readings", json=r).json()["results"][0]["code"] == "ACCEPTED"
    replay = dict(r)
    replay["reading_id"] = "fresh-id-same-content"
    p = c.post("/v1/passport", json={"evidence_digest": replay["digest"]})
    # the replayed digest is already known for this device -> MALICIOUS, never trusted
    c.post("/v1/readings", json=replay)
    events = c.get("/v1/verdict?since=0").json()["events"]
    verdicts = [e for e in events if e.get("reading_id") == "fresh-id-same-content"]
    assert verdicts and verdicts[0]["disposition"] == "MALICIOUS"
    assert "REPLAY" in verdicts[0]["reason_codes"]
    assert p.status_code in (200, 404)   # passport for unseen digest is 404 until ingested


# --- 5-7: time / sequence --------------------------------------------------
def test_stale_frame_rejected(tmp_path):
    c = _client(tmp_path, enforce_fresh=True)
    r = _sign(_reading(when="2000-01-01T00:00:00.000Z"))
    assert c.post("/v1/readings", json=r).json()["results"][0]["code"] == "STALE"


def test_future_stamp_rejected(tmp_path):
    c = _client(tmp_path, enforce_fresh=True)
    r = _sign(_reading(when="2099-01-01T00:00:00.000Z"))
    assert c.post("/v1/readings", json=r).json()["results"][0]["code"] == "STALE"


def test_sequence_gap_rejected(tmp_path):
    c = _client(tmp_path, enforce_fresh=True)
    assert c.post("/v1/readings", json=_sign(_reading(rid="s-10", seq=10))).json()["results"][0]["code"] == "ACCEPTED"
    assert c.post("/v1/readings", json=_sign(_reading(rid="s-14", seq=14))).json()["results"][0]["code"] == "STALE"


# --- 8-9: identity / range --------------------------------------------------
def test_unknown_device_rejected(tmp_path):
    c = _client(tmp_path)
    ghost = _reading(rid="ghost-1", sensor="ghost-1")
    assert c.post("/v1/readings", json=ghost).json()["results"][0]["code"] == "UNKNOWN_DEVICE"


def test_out_of_range_downgraded_not_trusted(tmp_path):
    c = _client(tmp_path)               # 99 m is outside the 0-6 m water profile
    r = _reading(rid="oor-1", value=99.0)
    assert c.post("/v1/readings", json=r).json()["results"][0]["code"] == "ACCEPTED"
    ev = [e for e in c.get("/v1/verdict?since=0").json()["events"]
          if e.get("reading_id") == "oor-1"][0]
    assert ev["disposition"] != "TRUSTED"
    assert "OUT_OF_RANGE" in ev["reason_codes"]


def test_missing_provenance_rejected_at_pipeline(tmp_path):
    """Defense in depth: even past the schema gate, Stage A demands firmware/cal."""
    from guardian.dedup import SeenSet
    from guardian.pipeline import Pipeline
    from guardian.registry import DeviceRegistry
    s = load_settings()
    s = dataclasses.replace(s, paths=dataclasses.replace(s.paths, audit_log=str(tmp_path / "a.jsonl")))
    pipe = Pipeline(s, DeviceRegistry.from_keyring(s.resolve(s.auth.keyring_path)),
                    SeenSet(s.ttl.seen_window_s), AuditLog(s.resolve(s.paths.audit_log)))
    r = _reading(rid="nprov-1")
    r.pop("provenance")
    assert pipe.process(r).code == "PROVENANCE_MISSING"


def test_schema_invalid_is_400_never_500(tmp_path):
    c = _client(tmp_path)
    bad = _reading()
    bad.pop("result")
    r = c.post("/v1/readings", json=bad)
    assert r.status_code == 400
    assert r.json()["error"] == "SCHEMA_INVALID"


# --- 10-11: passport attacks (Twin-side checks) ------------------------------
def _passport_record():
    return VerdictRecord(evidence_digest="sha256:" + "a" * 64, reading_id="r-x",
                         zone="Z-PORT", sensor_id="port-gauge-1",
                         observed_property="water_level", disposition="SUSPECT",
                         trust=0.544, reason_codes=["CONFLICT"],
                         allowed_actions=["reversible", "precautionary"],
                         conditions=["require_second_source"], verified_at=0.0)


def test_expired_passport_rejected(tmp_path):
    s = load_settings()
    p = build_passport(_passport_record(), s, {"ttl": {"passport_s": 6}}, now=1_000.0)
    ok, reason = verify_passport(p, s, now=1_000.0 + 10.0)
    assert (ok, reason) == (False, "EXPIRED")


def test_tampered_passport_signature_rejected(tmp_path):
    s = load_settings()
    p = build_passport(_passport_record(), s, {"ttl": {"passport_s": 6}}, now=1_000.0)
    p["trust"] = 0.99                  # attacker edits the verdict after issuance
    ok, reason = verify_passport(p, s, now=1_000.0 + 1.0)
    assert (ok, reason) == (False, "SIG_INVALID")


def test_out_of_scope_action_refused_by_brain():
    """A SUSPECT passport authorises reversible/precautionary only: a full
    grid-disconnect — or any action outside the passport — is refused."""
    d = decide({"passport_id": "psp-x", "disposition": "SUSPECT",
                "allowed_actions": ["reversible", "precautionary"]},
               "grid.disconnect")
    assert d["decision"] == "refused"
    assert "full" in d["reason"]


# --- 12: lying actuator -> quarantine ----------------------------------------
def test_three_mismatches_quarantine_and_downgrade(tmp_path):
    c = _client(tmp_path)
    for i in range(3):
        r = c.post("/v1/witness", json={
            "action_id": f"a-q-{i}", "requested": "pump.on",
            "acknowledged": "applied", "observed": {"flow_sensor": "flat"},
            "result": "MISMATCH", "implicated_device": "river-gauge-1"})
        assert r.json()["code"] == "WITNESS_RECORDED"
    c.post("/v1/witness", json={
        "action_id": "a-q-3", "requested": "pump.on", "acknowledged": "applied",
        "result": "MATCH", "implicated_device": "river-gauge-1"})
    tail = [e for e in c.get("/v1/verdict?since=0").json()["events"]
            if e.get("event") == "witness.received"]
    assert tail and tail[-1]["quarantined"] is True
    # quarantined provenance can never authorise a full-commit again
    c.post("/v1/readings", json=_reading(rid="post-q", when=utcnow_iso()))
    ev = [e for e in c.get("/v1/verdict?since=0").json()["events"]
          if e.get("reading_id") == "post-q"][0]
    assert "full" not in c.post(
        "/v1/passport", json={"evidence_digest": ev["evidence_digest"]}).json()["allowed_actions"]


# --- latency floor + audit integrity -------------------------------------------
def test_ingest_latency_within_contractual_floor(tmp_path):
    c = _client(tmp_path)
    lat = []
    for i in range(50):
        t0 = time.perf_counter()
        assert c.post("/v1/readings", json=_reading(rid=f"lat-{i}", seq=i)).status_code == 200
        lat.append(time.perf_counter() - t0)
    lat.sort()
    p95 = lat[int(0.95 * len(lat))]
    assert max(lat) < 10.0, "slower than the 10s contractual floor"
    assert p95 < 0.300, f"p95 {p95:.3f}s exceeds the 300ms design target"


def test_audit_chain_survives_attacks_and_detects_tampering(tmp_path):
    c = _client(tmp_path, verify_sig=True)
    c.post("/v1/readings", json=_sign(_reading(rid="chain-1")))
    c.post("/v1/readings", json=_sign(_reading(rid="chain-1")))   # DUPLICATE
    ghost = _reading(rid="chain-ghost", sensor="ghost-1")
    c.post("/v1/readings", json=ghost)                            # UNKNOWN_DEVICE
    log = AuditLog(c.app.state.settings.resolve(
        c.app.state.settings.paths.audit_log))
    assert log.verify_chain() is True
    # flip one byte on disk -> the chain must catch it
    path = log.path
    raw = path.read_bytes()
    path.write_bytes(raw[:120] + (b"X" if raw[120:121] != b"X" else b"Y") + raw[121:])
    assert AuditLog(path).verify_chain() is False


def test_no_attack_returns_500(tmp_path):
    """Blanket guard: every denial above answered with a stable code, never a crash."""
    c = _client(tmp_path, verify_sig=True)
    bodies = [
        {"readings": "not-a-list"},
        {"no": "fields"},
        {"readings": [{"sensor_id": 123}]},
    ]
    for b in bodies:
        r = c.post("/v1/readings", json=b)
        assert r.status_code in (200, 400, 422), r.text
        assert r.status_code != 500


def test_no_full_commit_ever_dispatched_on_untrusted_passport(tmp_path):
    """The headline security invariant, asserted over a whole multi-scenario run.

    Per-request tests prove one gate at a time. This proves the CROSS-cutting
    claim the pitch and report both make: across every scenario, no full-class
    action is ever dispatched on a passport that was not TRUSTED. It joins the
    audit trail (passport.issued -> action.requested) the same way a jury would.

    A regression here is a serious safety regression, not a cosmetic one.
    """
    import json as _json
    client = _client(tmp_path / "invariant")
    shared = Path(__file__).resolve().parents[1] / "shared"
    keyring = Path(__file__).resolve().parents[1] / "keys" / "dev_keys.json"
    full_class = {"valve.full_open", "valve.full_close", "valve.open",
                  "valve.close", "pump.on", "grid.disconnect", "signal.override"}

    for fixture in ("calm_day_t1.json", "real_flood_t3.json", "muted_gauge_t4.json",
                    "fake_flood_t5.json", "spoof_gps_t6.json", "combined_t7.json"):
        assert client.post("/v1/run/new", json={}).status_code == 200
        with open(shared / "fixtures" / fixture, encoding="utf-8") as fh:
            readings = _json.load(fh)["readings"]
        for r in mock_twin.rebase_times(readings, keyring):
            client.post("/v1/readings", json=r)

    events = client.get("/v1/verdict?since=0").json()["events"]
    passports = {e["passport_id"]: e for e in events if e.get("event") == "passport.issued"}
    acted = [e for e in events if e.get("event") == "action.requested"]

    violations = []
    for a in acted:
        if a.get("action") in full_class:
            p = passports.get(a.get("passport_id"))
            if not p or p.get("disposition") != "TRUSTED":
                violations.append((a.get("action"), a.get("passport_id")))
    assert not violations, f"full-class commit on untrusted passport: {violations}"
