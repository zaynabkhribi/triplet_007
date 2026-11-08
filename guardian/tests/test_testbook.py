"""Test Book bands T1-T7 (report Part 4 / TESTBOOK.md, Phase 1 spec §Test Book).

Every scenario fixture ships a *calibrated* verdict band. These tests pin the
bands so a future detector or policy edit cannot silently move a scenario:
T1/T2/T3 stay TRUSTED, T4 lands MALICIOUS/TAMPER, T6 lands MALICIOUS/SPOOF,
T7 keeps its per-zone split (industrial TRUSTED, port surge SUSPECT), T5 keeps
its canonical form (untrusted + CONFLICT).

Runs in the production posture (signatures ON) with rebased timestamps, the
same surface `run scenario <id>` exercises live.
"""
import json
from pathlib import Path

import pytest

from guardian.mock import mock_twin
from guardian.mock.mock_brain import decide

SHARED = Path(__file__).resolve().parents[1] / "shared"
# Absolute: `rebase_times` re-signs only when the keyring resolves, and old
# tests assume pytest runs from guardian/. An absolute path works from anywhere.
KEYRING = Path(__file__).resolve().parents[1] / "keys" / "dev_keys.json"

BOOK = {
    # id: (fixture, focus sensor, focus reading, expected dispositions, must-have flags)
    "t1": ("calm_day_t1.json", "river-gauge-1", None, {"TRUSTED"}, ()),
    "t2": ("rush_hour_t2.json", "traffic-cam-1", None, {"TRUSTED"}, ()),
    "t3": ("real_flood_t3.json", "river-gauge-1", None, {"TRUSTED"}, ()),
    "t4": ("muted_gauge_t4.json", "river-gauge-1", "t4-river-mute", {"MALICIOUS"}, ("TAMPER",)),
    "t5": ("fake_flood_t5.json", "port-gauge-1", "t5-port-gauge-1-0",
           {"SUSPECT", "MALICIOUS", "RESTRICT"}, ("CONFLICT",)),
    "t6": ("spoof_gps_t6.json", "fleet-gps-1", "t6-gps-2", {"MALICIOUS"}, ("SPOOF",)),
    "t7": ("combined_t7.json", "port-gauge-1", "t7-port-surge",
           {"SUSPECT", "MALICIOUS", "RESTRICT"}, ("CONFLICT",)),
}


def _fresh_secure_client(tmp_path):
    """One server run per scenario — mirrors `run scenario <id>` (fresh process).

    The pipeline keeps per-zone/per-device context windows, so streaming two
    fixtures into one client would let T1's frames corroborate (or fight) T2's.
    """
    import dataclasses
    from fastapi.testclient import TestClient
    from guardian.api import create_app
    from guardian.config import load_settings
    s = load_settings()
    s = dataclasses.replace(
        s,
        auth=dataclasses.replace(s.auth, verify_signatures=True),
        paths=dataclasses.replace(s.paths, audit_log=str(tmp_path / "tb.jsonl")),
    )
    return TestClient(create_app(s))


def _stream(client, fixture):
    with open(SHARED / "fixtures" / fixture, encoding="utf-8") as fh:
        readings = json.load(fh)["readings"]
    rebased = mock_twin.rebase_times(readings, KEYRING)
    for r in rebased:
        resp = client.post("/v1/readings", json=r)
        assert resp.status_code == 200, resp.text
        assert resp.json()["results"][0]["code"] == "ACCEPTED", r["reading_id"]
    return {e.get("reading_id"): e
            for e in client.get("/v1/verdict?since=0").json()["events"]
            if e.get("event") == "reading.accepted"}


@pytest.mark.parametrize("tid", sorted(BOOK))
def test_testbook_focus_verdict_band(tmp_path, tid):
    """Each scenario's focus frame lands in its calibrated band with its flags."""
    client = _fresh_secure_client(tmp_path / tid)
    fixture, sensor, reading_id, bands, flags = BOOK[tid]
    verdicts = _stream(client, fixture)
    ev = verdicts[reading_id] if reading_id else \
        next(e for e in reversed(list(verdicts.values())) if e.get("sensor_id") == sensor)
    assert ev["sensor_id"] == sensor, ev
    assert ev["disposition"] in bands, (tid, ev)
    for flag in flags:
        assert flag in ev["reason_codes"], (tid, ev)
    if ev["disposition"] != "TRUSTED":
        assert ev["trust"] is not None and ev["trust"] < 0.80, (tid, ev)


def test_t1_t2_t3_all_frames_trusted(tmp_path):
    for tid in ("t1", "t2", "t3"):
        fixture, _, _, _, _ = BOOK[tid]
        for rid, ev in _stream(_fresh_secure_client(tmp_path / tid), fixture).items():
            assert ev["disposition"] == "TRUSTED", (tid, rid, ev)


def test_t7_per_zone_split(tmp_path):
    """T7: industrial heat TRUSTED, hospital TRUSTED, port surge untrusted."""
    verdicts = _stream(_fresh_secure_client(tmp_path / "t7"), "combined_t7.json")
    zones = {}
    for ev in verdicts.values():
        zones.setdefault(ev["zone"], []).append(ev["disposition"])
    assert set(zones["Z-INDUSTRIAL"]) == {"TRUSTED"}, zones
    assert set(zones["Z-HOSPITAL"]) == {"TRUSTED"}, zones
    surge = verdicts["t7-port-surge"]
    assert surge["disposition"] in {"SUSPECT", "MALICIOUS", "RESTRICT"}, surge


def test_t1_t2_t3_passports_carry_full(tmp_path):
    """Healthy evidence authorises full-commit; T4/T5/T6/T7 focus passports never do."""
    for tid, (fixture, sensor, reading_id, bands, _) in BOOK.items():
        client = _fresh_secure_client(tmp_path / tid)
        verdicts = _stream(client, fixture)
        ev = verdicts[reading_id] if reading_id else \
            next(e for e in reversed(list(verdicts.values())) if e.get("sensor_id") == sensor)
        p = client.post("/v1/passport",
                        json={"evidence_digest": ev["evidence_digest"]})
        assert p.status_code == 200, (tid, p.text)
        body = p.json()
        if "TRUSTED" in bands and len(bands) == 1:
            assert "full" in body["allowed_actions"], (tid, body)
        else:
            assert "full" not in body["allowed_actions"], (tid, body)


def test_testbook_brain_behavior_matches_run_scenario(tmp_path):
    """The Brain stand-in's decisions mirror the scenario book's expected table.

    (Inlined, so tests need no scenario driver: the driver is for humans and a
    stage demo, the expectations are the contract.)
    """
    EXPECTED = {
        "t1": dict(disposition="TRUSTED", decision="proposed"),
        "t2": dict(disposition="TRUSTED", decision="proposed"),
        "t3": dict(disposition="TRUSTED", decision="proposed"),
        "t4": dict(disposition="MALICIOUS", reasons=["TAMPER"], decision="refused"),
        "t5": dict(disposition=("SUSPECT", "MALICIOUS", "RESTRICT"), reasons=["CONFLICT"], decision="refused"),
        "t6": dict(disposition="MALICIOUS", reasons=["SPOOF"], decision="refused"),
        "t7": dict(disposition=("SUSPECT", "MALICIOUS", "RESTRICT"), reasons=["CONFLICT"], decision="refused"),
    }
    for tid, (fixture, sensor, reading_id, _bands, _) in BOOK.items():
        client = _fresh_secure_client(tmp_path / tid)
        verdicts = _stream(client, fixture)
        ev = verdicts[reading_id] if reading_id else \
            next(e for e in reversed(list(verdicts.values())) if e.get("sensor_id") == sensor)
        p = client.post("/v1/passport",
                        json={"evidence_digest": ev["evidence_digest"]}).json()
        assert p["disposition"] in (EXPECTED[tid]["disposition"] if isinstance(EXPECTED[tid]["disposition"], tuple) else (EXPECTED[tid]["disposition"],)), (tid, p)
        for reason in EXPECTED[tid].get("reasons", ()):
            assert reason in p["reason_codes"], (tid, p)
        req = {"t1": "signal.hold", "t2": "signal.hold", "t3": "valve.full_close",
               "t4": "valve.full_open", "t5": "valve.full_open",
               "t6": "route.priority", "t7": "valve.full_open"}[tid]
        d = decide(p, req, "barrier.partial_close")
        assert d["decision"] == EXPECTED[tid]["decision"], (tid, d)
        # T3 and T5 are the two halves of the same rule: T3's TRUSTED passport must
        # permit the irreversible full close, T5's SUSPECT passport must not.
        if tid == "t3":
            assert d["action"] == "valve.full_close", d
        if tid == "t5":
            assert d["decision"] == "refused" and d.get("fallback"), d


def test_scenario_replay_is_repeatable_on_one_server(tmp_path):
    """R2 regression: re-running a scenario must not report DUPLICATE.

    The stage demo re-runs T5 for the jury, often right after a rehearsal. The
    audit log is append-only and outlives the run, so without a run boundary the
    dedup window and sequence watermarks from run N make run N+1 fail every
    frame as DUPLICATE and the Brain judge a city it never saw. `POST
    /v1/run/new` (what `run scenario` calls first) must restore byte-identical
    behaviour.
    """
    client = _fresh_secure_client(tmp_path / "replay")
    with open(SHARED / "fixtures" / "fake_flood_t5.json", encoding="utf-8") as fh:
        readings = json.load(fh)["readings"]

    def run_once():
        assert client.post("/v1/run/new", json={}).status_code == 200
        since = client.get("/v1/cursor").json()["head_seq"]
        for r in mock_twin.rebase_times(readings, KEYRING):
            resp = client.post("/v1/readings", json=r)
            assert resp.json()["results"][0]["code"] == "ACCEPTED", r["reading_id"]
        return [e for e in client.get(f"/v1/verdict?since={since}").json()["events"]
                if e.get("event") == "reading.accepted"]

    first, second = run_once(), run_once()
    assert len(first) == len(second) == len(readings)
    # Same dispositions and same reason codes: the verdict is a function of the
    # evidence, not of what the server happened to see earlier. These are the
    # contract — the report's Part 5 says exactly this.
    assert [e["disposition"] for e in first] == [e["disposition"] for e in second]
    assert [e["reason_codes"] for e in first] == [e["reason_codes"] for e in second]

    # Trust is NOT bit-identical, and must not be asserted as such. Freshness is
    # scored from the age of the frame at verification time (weight 0.10 over a
    # 7 s TTL), so two replays that straddle a second boundary legitimately differ
    # in the third decimal: observed 0.612 vs 0.611 on this fixture. The bands are
    # the contract, not the decimals (report Part 5, reproducibility).
    for a, b in zip(first, second):
        assert a["trust"] == pytest.approx(b["trust"], abs=0.02), (a["trust"], b["trust"])

    assert second[-1]["disposition"] in {"SUSPECT", "MALICIOUS", "RESTRICT"}
    assert "CONFLICT" in second[-1]["reason_codes"]
