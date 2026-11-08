"""T5 canonical path — fake flood at the port, end to end (spec §09 example).

Twin streams 180cm fake (true 40cm hidden) + dry rain + calm camera.
Guardian MUST mark it untrusted; Brain MUST refuse valve.full_open.
Runs the FULL stack (transport -> pipeline -> passport -> decide) with the
production posture (signatures + freshness enforced).
"""
import json
from pathlib import Path

from fastapi.testclient import TestClient

from guardian.mock import mock_twin
from guardian.mock.mock_brain import decide

SHARED = Path(__file__).resolve().parents[1] / "shared"


def _load(name):
    with open(SHARED / "fixtures" / name, encoding="utf-8") as fh:
        return json.load(fh)["readings"]


def test_t5_fixture_schema_valid():
    from guardian.schemas import validate
    for r in _load("fake_flood_t5.json"):
        ok, errs = validate(r, "reading")
        assert ok, [str(e.message) for e in errs]


def test_t5_gauge_untrusted_and_contains_conflict(secure_client):
    c = secure_client
    readings = mock_twin.rebase_times(_load("fake_flood_t5.json"),
                                      Path("keys/dev_keys.json"))
    for r in readings:
        resp = c.post("/v1/readings", json=r)
        assert resp.status_code == 200, resp.text
        assert resp.json()["results"][0]["accepted"] is True
    data = c.get("/v1/verdict?since=0").json()
    gauge_evs = [e for e in data["events"] if e.get("sensor_id") == "port-gauge-1"]
    final = gauge_evs[-1]
    assert final["reading_id"] == "t5-port-gauge-1-0", final
    assert final["disposition"] in ("SUSPECT", "MALICIOUS", "RESTRICT"), final
    assert "CONFLICT" in final["reason_codes"], final
    assert final["trust"] is not None and final["trust"] < 0.80, final


def test_t5_passport_carries_no_full_and_brain_refuses(secure_client):
    c = secure_client
    readings = mock_twin.rebase_times(_load("fake_flood_t5.json"),
                                      Path("keys/dev_keys.json"))
    calm = [r for r in readings if r["batch_id"] == "b-t5-calm"]
    attack = [r for r in readings if r["batch_id"] == "b-t5-fake"]
    gauge = next(r for r in attack if r["sensor_id"] == "port-gauge-1")
    for r in calm + [x for x in attack if x["reading_id"] != gauge["reading_id"]] + [gauge]:
        assert c.post("/v1/readings", json=r).status_code == 200
    data = c.get("/v1/verdict?since=0").json()
    verdict = next(e for e in data["events"] if e.get("reading_id") == gauge["reading_id"])
    assert verdict["disposition"] in ("SUSPECT", "MALICIOUS", "RESTRICT"), verdict
    assert "CONFLICT" in verdict["reason_codes"], verdict
    assert verdict.get("evidence_digest") == gauge["digest"], verdict
    p = c.post("/v1/passport", json={"evidence_digest": verdict["evidence_digest"]}).json()
    assert "full" not in p["allowed_actions"], p
    d = decide(p, "valve.full_open", "barrier.partial_close")
    assert d["decision"] == "refused" and d["fallback"] == "barrier.partial_close"


def test_decision_and_action_endpoints_feed_timeline(client):
    c: TestClient = client
    s, b = c.post("/v1/decision", json={"decision": "refused", "sensor_id": "x",
                                        "reason": "not in allowed_actions"}), None
    assert s.status_code == 200 and s.json()["code"] == "DECISION"
    b = c.post("/v1/action", json={"action_id": "a-1",
                                   "action": "barrier.partial_close",
                                   "result": "requested"})
    assert b.status_code == 200 and b.json()["code"] == "ACTION"
    events = c.get("/v1/verdict?since=0").json()["events"]
    kinds = {e["event"] for e in events}
    assert "decision.refused" in kinds and "action.requested" in kinds


def test_s1_still_suspect_with_new_coupling(secure_client):
    """Guard: the dry-catchment rule must not break the S1 flagship."""
    c = secure_client
    readings = mock_twin.rebase_times(_load("drift_attack.json"),
                                      Path("keys/dev_keys.json"))
    for r in readings:
        assert c.post("/v1/readings", json=r).status_code == 200
    gauges = [e for e in c.get("/v1/verdict?since=0").json()["events"]
              if e.get("sensor_id") == "river-gauge-1"]
    assert gauges and gauges[-1]["disposition"] == "SUSPECT", gauges[-1] if gauges else None


def test_unknown_action_fails_closed():
    """Fail closed: a novel actuation the map never saw needs TRUSTED."""
    from guardian.mock.mock_brain import decide
    d = decide({"passport_id": "psp-x", "disposition": "SUSPECT",
                "allowed_actions": ["reversible", "precautionary"]},
               " railgun.fire")
    assert d["decision"] == "refused"
    ok = decide({"passport_id": "psp-x", "disposition": "TRUSTED",
                 "allowed_actions": ["full", "reversible", "precautionary"]},
                " railgun.fire".strip())
    assert ok["decision"] == "proposed"
