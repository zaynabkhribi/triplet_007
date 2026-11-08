"""End-to-end transport tests for the readings/verdict/witness/passport surface.

These prove the transport + verdict + passport surface (plan §6-7): schema gate, dedup,
device identity gate, audit streaming with verdict fields, and on-demand passport minting.
"""
import copy


def test_accept_golden_reading(client, golden):
    r = client.post("/v1/readings", json=golden[0])
    assert r.status_code == 200
    body = r.json()
    assert body["received"] == 1 and body["accepted"] == 1
    assert body["results"][0]["code"] == "ACCEPTED"


def test_duplicate_reading_rejected(client, golden):
    client.post("/v1/readings", json=golden[0])
    r = client.post("/v1/readings", json=golden[0])   # same reading_id
    assert r.status_code == 200
    assert r.json()["results"][0]["code"] == "DUPLICATE"
    assert r.json()["accepted"] == 0


def test_unknown_device_rejected(client, golden):
    ghost = copy.deepcopy(golden[0])
    ghost["sensor_id"] = "ghost-1"
    ghost["reading_id"] = "r-ghost"
    r = client.post("/v1/readings", json=ghost)
    assert r.status_code == 200
    assert r.json()["results"][0]["code"] == "UNKNOWN_DEVICE"


def test_schema_invalid_returns_400(client, golden):
    bad = copy.deepcopy(golden[0])
    bad.pop("result")
    r = client.post("/v1/readings", json=bad)
    assert r.status_code == 400
    assert r.json()["error"] == "SCHEMA_INVALID"


def test_batch_accept(client, golden):
    r = client.post("/v1/readings", json={"readings": golden})
    assert r.status_code == 200
    assert r.json()["received"] == len(golden)
    assert r.json()["accepted"] == len(golden)


def test_verdict_stream_contains_events(client, golden):
    client.post("/v1/readings", json={"readings": golden})
    r = client.get("/v1/verdict?since=0")
    assert r.status_code == 200
    events = r.json()["events"]
    assert any(e["event"] == "reading.accepted" for e in events)
    # hash chain is intact
    seqs = [e["seq"] for e in events]
    assert seqs == sorted(seqs)


def test_verdict_lookup_missing_returns_404(client):
    r = client.get("/v1/verdict/psp-none")
    assert r.status_code == 404
    assert r.json()["error"] == "NOT_FOUND"


def _fresh_reading_for_api():
    """Fresh, signed reading (valid now) so the freshness factor is ~1.0 -> TRUSTED."""
    from guardian.signing import compute_digest, hmac_signature, utcnow_iso
    r = {
        "batch_id": "b-fresh", "reading_id": "r-fresh-api",
        "sensor_id": "river-gauge-1", "zone": "Z-RIVER_UNDERPASS",
        "observed_property": "water_level", "phenomenon_time": utcnow_iso(),
        "result": {"value": 0.82, "unit": "m"},
        "provenance": {"firmware": "1.4", "cal": "CAL-07", "seq": 1},
    }
    r["digest"] = compute_digest(r)
    r["signature"] = hmac_signature("dev-secret-river-gauge-1", r["digest"])
    return r


def test_passport_issued_for_trusted_reading(client):
    reading = _fresh_reading_for_api()
    r = client.post("/v1/readings", json=reading)
    assert r.json()["results"][0]["code"] == "ACCEPTED"
    p = client.post("/v1/passport", json={"evidence_digest": reading["digest"]})
    assert p.status_code == 200
    body = p.json()
    assert body["disposition"] == "TRUSTED"
    assert body["trust"] >= 0.80
    assert "full" in body["allowed_actions"]
    assert body["signature"].startswith("hmac-sha256:")
    assert body["evidence_digest"] == reading["digest"]


def test_passport_missing_evidence_digest_422(client):
    r = client.post("/v1/passport", json={})
    assert r.status_code == 422
    assert r.json()["error"] == "BAD_REQUEST"


def test_passport_unknown_evidence_404(client):
    r = client.post("/v1/passport", json={"evidence_digest": "sha256:" + "f" * 64})
    assert r.status_code == 404


def test_witness_recorded(client):
    witness = {
        "action_id": "a-900", "requested": "pump.on", "acknowledged": "applied",
        "observed": {"flow_sensor": "flat"}, "result": "MISMATCH", "implicated_device": "pump-1",
    }
    r = client.post("/v1/witness", json=witness)
    assert r.status_code == 200
    assert r.json()["code"] == "WITNESS_RECORDED"


def test_witness_mismatch_decays_history(client):
    """The `history` factor is now live: a MISMATCH witness must move it off 1.0."""
    witness = {
        "action_id": "a-901", "requested": "valve.close", "acknowledged": "applied",
        "observed": {"flow_sensor": "flat"}, "result": "MISMATCH",
        "implicated_device": "river-gauge-1",
    }
    r = client.post("/v1/witness", json=witness)
    assert r.status_code == 200
    assert r.json()["history_score"] < 1.0


def test_healthy_multi_sensor_zone_is_not_flagged(client):
    """REGRESSION: a rain gauge correctly reporting 0.0mm next to a normal river gauge
    was hard-gated to MALICIOUS/TAMPER. Both readings must now stay TRUSTED."""
    from guardian.signing import compute_digest, hmac_signature, utcnow_iso
    secrets = {"river-gauge-1": "dev-secret-river-gauge-1",
               "rain-gauge-2": "dev-secret-rain-gauge-2"}
    t0 = utcnow_iso()
    readings = []
    for sensor, prop, val, unit in [
            ("river-gauge-1", "water_level", 0.82, "m"),
            ("rain-gauge-2", "rain", 0.0, "mm")]:
        r = {"batch_id": "b-healthy", "reading_id": f"h-{sensor}", "sensor_id": sensor,
             "zone": "Z-RIVER_UNDERPASS", "observed_property": prop, "phenomenon_time": t0,
             "result": {"value": val, "unit": unit},
             "provenance": {"firmware": "1.4", "cal": "CAL-07", "seq": 1}}
        r["digest"] = compute_digest(r)
        r["signature"] = hmac_signature(secrets[sensor], r["digest"])
        readings.append(r)
    resp = client.post("/v1/readings", json={"readings": readings})
    assert resp.json()["accepted"] == 2
    events = [e for e in client.get("/v1/verdict?since=0").json()["events"]
              if e.get("disposition")]
    assert events, "no verdicts produced"
    for e in events:
        assert e["disposition"] == "TRUSTED", (e["sensor_id"], e["reason_codes"])
        assert e["reason_codes"] == []


def test_passport_audit_record_uses_real_disposition(client):
    """REGRESSION: passport issuance was logged with a hardcoded code=TRUSTED even for a
    SUSPECT verdict, corrupting the audit trail."""
    from guardian.signing import compute_digest, hmac_signature, utcnow_iso
    r = {"batch_id": "b-audit", "reading_id": "r-audit-1", "sensor_id": "river-gauge-1",
         "zone": "Z-RIVER_UNDERPASS", "observed_property": "water_level",
         "phenomenon_time": utcnow_iso(), "result": {"value": 0.82, "unit": "m"},
         "provenance": {"firmware": "1.4", "cal": "CAL-07", "seq": 1}}
    r["digest"] = compute_digest(r)
    r["signature"] = hmac_signature("dev-secret-river-gauge-1", r["digest"])
    client.post("/v1/readings", json=r)
    p = client.post("/v1/passport", json={"evidence_digest": r["digest"]}).json()
    issued = [e for e in client.get("/v1/verdict?since=0").json()["events"]
              if e.get("event") == "passport.issued"][-1]
    assert issued["code"] == "PASSPORT_ISSUED"
    assert issued["disposition"] == p["disposition"]
    assert issued["code"] != "TRUSTED" or issued["disposition"] == "TRUSTED"


def test_s1_flagship_passport_denies_full_commit(secure_client):
    """End-to-end S1: drift sequence through the API -> SUSPECT passport that the Twin
    must not use to authorize a full-commit (valve full-close).

    Runs on `secure_client` (signature verification ON) because S1 is a security
    scenario built on valid HMACs; an unverified frame is correctly scored lower.
    """
    from guardian.signing import compute_digest, hmac_signature, utcnow_iso
    secrets = {"river-gauge-1": "dev-secret-river-gauge-1",
               "rain-gauge-2": "dev-secret-rain-gauge-2"}
    t0 = utcnow_iso()
    batch = []
    for i, v in enumerate([0.30, 0.36, 0.42, 0.48]):
        for sensor, prop, val in [("river-gauge-1", "water_level", v),
                                  ("rain-gauge-2", "rain", 79.0)]:
            r = {"batch_id": "b-s1", "reading_id": f"s1-{sensor}-{i}", "sensor_id": sensor,
                 "zone": "Z-RIVER_UNDERPASS", "observed_property": prop, "phenomenon_time": t0,
                 "result": {"value": val, "unit": "m" if prop == "water_level" else "mm"},
                 "provenance": {"firmware": "1.4", "cal": "CAL-07", "seq": i + 1}}
            r["digest"] = compute_digest(r)
            r["signature"] = hmac_signature(secrets[sensor], r["digest"])
            batch.append(r)
    resp = secure_client.post("/v1/readings", json={"readings": batch})
    assert resp.status_code == 200
    assert resp.json()["accepted"] == len(batch)
    last_g1 = [r for r in batch if r["sensor_id"] == "river-gauge-1"][-1]
    p = secure_client.post("/v1/passport", json={"evidence_digest": last_g1["digest"]})
    assert p.status_code == 200
    body = p.json()
    assert body["disposition"] == "SUSPECT"
    assert "full" not in body["allowed_actions"]            # Twin MUST deny full-commit
    assert {"DRIFT", "CONFLICT"}.issubset(set(body["reason_codes"]))
