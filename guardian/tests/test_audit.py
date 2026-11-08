"""Audit log tests: append-only, hash-chained, tamper-evident, replayable (plan §11)."""
import json

from guardian.audit import AuditLog


def test_append_and_verify_chain(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append({"event": "reading.accepted", "sensor_id": "s1"})
    log.append({"event": "reading.rejected", "sensor_id": "s2"})
    assert log.verify_chain() is True
    assert len(log.read_since(0)) == 2


def test_read_since_filters(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    a = log.append({"event": "e1"})
    b = log.append({"event": "e2"})
    assert [e["seq"] for e in log.read_since(a["seq"])] == [b["seq"]]


def test_tamper_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append({"event": "e1"})
    log.append({"event": "e2"})
    # flip a value in the first record without fixing the chain
    lines = path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["sensor_id"] = "TAMPERED"
    lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    assert log.verify_chain() is False
