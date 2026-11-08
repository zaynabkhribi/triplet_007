"""Append-only, hash-chained JSONL audit log (plan §11).

Every reading, verdict, passport, action and witness is appended here. The chain is
tamper-evident (each record commits to the previous hash) and fully replayable:
`make replay id=S1` re-feeds a stored batch and asserts byte-identical verdicts.

Determinism note: `ts` is wall-clock (allowed — only SCORING must avoid wall-clock);
verdicts never depend on it.
"""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

_LOCK = threading.Lock()
_GENESIS = "0" * 64


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _chain_hash(prev_hash: str, record: Dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k not in ("prev_hash", "hash")}
    return hashlib.sha256((prev_hash + "|" + _canonical(body)).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_hash = self._load_last_hash()
        self._seq = self._count_records()

    # -- internals --
    def _load_last_hash(self) -> str:
        last = _GENESIS
        if not self.path.exists():
            return last
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    last = json.loads(line).get("hash", last)
                except json.JSONDecodeError:
                    continue
        return last

    def _count_records(self) -> int:
        if not self.path.exists():
            return 0
        n = 0
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    n += 1
        return n

    # -- public API --
    def append(self, event: Dict[str, Any]) -> Dict[str, Any]:
        with _LOCK:
            record = dict(event)
            record.setdefault("ts", _utcnow_iso())
            self._seq += 1
            record["seq"] = self._seq
            record["prev_hash"] = self._prev_hash
            record["hash"] = _chain_hash(self._prev_hash, record)
            self._prev_hash = record["hash"]
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(_canonical(record) + "\n")
            return record

    def read_since(self, since_seq: int = 0) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not self.path.exists():
            return out
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if int(rec.get("seq", 0)) > since_seq:
                    out.append(rec)
        return out

    def verify_chain(self) -> bool:
        prev = _GENESIS
        if not self.path.exists():
            return True
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    return False
                if rec.get("prev_hash") != prev:
                    return False
                if _chain_hash(prev, rec) != rec.get("hash"):
                    return False
                prev = rec.get("hash", prev)
        return True
