"""Reading integrity + signing for the Guardian (plan §8 — Security & Trust).

The default is **HMAC-SHA256** (Python stdlib only, no extra dependency). The
production target is per-device **Ed25519** — documented here, wired later behind
this same interface. The wire format is ``hmac-sha256:<hex>`` so partners can
migrate to ``ed25519:<b64>`` without a schema change.

Integrity model:
  * ``digest``     = sha256 over the canonical body (reading minus digest/signature)
                     — binds the reading's *content*.
  * ``signature``  = HMAC(secret, digest) — binds that content hash to the device key.

``verify_reading_integrity`` checks BOTH: a tampered value changes the recomputed
digest (DIGEST_MISMATCH), and a wrong/missing key breaks the MAC (SIG_MISMATCH /
NO_SECRET). This is why "signature valid but value pinned" (TAMPER) is caught even
when an attacker replays a valid signature.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Tuple

# fields excluded from the canonical body (the digest/signature cover everything else)
_EXCLUDED = ("digest", "signature")


def canonical_body(raw: dict) -> bytes:
    body = {k: v for k, v in raw.items() if k not in _EXCLUDED}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_digest(raw: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical_body(raw)).hexdigest()


def hmac_signature(secret: str, digest: str) -> str:
    mac = hmac.new(str(secret).encode("utf-8"), str(digest).encode("utf-8"), hashlib.sha256).hexdigest()
    return "hmac-sha256:" + mac


def verify_reading_integrity(raw: dict, secret) -> Tuple[bool, str]:
    """Return (ok, reason). reason ∈ {OK, DIGEST_MISMATCH, SIG_MISMATCH, NO_SECRET}."""
    if compute_digest(raw) != str(raw.get("digest", "")):
        return False, "DIGEST_MISMATCH"
    if not secret:
        return False, "NO_SECRET"
    expected = hmac_signature(str(secret), str(raw.get("digest", "")))
    if hmac.compare_digest(str(raw.get("signature", "")), expected):
        return True, "OK"
    return False, "SIG_MISMATCH"


def parse_iso(ts: str) -> float:
    """ISO-8601 (with 'Z' or offset) -> epoch seconds. Naive timestamps assumed UTC."""
    s = str(ts).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def derive_reading_id(raw: dict) -> str:
    """Stable reading id: explicit `reading_id`, else a short hash of identity fields."""
    rid = raw.get("reading_id")
    if rid:
        return str(rid)
    key = "|".join(
        str(raw.get(k, ""))
        for k in ("batch_id", "sensor_id", "observed_property", "phenomenon_time", "digest")
    )
    return "rid-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def iso_from_epoch(epoch_s: float) -> str:
    """Epoch seconds -> the same ISO-8601 'Z' form `utcnow_iso` emits.

    Exists so anything that needs a deterministic clock (passport issuance in tests,
    fixture re-stamping in the mock Twin) produces byte-identical formatting.
    """
    return datetime.fromtimestamp(float(epoch_s), tz=timezone.utc).isoformat().replace("+00:00", "Z")
