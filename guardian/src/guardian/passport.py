"""Evidence Passport construction + signing (plan §6.5, §8 scope+expiry).

A passport binds an authorization to: zone + evidence_digest + policy_version +
disposition + the derived `allowed_actions` + TTL. It is short-lived (5-7s) and
signed with the Guardian's service HMAC key (Ed25519 is the production target).
The signature covers the canonical body (passport minus `signature`) so any
tampering invalidates it — which is what lets the Twin trust a passport it
receives.

`verify_passport` checks BOTH signature integrity AND TTL expiry, so a replayed
or stale passport is rejected even if its bytes are intact.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .signing import iso_from_epoch, parse_iso, utcnow_iso


@dataclass
class VerdictRecord:
    """A stored trust verdict, keyed by evidence_digest (for on-demand passports)."""
    evidence_digest: str
    reading_id: str
    zone: str
    sensor_id: str
    observed_property: str
    disposition: str
    trust: float
    reason_codes: List[str] = field(default_factory=list)
    factors: Dict[str, float] = field(default_factory=dict)
    conflict: float = 0.0
    verified_at: float = 0.0
    policy_version: str = "v1.0"
    allowed_actions: List[str] = field(default_factory=list)
    conditions: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    passport_id: Optional[str] = None


def _service_key(settings) -> bytes:
    k = os.environ.get(settings.auth.key_env_var)
    if not k:
        k = "dev-guardian-service-key"  # dev default; NEVER in prod (plan §8 secrets)
    return k.encode("utf-8")


def _canonical(obj: dict) -> bytes:
    body = {k: v for k, v in obj.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _passport_id_for(evidence_digest: str, zone: str) -> str:
    h = hashlib.sha256((evidence_digest + "|" + zone).encode("utf-8")).hexdigest()
    return "psp-" + h[:8]


def build_passport(record: VerdictRecord, settings, policy: dict, *,
                   now: Optional[float] = None) -> Dict[str, object]:
    """Build and sign a passport from a stored verdict (plan §6.5).

    `now` is honoured when supplied so issuance is deterministic under test; it
    defaults to the wall clock. The signature covers the canonical body (everything
    except `signature`), so any later edit invalidates the passport.
    """
    ttl = int(policy.get("ttl", {}).get("passport_s", settings.ttl.passport_s))
    issued_at = iso_from_epoch(now) if now is not None else utcnow_iso()
    passport = {
        "passport_id": record.passport_id or _passport_id_for(record.evidence_digest, record.zone),
        "issued_at": issued_at,
        "ttl_s": ttl,
        "zone": record.zone,
        "disposition": record.disposition,
        "trust": record.trust,
        "reason_codes": list(record.reason_codes),
        "evidence_digest": record.evidence_digest,
        "source_ids": list(record.source_ids),
        "policy_version": policy.get("policy_version", record.policy_version),
        "allowed_actions": list(record.allowed_actions),
        "conditions": list(record.conditions),
        "signature": "",
    }
    passport["signature"] = sign_passport(passport, settings)
    return passport


def sign_passport(passport: dict, settings) -> str:
    return "hmac-sha256:" + hmac.new(_service_key(settings), _canonical(passport), hashlib.sha256).hexdigest()


def verify_passport(passport: dict, settings, *, now: Optional[float] = None) -> Tuple[bool, str]:
    """Signature + expiry. (Twin calls this before acting on a Proof-Carrying Action.)"""
    sig = str(passport.get("signature", ""))
    expected = sign_passport(passport, settings)
    if not hmac.compare_digest(sig, expected):
        return False, "SIG_INVALID"
    if is_expired(passport, now=now):
        return False, "EXPIRED"
    return True, "OK"


def is_expired(passport: dict, *, now: Optional[float] = None) -> bool:
    """True once `age >= ttl_s` — validity is the half-open interval [issued, issued+ttl).

    Using >= (not >) means a passport is never valid for a full extra instant at the
    boundary; at exactly ttl_s it is already expired.
    """
    issued = parse_iso(str(passport.get("issued_at", "")))
    ttl = float(passport.get("ttl_s", 0))
    if now is None:
        now = parse_iso(utcnow_iso())
    return (now - issued) >= ttl
