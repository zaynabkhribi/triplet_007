"""Stable, machine-readable error taxonomy.

Partners switch on `code`, never on prose. Stack traces are never leaked to the
wire (plan §12: clean error taxonomy).
"""
from __future__ import annotations

from typing import Dict, Optional

# --- Stage A reject codes (plan §6.1) ---
SCHEMA_INVALID = "SCHEMA_INVALID"
SIG_INVALID = "SIG_INVALID"
DIGEST_MISMATCH = "DIGEST_MISMATCH"
NO_SECRET = "NO_SECRET"
DUPLICATE = "DUPLICATE"
UNKNOWN_DEVICE = "UNKNOWN_DEVICE"
STALE = "STALE"
PROVENANCE_MISSING = "PROVENANCE_MISSING"

# --- Transport / API ---
BAD_REQUEST = "BAD_REQUEST"
NOT_FOUND = "NOT_FOUND"
INTERNAL_ERROR = "INTERNAL_ERROR"

# --- Detector flags (plan §6.2) — emitted by the pipeline (Day 3-6) ---
DRIFT = "DRIFT"
SPOOF = "SPOOF"
JAM = "JAM"
REPLAY = "REPLAY"
MISMATCH = "MISMATCH"
RATE_ANOMALY = "RATE_ANOMALY"
OUT_OF_RANGE = "OUT_OF_RANGE"
TAMPER = "TAMPER"
IMPLAUSIBLE = "IMPLAUSIBLE"
CONFLICT = "CONFLICT"

# --- Accept codes ---
ACCEPTED = "ACCEPTED"
WITNESS_RECORDED = "WITNESS_RECORDED"
PASSPORT_ISSUED = "PASSPORT_ISSUED"

# --- Effect-witness outcome codes (drive history decay + quarantine, plan §11) ---
EFFECT_MATCH = "MATCH"
EFFECT_MISMATCH = "MISMATCH"


class GuardianError(Exception):
    """Base error carrying a stable code, a safe message, an HTTP status, and details."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        http_status: int = 400,
        details: Optional[Dict] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.details = details or {}

    def to_dict(self) -> Dict:
        return {"error": self.code, "message": self.message, "details": self.details}
