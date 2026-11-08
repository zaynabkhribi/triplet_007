"""6-factor trust score, hard gates, disposition, and allowed_actions (plan §3, §6.3).

Canonical v1. Weights, conflict penalty, thresholds and hard flags are **loaded from
policy.yaml** — the single source of truth (plan §3). This module computes from the
policy and never re-declares a tunable: re-calibrating `policy.yaml` changes verdicts
with no code edit. `policy_version` is stamped on every passport so a verdict is
reproducible against the exact policy that produced it.

  T = sum(weight_f * factor_f) - conflict_penalty * conflict

Hard gates: TAMPER/SPOOF/REPLAY -> MALICIOUS (override the disposition entirely, and
cap `trust` at `malicious_trust_ceiling` so a MALICIOUS verdict can never numerically
outrank a SUSPECT one).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Tuple

from .detectors import DetectionResult, DetectorContext
from .errors import TAMPER, SPOOF, REPLAY  # noqa: F401 (documented hard flags)
from .signing import parse_iso

# Canonical factor order — also the report order on every passport.
FACTOR_NAMES: Tuple[str, ...] = (
    "corroboration", "consistency", "plausibility",
    "provenance", "freshness", "history",
)

# v1 defaults, used ONLY when policy.yaml is absent or omits a key. They mirror
# policy.yaml v1 exactly; `ScoringPolicy.from_policy` prefers the file, so a policy
# edit always wins. Kept here so the module still imports without a config.
_FALLBACK_WEIGHTS: Dict[str, float] = {
    "corroboration": 0.30, "consistency": 0.20, "plausibility": 0.18,
    "provenance": 0.12, "freshness": 0.10, "history": 0.10,
}
_FALLBACK_CONFLICT_PENALTY = 0.25
_FALLBACK_TRUSTED = 0.80
_FALLBACK_SUSPECT = 0.50
_FALLBACK_MALICIOUS_CEILING = 0.49
_FALLBACK_HARD: Tuple[str, ...] = ("TAMPER", "SPOOF", "REPLAY")


@dataclass(frozen=True)
class ScoringPolicy:
    """The scoring tunables, read from policy.yaml (plan §3)."""

    weights: Dict[str, float]
    conflict_penalty: float
    trusted_threshold: float
    suspect_threshold: float
    malicious_trust_ceiling: float
    hard_malicious: FrozenSet[str]

    @classmethod
    def from_policy(cls, policy: Optional[dict]) -> "ScoringPolicy":
        """Build from a parsed policy.yaml. Missing keys fall back to v1 defaults."""
        policy = policy or {}
        raw_weights = policy.get("weights", {}) or {}
        thresholds = policy.get("thresholds", {}) or {}
        hard = policy.get("hard_flags", {}).get("malicious") or _FALLBACK_HARD
        return cls(
            weights={name: float(raw_weights.get(name, _FALLBACK_WEIGHTS[name]))
                     for name in FACTOR_NAMES},
            conflict_penalty=float(policy.get("conflict_penalty", _FALLBACK_CONFLICT_PENALTY)),
            trusted_threshold=float(thresholds.get("trusted", _FALLBACK_TRUSTED)),
            suspect_threshold=float(thresholds.get("suspect", _FALLBACK_SUSPECT)),
            malicious_trust_ceiling=float(
                thresholds.get("malicious_trust_ceiling", _FALLBACK_MALICIOUS_CEILING)),
            hard_malicious=frozenset(str(f) for f in hard),
        )

    def validate(self) -> None:
        """Fail loudly on a malformed policy — a silent typo must not shift verdicts."""
        total = sum(self.weights.values())
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"policy weights must sum to 1.00, got {total:.6f}")
        for name, w in self.weights.items():
            if not 0.0 <= w <= 1.0:
                raise ValueError(f"policy weight {name}={w} outside [0, 1]")
        if not 0.0 <= self.suspect_threshold < self.trusted_threshold <= 1.0:
            raise ValueError(
                "policy thresholds must satisfy 0 <= suspect < trusted <= 1, got "
                f"suspect={self.suspect_threshold} trusted={self.trusted_threshold}")
        if not 0.0 <= self.malicious_trust_ceiling <= self.suspect_threshold:
            raise ValueError(
                "malicious_trust_ceiling must sit at or below suspect_threshold so a "
                f"MALICIOUS verdict can never outrank SUSPECT, got "
                f"{self.malicious_trust_ceiling}")

    def total(self, factors: "TrustFactors") -> float:
        return sum(self.weights[k] * getattr(factors, k) for k in FACTOR_NAMES)


# v1 policy used when a caller does not supply one (pure-function unit tests).
DEFAULT_SCORING_POLICY = ScoringPolicy.from_policy({})

# Back-compat aliases, derived from the default policy rather than re-declared.
WEIGHTS: Dict[str, float] = dict(DEFAULT_SCORING_POLICY.weights)
CONFLICT_PENALTY = DEFAULT_SCORING_POLICY.conflict_penalty
TRUSTED_THRESH = DEFAULT_SCORING_POLICY.trusted_threshold
SUSPECT_THRESH = DEFAULT_SCORING_POLICY.suspect_threshold
HARD_MALICIOUS = set(DEFAULT_SCORING_POLICY.hard_malicious)
DISPOSITIONS = ("TRUSTED", "SUSPECT", "RESTRICT", "MALICIOUS")


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


@dataclass
class TrustFactors:
    corroboration: float = 1.0
    consistency: float = 1.0
    plausibility: float = 1.0
    provenance: float = 1.0
    freshness: float = 1.0
    history: float = 1.0

    def to_dict(self) -> Dict[str, float]:
        return {name: round(getattr(self, name), 3) for name in FACTOR_NAMES}


@dataclass
class TrustResult:
    disposition: str
    trust: float
    reason_codes: List[str] = field(default_factory=list)
    factors: TrustFactors = field(default_factory=TrustFactors)
    conflict: float = 0.0
    verified_at: float = 0.0


def compute_trust(raw: dict, detections: List[DetectionResult], ctx: DetectorContext,
                  *, device_known: bool, signature_ok: bool, quarantined: bool,
                  history_score: float,
                  policy: Optional[ScoringPolicy] = None) -> TrustResult:
    """Compute the 6-factor score + disposition from a reading + its detections.

    Pure & deterministic given the inputs (now is injected via ctx.reading_time so
    fixtures can pin time for reproducible scoring).
    """
    pol = policy or DEFAULT_SCORING_POLICY
    factors = TrustFactors()
    reasons: List[str] = []
    conflict_val = 0.0
    hard = False

    for d in detections:
        if not d.flag:
            continue
        reasons.append(d.flag)
        if d.flag in pol.hard_malicious:
            hard = True
        if d.detector == "conflict":
            # detect_conflict exposes the dissent ratio via magnitude -> conflict penalty
            conflict_val = max(conflict_val, d.magnitude)
        for f in d.factors:
            if f == "freshness":
                continue  # freshness is recomputed from age below (single source of truth)
            if f in FACTOR_NAMES:
                factors.__dict__[f] = _clamp(factors.__dict__[f] + d.impact)

    # Provenance hard checks (signature/secret/quarantine).
    if not device_known or quarantined:
        factors.provenance = 0.0
    elif not signature_ok:
        factors.provenance = _clamp(factors.provenance - 0.5)

    # Freshness factor from age (independent of the STALE flag text, which stays in reasons).
    try:
        age = ctx.reading_time - parse_iso(str(raw.get("phenomenon_time", "")))
    except Exception:
        age = ctx.ttl_s
    if ctx.ttl_s <= 0:
        factors.freshness = 1.0
    elif age < 0:
        # A phenomenon_time in the future means the reading's age cannot be verified
        # (clock skew, or a stamp pushed forward to dodge the age gate). It is NOT
        # fresh — scoring it as 1.0 would hand an attacker a permanent bypass.
        factors.freshness = 0.0
    else:
        factors.freshness = _clamp(1.0 - age / float(ctx.ttl_s))
    factors.history = _clamp(history_score)

    # The published formula, applied for every disposition.
    trust = _clamp(pol.total(factors) - pol.conflict_penalty * conflict_val)
    if hard:
        disposition = "MALICIOUS"
        trust = min(trust, pol.malicious_trust_ceiling)
    else:
        disposition = disposition_for(trust, pol)

    # de-dup reasons, keep sorted for stable, testable output
    reason_codes = sorted(set(reasons))
    return TrustResult(
        disposition=disposition, trust=round(trust, 3),
        reason_codes=reason_codes, factors=factors,
        conflict=round(conflict_val, 3), verified_at=ctx.reading_time,
    )


def allowed_actions_for(disposition: str, policy: dict) -> List[str]:
    """Map a disposition to its allowed action *classes* (plan §6.3).

    TRUSTED -> full; SUSPECT/RESTRICT/MALICIOUS never include 'full', so a downgraded
    passport physically cannot authorize a full-commit -> this is the non-bypassable
    rule the flagship S1 (and our tests) assert. This is the ONLY implementation of
    the mapping; the pipeline calls it rather than re-reading policy.yaml inline.
    """
    mapping = (policy or {}).get("allowed_actions", {}) or {}
    entry = mapping.get(disposition, {}) or {}
    return list(entry.get("classes", []))


def conditions_for(disposition: str, policy: dict) -> List[str]:
    """Conditions attached to a disposition (plan §6.3); empty for MALICIOUS/TRUSTED."""
    mapping = (policy or {}).get("allowed_actions", {}) or {}
    entry = mapping.get(disposition, {}) or {}
    return list(entry.get("conditions", []))


def disposition_for(trust: float, policy: Optional[ScoringPolicy] = None) -> str:
    pol = policy or DEFAULT_SCORING_POLICY
    if trust >= pol.trusted_threshold:
        return "TRUSTED"
    if trust >= pol.suspect_threshold:
        return "SUSPECT"
    return "RESTRICT"