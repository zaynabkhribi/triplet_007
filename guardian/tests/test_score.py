"""Trust-score unit tests (plan §3, §6.3, §9).

Asserts the canonical v1 invariants:
 * healthy -> TRUSTED (may authorize full-commit)
 * S1-style drift + contradiction -> SUSPECT, and a SUSPECT passport NEVER contains
   a 'full' action class (non-bypassable rule the flagship and rubric assert)
 * TAMPER/SPOOF/REPLAY -> MALICIOUS regardless of other factors
 * threshold boundaries are exact (0.80 / 0.50)
"""
import pytest

from guardian.config import load_settings, load_policy, load_sensor_profiles
from guardian.detectors import DetectorContext, Sibling, DetectionResult
from guardian.score import (compute_trust, disposition_for, allowed_actions_for,
                            TRUSTED_THRESH, SUSPECT_THRESH)
from guardian.signing import parse_iso

SETTINGS = load_settings()
POLICY = load_policy(SETTINGS)
PROFILES = load_sensor_profiles(SETTINGS)
NOW = parse_iso("2026-10-20T10:03:11.000Z")


def _ctx(**kw):
    d = dict(reading_time=NOW, reading_property="water_level", siblings=[], profiles=PROFILES,
             profile=PROFILES.get("water_level"), history_values=[], history_digests=[], ttl_s=7.0)
    d.update(kw)
    return DetectorContext(**d)


def _water(v=0.82, seq=1):
    return {"sensor_id": "river-gauge-1", "zone": "Z-RIVER_UNDERPASS", "observed_property": "water_level",
            "phenomenon_time": "2026-10-20T10:03:11.000Z", "result": {"value": v, "unit": "m"},
            "provenance": {"firmware": "1.4", "cal": "CAL-07", "seq": seq},
            "digest": "sha256:" + "0" * 64, "signature": "hmac:x"}


def _score(raw, ctx):
    from guardian.detectors import run_detectors
    return compute_trust(raw, run_detectors(raw, ctx), ctx,
                         device_known=True, signature_ok=True, quarantined=False, history_score=1.0)


def _hard(hard_flag):
    return [DetectionResult(hard_flag.lower(), hard_flag, factors=["provenance"],
                            impact=-1.0, magnitude=1.0, detail="trigger")]


def test_healthy_single_source_is_trusted():
    tr = _score(_water(0.82), _ctx(history_values=[0.8]))
    assert tr.disposition == "TRUSTED"
    assert tr.trust >= TRUSTED_THRESH
    assert "full" in allowed_actions_for(tr.disposition, POLICY)


def test_s1_drift_plus_conflict_is_suspect_no_full():
    ctx = _ctx(history_values=[0.30, 0.36, 0.42],
               siblings=[Sibling(sensor_id="rain-gauge-2", observed_property="rain", value=80.0,
                                 phenomenon_time="2026-10-20T10:03:11.000Z")])
    tr = _score(_water(0.48), ctx)
    assert tr.disposition == "SUSPECT", tr
    assert SUSPECT_THRESH <= tr.trust < TRUSTED_THRESH
    assert {"DRIFT", "CONFLICT"}.issubset(set(tr.reason_codes))
    acts = allowed_actions_for(tr.disposition, POLICY)
    assert "full" not in acts                  # the non-bypassable rule
    assert "reversible" in acts


@pytest.mark.parametrize("hard_flag", ["TAMPER", "SPOOF", "REPLAY"])
def test_hard_flags_force_malicious(hard_flag):
    tr = compute_trust(_water(0.48), _hard(hard_flag), _ctx(),
                       device_known=True, signature_ok=True, quarantined=False, history_score=1.0)
    assert tr.disposition == "MALICIOUS"
    assert hard_flag in tr.reason_codes
    assert allowed_actions_for(tr.disposition, POLICY) == []


def test_disposition_thresholds():
    assert disposition_for(0.80) == "TRUSTED"
    assert disposition_for(0.799) == "SUSPECT"
    assert disposition_for(0.50) == "SUSPECT"
    assert disposition_for(0.499) == "RESTRICT"


# --- policy.yaml is the single source of truth (weights/thresholds/penalty) ---
def test_scoring_policy_reads_thresholds_from_policy_yaml():
    from guardian.score import ScoringPolicy
    pol = ScoringPolicy.from_policy(POLICY)
    pol.validate()
    assert pol.trusted_threshold == POLICY["thresholds"]["trusted"]
    assert pol.suspect_threshold == POLICY["thresholds"]["suspect"]
    assert pol.conflict_penalty == POLICY["conflict_penalty"]
    assert pol.hard_malicious == frozenset(POLICY["hard_flags"]["malicious"])
    for name, w in pol.weights.items():
        assert w == POLICY["weights"][name]


def test_policy_threshold_change_actually_moves_verdicts():
    """REGRESSION: thresholds were hardcoded, so editing policy.yaml was a no-op."""
    from guardian.detectors import run_detectors
    from guardian.score import ScoringPolicy
    strict = ScoringPolicy.from_policy(
        {**POLICY, "thresholds": {**POLICY["thresholds"], "suspect": 0.90, "trusted": 0.95}})
    strict.validate()
    ctx = _ctx(history_values=[0.30, 0.36, 0.42],
               siblings=[Sibling(sensor_id="rain-gauge-2", observed_property="rain", value=80.0,
                                 phenomenon_time="2026-10-20T10:03:11.000Z")])
    default = _score(_water(0.48), ctx)
    strict_tr = compute_trust(_water(0.48), run_detectors(_water(0.48), ctx), ctx,
                              device_known=True, signature_ok=True, quarantined=False,
                              history_score=1.0, policy=strict)
    assert default.disposition == "SUSPECT"
    assert strict_tr.disposition == "RESTRICT", "raising the suspect threshold must bite"
    assert strict_tr.trust == default.trust   # same score, different policy => different verdict


def test_policy_conflict_penalty_change_actually_moves_trust():
    from guardian.detectors import run_detectors
    from guardian.score import ScoringPolicy
    heavy = ScoringPolicy.from_policy({**POLICY, "conflict_penalty": 0.60})
    heavy.validate()
    ctx = _ctx(history_values=[0.30, 0.36, 0.42],
               siblings=[Sibling(sensor_id="rain-gauge-2", observed_property="rain", value=80.0,
                                 phenomenon_time="2026-10-20T10:03:11.000Z")])
    raw = _water(0.48)
    base = compute_trust(raw, run_detectors(raw, ctx), ctx, device_known=True,
                         signature_ok=True, quarantined=False, history_score=1.0)
    harsh = compute_trust(raw, run_detectors(raw, ctx), ctx, device_known=True,
                          signature_ok=True, quarantined=False, history_score=1.0, policy=heavy)
    assert harsh.trust < base.trust


def test_scoring_policy_validates_malformed_configs():
    from guardian.score import ScoringPolicy
    with pytest.raises(ValueError):
        ScoringPolicy.from_policy({"weights": {"corroboration": 0.5}}).validate()
    with pytest.raises(ValueError):
        ScoringPolicy.from_policy({"thresholds": {"suspect": 0.9, "trusted": 0.5}}).validate()
    with pytest.raises(ValueError):
        ScoringPolicy.from_policy({"thresholds": {"malicious_trust_ceiling": 0.95}}).validate()


def test_hard_gate_trust_never_outranks_suspect():
    """The published formula runs for every disposition; a hard gate caps trust."""
    from guardian.score import ScoringPolicy
    pol = ScoringPolicy.from_policy(POLICY)
    tr = compute_trust(_water(0.48), _hard("TAMPER"), _ctx(),
                       device_known=True, signature_ok=True, quarantined=False,
                       history_score=1.0, policy=pol)
    assert tr.disposition == "MALICIOUS"
    assert tr.trust <= pol.malicious_trust_ceiling < pol.suspect_threshold


def test_future_timestamp_is_not_scored_as_fresh():
    """REGRESSION: a stamp in the future used to clamp freshness to 1.0 (age < 0),
    which is a permanent age-gate bypass for anyone controlling phenomenon_time."""
    from guardian.detectors import detect_stale
    raw = _water(0.48)
    raw["phenomenon_time"] = "2099-01-01T00:00:00.000Z"
    tr = compute_trust(raw, [], _ctx(), device_known=True, signature_ok=True,
                       quarantined=False, history_score=1.0)
    assert tr.factors.freshness == 0.0, "an un-verifiable future stamp must not read as fresh"
    assert detect_stale(raw, _ctx()).flag == "STALE", "it must also surface a stable reason code"


def test_unverified_signature_costs_provenance():
    """The scorer must be told the truth about whether signatures were checked."""
    raw = _water(0.48)
    verified = compute_trust(raw, [], _ctx(), device_known=True, signature_ok=True,
                             quarantined=False, history_score=1.0)
    unverified = compute_trust(raw, [], _ctx(), device_known=True, signature_ok=False,
                               quarantined=False, history_score=1.0)
    assert verified.factors.provenance == 1.0
    assert unverified.factors.provenance == 0.5
    assert unverified.trust < verified.trust


def test_stale_and_conflict_restricts():
    raw = _water(0.48)
    raw["phenomenon_time"] = "2000-01-01T00:00:00.000Z"
    ctx = _ctx(history_values=[0.30, 0.36, 0.42],
               siblings=[Sibling(sensor_id="rain-gauge-2", observed_property="rain", value=80.0,
                                 phenomenon_time="2000-01-01T00:00:00.000Z")], ttl_s=7.0)
    tr = _score(raw, ctx)
    assert tr.disposition == "RESTRICT", tr
    assert tr.factors.freshness == 0.0
    assert "STALE" in tr.reason_codes
    assert "full" not in allowed_actions_for(tr.disposition, POLICY)
