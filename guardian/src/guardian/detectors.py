"""The eleven detectors (plan §6.2: ten, plus the triplet's D11 steady detector). Pure functions: (reading, context) -> DetectionResult.

Each detector emits a stable **flag** (or None), the factor(s) it touches, a numeric
`impact` (in [-1, 1]) applied to those factors, and a `magnitude` (0..1) for any
conflict-level signal consumed by the hard-gate/flag aggregation.

Flags feed `score.py` (§E): TAMPER/SPOOF/REPLAY are hard gates -> MALICIOUS;
DRIFT/CONFLICT/OUT_OF_RANGE/RATE_ANOMALY/STALE/JAM/STEADY_ANOMALY/IMPLAUSIBLE lower
the 6-factor score. Data-driven via `sensor_profiles.yaml`.

v1 calibration note (plan §20): impacts are a calibrated v1 — tuned so the flagship S1
(drifting gauge contradicted by its corroborators) lands in SUSPECT, not RESTRICT.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .signing import parse_iso


@dataclass
class DetectionResult:
    detector: str
    flag: Optional[str]
    factors: List[str] = field(default_factory=list)
    impact: float = 0.0      # influence on the affected factor(s), [-1, 1]
    magnitude: float = 0.0   # raw 0..1 signal size (e.g. conflict ratio), independent of impact
    detail: str = ""


@dataclass
class Sibling:
    """Lightweight view of a sibling reading for corroboration/comparison."""
    sensor_id: str
    observed_property: str
    value: float
    phenomenon_time: str


@dataclass
class DetectorContext:
    reading_time: float                    # epoch seconds of this reading (now, injectable)
    reading_property: str                  # observed_property of THIS reading
    sensor_id: str = ""                    # the reading's own device ("independence" checks)
    siblings: List[Sibling] = field(default_factory=list)
    profiles: Dict[str, Any] = field(default_factory=dict)  # all sensor profiles
    profile: Optional[Dict[str, Any]] = None                # this property's profile
    history_values: List[float] = field(default_factory=list)   # own device, recent
    history_digests: List[str] = field(default_factory=list)    # own device, recent
    ttl_s: float = 7.0
    # A phenomenon_time further ahead than this is un-verifiable (clock skew, or a
    # stamp pushed forward to dodge the age gate) and is reported as STALE.
    future_tolerance_s: float = 1.0
    # True when a declared corroborator moved in the same direction over the same
    # window. Suppresses DRIFT for physically coupled pairs (smoke+heat, rain+level).
    coupled_rise: bool = False

    def declared_corroborators(self) -> List[str]:
        """`observed_property` names this profile declares as independent corroborators."""
        return list((self.profile or {}).get("corroborators", []) or [])


def _value_of(raw: dict) -> Optional[float]:
    res = raw.get("result")
    return res.get("value") if isinstance(res, dict) else None


def _contradicts(prop: str, value: float, sib_prop: str, sib_value: float,
                 profiles: Dict[str, Any]) -> bool:
    """v1 physics-coupling: does a corroborating sibling contradict THIS reading?

    Contradiction (not mere event-presence mismatch) is what flags CONFLICT. Unknown
    couplings are conservative (no conflict) to avoid false positives -> a documented
    §8 limitation rather than a risk to healthy traffic.
    """
    try:
        v, sv = float(value), float(sib_value)
    except Exception:
        return False
    # water_level corroborated by rain: heavy rain implies the river should be elevated;
    # a low/gauging reading contradicts it.
    if (prop == "water_level" and sib_prop == "rain") or (prop == "rain" and sib_prop == "water_level"):
        w = v if prop == "water_level" else sv    # the water_level reading's value
        r = sv if sib_prop == "rain" else v        # the rain reading's value
        heavy_rain, flood_level = 20.0, 0.5
        if r > heavy_rain and w < flood_level:
            return True
        # Flood with a dry catchment: a 1m+ surge with (near-)zero rain input
        # contradicts the water balance. An upstream release would move `flow`;
        # with no rain AND no flow movement, the surge is uncorroborated.
        # (Symmetric: this fires for the gauge frame AND for the dry rain frame
        # that claims "no rain" during a flood — both become untrusted, and an
        # independent source such as the camera breaks the tie. Documented §8.)
        if w > 1.0 and r < 1.0:
            return True
        return False
    # Fire: smoke and heat are coupled. A real fire raises BOTH; smoke alone, or
    # heat alone, is the spoof signature (triplet_07 scenario g1: "smoke 400 ppm
    # with a normal temperature -> UNTRUSTED"). Thresholds mirror the Twin's own
    # warning levels in twin/config.json: smoke 10 ppm, temperature 38 C.
    if (prop == "fire_smoke" and sib_prop == "temperature") or \
       (prop == "temperature" and sib_prop == "fire_smoke"):
        smoke = v if prop == "fire_smoke" else sv
        heat = sv if sib_prop == "temperature" else v
        smoke_warn, heat_warn = 10.0, 38.0
        # High smoke with a cold building: no combustion can produce it.
        if smoke >= smoke_warn * 5 and heat < heat_warn - 8.0:
            return True
        # Extreme heat with no smoke at all is equally unphysical.
        if heat >= heat_warn * 2 and smoke < smoke_warn:
            return True
        return False
    return False


def _range_bounds(profile: Dict[str, Any]) -> tuple:
    """Extract (lo, hi) from a profile's `range`.

    Two shapes are supported:
      * scalar   — `range: {min: 0, max: 6}`            (most profiles)
      * component — `range: {lat: {min, max}, lon: {...}}` (position sensors)
    For the component shape we return the union of the declared components, so a
    position reading is still range-checked instead of silently skipping the check.
    """
    rng = (profile or {}).get("range") or {}
    lo, hi = rng.get("min"), rng.get("max")
    if lo is not None and hi is not None:
        return lo, hi
    los, his = [], []
    for v in rng.values():
        if isinstance(v, dict) and v.get("min") is not None and v.get("max") is not None:
            los.append(v["min"])
            his.append(v["max"])
    if los:
        return min(los), max(his)
    return None, None


# D6
def detect_range(raw: dict, ctx: DetectorContext) -> DetectionResult:
    lo, hi = _range_bounds(ctx.profile or {})
    v = _value_of(raw)
    if v is None or lo is None or hi is None:
        return DetectionResult("range", None, detail="no bounded range defined for this profile")
    if not (lo <= v <= hi):
        return DetectionResult("range", "OUT_OF_RANGE", factors=["plausibility"], impact=-1.0,
                               magnitude=1.0, detail=f"value {v} outside [{lo}, {hi}]")
    return DetectionResult("range", None, detail=f"value {v} within [{lo}, {hi}]")


# D1 - rate/anomaly against the device's OWN previous value (one tick assumed)
def detect_rate(raw: dict, ctx: DetectorContext) -> DetectionResult:
    max_rate = (ctx.profile or {}).get("max_rate_per_tick")
    v = _value_of(raw)
    if max_rate is None or v is None or not ctx.history_values:
        return DetectionResult("rate", None, detail="no rate bound or no predecessor")
    delta = abs(v - ctx.history_values[-1])
    if delta > float(max_rate):
        return DetectionResult("rate", "RATE_ANOMALY", factors=["plausibility"], impact=-1.0,
                               magnitude=1.0, detail=f"delta {delta:.2f} > {max_rate}/tick")
    return DetectionResult("rate", None, detail=f"delta {delta:.2f} <= {max_rate}/tick")


# D2 - drift: sustained monotonic trend in own history
# A coupled rise is physics, not attack: a real fire raises smoke and heat
# together (triplet_07 b1), and a real flood raises level with rain. Drift is
# only suspicious when the trend is UNEXPLAINED by a corroborator that should
# move with it. Set by the caller from the sibling window.
COUPLED_PROPERTIES = {"fire_smoke", "temperature", "congestion", "fill_level"}


def detect_drift(ctx: DetectorContext) -> DetectionResult:
    hv = ctx.history_values
    if len(hv) < 3:
        return DetectionResult("drift", None, detail="insufficient history")
    if ctx.coupled_rise:
        return DetectionResult("drift", None,
                               detail="monotonic rise, corroborated by a coupled property")
    # An upward trend on a quantity whose profile names NO corroborator cannot be
    # cross-checked at all. Flagging it would make every legitimate build-up
    # (a bin filling, a queue forming) an attack, so it is reported as
    # un-corroborated rather than as drift. A device that *has* corroborators and
    # moves while they stay flat is still flagged below.
    if not ctx.declared_corroborators():
        return DetectionResult("drift", None,
                               detail="monotonic rise, but the profile declares no corroborator")
    diffs = [hv[i] - hv[i - 1] for i in range(1, len(hv))]
    if all(d > 1e-9 for d in diffs):
        return DetectionResult("drift", "DRIFT", factors=["corroboration"], impact=-0.20,
                               magnitude=1.0, detail=f"upward drift over {len(diffs)} ticks")
    if all(d < -1e-9 for d in diffs):
        return DetectionResult("drift", "DRIFT", factors=["corroboration"], impact=-0.20,
                               magnitude=1.0, detail=f"downward drift over {len(diffs)} ticks")
    return DetectionResult("drift", None, detail="no sustained drift")


# D3 - spoof: physically impossible speed vs own previous value
def detect_spoof(raw: dict, ctx: DetectorContext) -> DetectionResult:
    p = ctx.profile or {}
    if "max_speed_kmh" not in p:
        return DetectionResult("spoof", None, detail="no speed model")
    v = _value_of(raw)
    if v is None or not ctx.history_values:
        return DetectionResult("spoof", None, detail="no predecessor")
    speed = abs(v - ctx.history_values[-1])
    if speed > float(p["max_speed_kmh"]):
        return DetectionResult("spoof", "SPOOF", factors=["plausibility"], impact=-1.0,
                               magnitude=1.0, detail=f"speed {speed:.1f} > {p['max_speed_kmh']}")
    return DetectionResult("spoof", None, detail=f"speed {speed:.1f} ok")


# D4 - replay: this frame's digest is already in the device's own recent digests.
#
# Stage A dedup keys on `reading_id`, which an attacker controls. Re-sending an old
# signed frame under a FRESH reading_id therefore slips past dedup, so the content
# digest is the real anti-replay check and must be compared against the CURRENT frame.
def detect_replay(raw: dict, ctx: DetectorContext) -> DetectionResult:
    d = str(raw.get("digest", ""))
    if not d:
        return DetectionResult("replay", None, detail="no digest to check")
    if d in ctx.history_digests:
        return DetectionResult("replay", "REPLAY", factors=["provenance"], impact=-1.0,
                               magnitude=1.0, detail="digest already seen for this device")
    return DetectionResult("replay", None, detail="digest fresh")


# D5 - stale: age exceeds TTL, or the stamp is un-verifiably in the future.
# (The transport-level gate is Stage A when enforce_freshness=on; this keeps the
# reason code on the verdict even when that gate is off.)
def detect_stale(raw: dict, ctx: DetectorContext) -> DetectionResult:
    try:
        age = ctx.reading_time - parse_iso(str(raw.get("phenomenon_time", "")))
    except Exception as exc:
        return DetectionResult("stale", None, detail=f"unparseable phenomenon_time: {exc}")
    if age < -ctx.future_tolerance_s:
        return DetectionResult("stale", "STALE", factors=["freshness"], impact=-1.0,
                               magnitude=1.0,
                               detail=f"phenomenon_time {-age:.1f}s in the future")
    if age > ctx.ttl_s:
        return DetectionResult("stale", "STALE", factors=["freshness"], impact=-1.0,
                               magnitude=1.0, detail=f"age {age:.1f}s > TTL {ctx.ttl_s}s")
    return DetectionResult("stale", None, detail=f"age {age:.1f}s within TTL")


# D7 - jam: the signal FROZE after it was moving.
#
# A constant reading is not a jam: quantized sensors (aqi, camera counts, rain in dry
# weather) legitimately repeat, and a steady reservoir repeats forever. The mute/jam
# signature is a freeze that follows real movement.
#
# Triplet parity: the frozen signal IS the fault — the Twin's own judge ("the value
# did not change for 6 reads -> UNTRUSTED", g2's stuck sensor) treats a freeze as
# disqualifying, whatever level it sits at. Impact is therefore decisive (-0.70,
# same as STEADY_ANOMALY) so a frozen device lands SUSPECT -> UNTRUSTED.
def detect_jam(ctx: DetectorContext) -> DetectionResult:
    cfg = (ctx.profile or {}).get("jam")
    if isinstance(cfg, dict) and cfg.get("significant") is False:
        return DetectionResult("jam", None,
                               detail="profile declares freezes legitimate (saturation/rest)")
    hv = ctx.history_values
    # Triplet parity, explicit opt-in: `jam: {repeat_ticks: N}` says "N identical
    # reads IS the fault", which is the Twin's own judge rule ("the value did not
    # change for 6 reads -> UNTRUSTED", scenario g2's stuck sensor). Only profiles
    # whose physics is genuinely noisy opt in: a live traffic sensor wanders by
    # a few tenths every tick, so an exact repeat cannot be coincidence — whereas
    # a quantized counter legitimately repeats and must not opt in.
    repeats = int(cfg.get("repeat_ticks", 0)) if isinstance(cfg, dict) else 0
    if repeats > 0:
        if len(hv) < repeats:
            return DetectionResult("jam", None, detail="insufficient history for the repeat rule")
        tail = hv[-repeats:]
        if all(abs(v - tail[-1]) < 1e-12 for v in tail):
            return DetectionResult("jam", "JAM", factors=["corroboration"], impact=-0.70,
                                   magnitude=1.0,
                                   detail=f"identical value repeated for {repeats} reads (stuck sensor)")
        return DetectionResult("jam", None, detail="value still varying")
    if len(hv) < 4:
        return DetectionResult("jam", None, detail="insufficient history to distinguish freeze from steady")
    tail = hv[-3:]
    if not all(abs(v - tail[-1]) < 1e-12 for v in tail):
        return DetectionResult("jam", None, detail="value changing")
    prior = hv[:-3]
    if not prior or all(abs(v - prior[-1]) < 1e-12 for v in prior):
        return DetectionResult("jam", None, detail="steady throughout (not a freeze)")
    return DetectionResult("jam", "JAM", factors=["corroboration"], impact=-0.70,
                           magnitude=1.0,
                           detail="moving, then frozen for 3+ ticks")


# D11 - steady: the value is PINNED inside an anomalous band, unsupported by evidence.
#
# The triplet's fake_jam (scenario g3) publishes a jam at full level forever: the
# value barely moves tick to tick, sits at the ceiling, and — unlike a real jam
# (a1) — NO independent source in the zone states the same thing. Two conditions
# together make that claim untrustworthy, and both are data, not code: the
# profile's `steady:` block opts a property in and carries the thresholds
# (ticks / span / min_value), mirroring the Twin's own mock judge ("the value did
# not change for 6 reads -> UNTRUSTED").
#
# Independence rule: a lying generator often renders its own other channels
# coherently too (fake vehicleCount moves with fake congestion), so the
# corroborator that can cancel the flag must be another DEVICE, never the same
# device's own attributes.
#
# Steady at an ORDINARY level is healthy (calm roads, a full reservoir): the
# `min_value` band is what separates anomalous pinning from quantized calm.
def _independent(ctx: DetectorContext, props: set) -> List[Sibling]:
    own = getattr(ctx, "sensor_id", "")
    return [s for s in ctx.siblings if s.sensor_id != own and s.observed_property in props]

def _supports_steady(sibling: "Sibling", cond: Dict[str, Any]) -> bool:
    """Directional support: does the sibling's value satisfy the condition?"""
    op, value = str(cond.get("op", ">=")), float(cond.get("value", 0.0))
    return {
        ">=": sibling.value >= value,
        ">": sibling.value > value,
        "<=": sibling.value <= value,
        "<": sibling.value < value,
    }.get(op, sibling.value >= value)


def detect_steady(ctx: DetectorContext) -> DetectionResult:
    cfg = (ctx.profile or {}).get("steady") or {}
    if not cfg:
        return DetectionResult("steady", None, detail="no steady rule for this profile")
    hv = ctx.history_values
    ticks = int(cfg.get("ticks", 5))
    span = float(cfg.get("span", 6.0))
    min_value = float(cfg.get("min_value", 0.0))
    if len(hv) < ticks:
        return DetectionResult("steady", None, detail="insufficient history")
    window = hv[-ticks:]
    if max(window) - min(window) > span:
        return DetectionResult("steady", None, detail="value still moving")
    if min(window) < min_value:
        return DetectionResult("steady", None, detail="steady at an ordinary level")
    # The falsifier: an independent device in the same zone must support the
    # high state through one of the DIRECTIONAL conditions in `corroborate`
    # (count high, or speed low — see the congestion profile). Without one, the
    # pinned ceiling is a story only this device tells.
    spec = (cfg.get("corroborate") or
            # legacy-free default: any declared corroborator above a floor
            {p: {"op": ">=", "value": float(cfg.get("corroborate_min", min_value * 0.5))}
             for p in ctx.declared_corroborators()})
    sibs = _independent(ctx, set(spec))
    if not sibs:
        return DetectionResult("steady", None, detail="no independent corroborator present")
    support = [s for s in sibs if _supports_steady(s, spec.get(s.observed_property, {}))]
    if support:
        return DetectionResult("steady", None,
                               detail="steady high, corroborated by " + ", ".join(sorted({s.sensor_id for s in support})))
    return DetectionResult("steady", "STEADY_ANOMALY", factors=["corroboration"], impact=-0.70,
                           magnitude=1.0,
                           detail=f"pinned >= {min_value:g} for {ticks}+ reads; no independent corroborator")



# D8 - conflict: cross-property corroboration (plan §6.2 "independent sources agree")
def detect_conflict(raw: dict, ctx: DetectorContext) -> DetectionResult:
    """CONFLICT when a declared corroborator contradicts this reading on a coupling.

    Uses `profile.corroborators` + the `_contradicts` physics-coupling table. Dissent
    fraction -> `magnitude` (drives the 0.25 conflict penalty) and `impact` (drives the
    corroboration factor). Single-source readings are NOT penalized (known §8 limitation).
    """
    profile = ctx.profile or {}
    corroborators = profile.get("corroborators", []) or []
    v = _value_of(raw)
    if v is None:
        return DetectionResult("conflict", None, detail="no value")
    if not corroborators or not ctx.siblings:
        return DetectionResult("conflict", None, detail="single-source (no corroborators)")
    total = agree = 0
    prop = ctx.reading_property
    for s in ctx.siblings:
        if s.observed_property not in corroborators:
            continue
        total += 1
        if not _contradicts(prop, v, s.observed_property, s.value, ctx.profiles):
            agree += 1
    if total == 0:
        return DetectionResult("conflict", None, detail="no corroborator siblings present")
    ratio = (total - agree) / total          # dissent fraction
    agree_ratio = agree / total
    if agree_ratio < 0.6:
        return DetectionResult("conflict", "CONFLICT", factors=["corroboration"],
                               impact=-0.50 * ratio, magnitude=ratio,
                               detail=f"{agree}/{total} corroborators support (dissent {ratio:.2f})")
    return DetectionResult("conflict", None, detail=f"{agree}/{total} corroborators support")


# D9 - tamper/mute: the device's own signal COLLAPSED to zero.
#
# Zero is a legitimate reading for most of this profile set — rain 0mm in dry weather,
# emergency_call 0 incidents, traffic_camera 0 vehicles overnight, water_level at
# datum. Convicting on "value is zero and some neighbour is nonzero" hard-gates
# perfectly healthy traffic to MALICIOUS, so zero alone is never a signature.
#
# The mute signature is a COLLAPSE: this device was reporting materially nonzero and
# has now dropped to zero. Declared corroborators only enrich the detail; they never
# convict on their own.
#
# Triplet parity: a collapse within the profile's own `max_rate_per_tick` is a
# LAWFUL decay, not a mute — the Twin's building empties during an evacuation at
# 3 people/tick (building occupancy 15 -> ... -> 0 is the incident completing,
# b1, and convicting it would hard-gate a real fire scene to MALICIOUS). A mute
# cliff moves faster than the profile allows in one tick (the t4 muted gauge:
# 0.82 -> 0.0 vs a 0.5/tick limit).
def detect_tamper(raw: dict, ctx: DetectorContext) -> DetectionResult:
    v = _value_of(raw)
    if v is None:
        return DetectionResult("tamper", None, detail="no value")
    if abs(v) > 1e-12:
        return DetectionResult("tamper", None, detail="value not muted")
    hv = ctx.history_values
    if len(hv) < 2:
        return DetectionResult("tamper", None, detail="no own history to establish a collapse")
    prior = hv[-2:]
    if all(abs(h) <= 1e-12 for h in prior):
        return DetectionResult("tamper", None, detail="device has been reporting zero (no collapse)")
    drop = abs(prior[-1])
    rate_limit = float((ctx.profile or {}).get("max_rate_per_tick", 0.0) or 0.0)
    if rate_limit > 0.0:
        if drop >= rate_limit:
            # A cliff beyond the one-tick law: muted/mounted tamper, not decay.
            pass
        else:
            return DetectionResult("tamper", None,
                                   detail=f"lawful decay to 0 ({drop:g} <= {rate_limit:g}/tick)")
    corroborated = [s.observed_property for s in ctx.siblings
                    if s.observed_property in set(ctx.declared_corroborators())
                    and abs(s.value) > 1e-12]
    detail = (f"collapsed from {prior[-1]:.4g} to 0"
              + (f"; corroborated live by {sorted(set(corroborated))}" if corroborated else ""))
    return DetectionResult("tamper", "TAMPER", factors=["provenance"], impact=-1.0,
                           magnitude=1.0, detail=detail)


# D10 - consistency/physics: violates a stated physical coupling.
#
# A river can sit high with zero local rain (residual drainage, upstream release,
# a dam releasing), so "no rain and high water" is not by itself impossible. The
# physically odd case is water RISING with no rain input at all.
def detect_consistency(raw: dict, ctx: DetectorContext) -> DetectionResult:
    v = _value_of(raw)
    if v is None:
        return DetectionResult("consistency", None, detail="no value")
    if raw.get("observed_property") != "water_level":
        return DetectionResult("consistency", None, detail="no coupling declared for this property")
    rain = next((s.value for s in ctx.siblings if s.observed_property == "rain"), None)
    if rain is None or rain > 0:
        return DetectionResult("consistency", None, detail="rain input present (or absent) - consistent")
    hv = ctx.history_values
    if len(hv) < 3:
        return DetectionResult("consistency", None, detail="no trend to evaluate")
    rising = all(hv[i] - hv[i - 1] > 1e-9 for i in range(1, len(hv)))
    if rising and v > 0.5:
        return DetectionResult("consistency", "IMPLAUSIBLE", factors=["consistency"], impact=-1.0,
                               magnitude=1.0, detail="water rising with zero rain input")
    return DetectionResult("consistency", None, detail="physics consistent")


# Registry (plan §9.2: every detector has >=1 triggering fixture)
ALL = [
    ("range", detect_range),
    ("rate", detect_rate),
    ("drift", detect_drift),
    ("spoof", detect_spoof),
    ("stale", detect_stale),
    ("jam", detect_jam),
    ("steady", detect_steady),
    ("conflict", detect_conflict),
    ("tamper", detect_tamper),
    ("consistency", detect_consistency),
    ("replay", detect_replay),
]


def run_detectors(raw: dict, ctx: DetectorContext) -> List[DetectionResult]:
    """Run every detector; return all results (benign + flagged).

    Anti-fragile: a detector that raises is recorded as a benign error-hit so a
    single detector bug never fails an ingestion path (plan §7.4).
    """
    ctx_only = {"drift", "jam", "steady"}
    results: List[DetectionResult] = []
    for name, fn in ALL:
        try:
            results.append(fn(ctx) if name in ctx_only else fn(raw, ctx))
        except Exception as exc:
            results.append(DetectionResult(name, None, detail=f"detector error: {exc}"))
    return results
