"""Unit tests for the ten detectors (plan §6.2, §9.2).

Plan §9.2 mandates every detector has >=1 triggering fixture: each `test_*_flags`
case here is that fixture. Benign (no-flag) cases prove the detectors don't
false-positive on healthy telemetry.
"""
from guardian.config import load_settings, load_sensor_profiles
from guardian.detectors import (DetectorContext, Sibling, run_detectors,
    detect_range, detect_rate, detect_drift, detect_spoof,
    detect_stale, detect_jam, detect_conflict, detect_tamper,
    detect_consistency, detect_replay)
from guardian.signing import parse_iso

PROFILES = load_sensor_profiles(load_settings())
NOW = parse_iso("2026-10-20T10:03:11.000Z")


def _raw(prop="water_level", value=0.82, zone="Z-RIVER_UNDERPASS", digest=None):
    return {"sensor_id": "river-gauge-1", "zone": zone, "observed_property": prop,
            "phenomenon_time": "2026-10-20T10:03:11.000Z",
            "result": {"value": value, "unit": "m" if prop == "water_level" else "mm"},
            "provenance": {"firmware": "1.4", "cal": "CAL-07", "seq": 1},
            "digest": digest or ("sha256:" + "0" * 64), "signature": "hmac:x"}


def _ctx(**kw):
    d = dict(reading_time=NOW, reading_property="water_level", siblings=[], profiles=PROFILES,
             profile=PROFILES.get("water_level"), history_values=[], history_digests=[], ttl_s=7.0)
    d.update(kw)
    return DetectorContext(**d)


# --- range ---
def test_range_ok_in_bounds():
    assert detect_range(_raw(value=0.82), _ctx()).flag is None


def test_range_flags_out_of_range():
    r = detect_range(_raw(value=99.0), _ctx())
    assert r.flag == "OUT_OF_RANGE" and r.impact <= -1.0


def test_range_checks_gps_too():
    """REGRESSION: the gps profile used a nested {lat:{..},lon:{..}} range that a scalar
    reading could never match, so GPS was silently never range-checked."""
    ctx = ctx_gps = _ctx(reading_property="gps", profile=PROFILES.get("gps"))
    assert detect_range(_raw(prop="gps", value=45.0), ctx_gps).flag is None
    bad = detect_range(_raw(prop="gps", value=9999.0), ctx)
    assert bad.flag == "OUT_OF_RANGE", bad.detail


def test_range_handles_component_wise_profile_shape():
    """A component-wise range profile must still yield usable bounds."""
    from guardian.detectors import _range_bounds
    assert _range_bounds({"range": {"lat": {"min": -90, "max": 90},
                                    "lon": {"min": -180, "max": 180}}}) == (-180, 180)
    assert _range_bounds({"range": {"min": 0, "max": 6}}) == (0, 6)
    assert _range_bounds({}) == (None, None)


# --- rate ---
def test_rate_flags_anomaly():
    r = detect_rate(_raw(value=99.0), _ctx(history_values=[0.1]))
    assert r.flag == "RATE_ANOMALY"


def test_rate_ok_within_bound():
    r = detect_rate(_raw(value=0.36), _ctx(history_values=[0.30]))  # +6cm < 0.5/tick
    assert r.flag is None


# --- drift ---
def test_drift_flags_monotonic():
    r = detect_drift(_ctx(history_values=[0.30, 0.36, 0.42]))
    assert r.flag == "DRIFT"


def test_drift_no_history_is_benign():
    assert detect_drift(_ctx(history_values=[0.3])).flag is None


# --- spoof ---
def test_spoof_flags_gps_speed():
    g = _raw(prop="gps", value=200.0, zone="Z-FLEET")
    r = detect_spoof(g, _ctx(reading_property="gps", profile=PROFILES.get("gps"),
                            history_values=[0.0]))
    assert r.flag == "SPOOF"


def test_spoof_no_speed_model_is_benign():
    assert detect_spoof(_raw(), _ctx()).flag is None


# --- stale ---
def test_stale_flags_old_reading():
    r = _raw()
    r["phenomenon_time"] = "2000-01-01T00:00:00.000Z"
    assert detect_stale(r, _ctx()).flag == "STALE"


def test_stale_ok_when_fresh():
    assert detect_stale(_raw(), _ctx()).flag is None


def test_stale_flags_future_timestamp():
    """A stamp pushed into the future dodges the age gate -> must not read as fresh."""
    r = _raw()
    r["phenomenon_time"] = "2099-01-01T00:00:00.000Z"
    assert detect_stale(r, _ctx()).flag == "STALE"


def test_stale_tolerates_small_clock_skew():
    r = _raw()
    r["phenomenon_time"] = "2026-10-20T10:03:11.500Z"   # 0.5s ahead, inside tolerance
    assert detect_stale(r, _ctx()).flag is None


# --- jam ---
def test_jam_flags_freeze_after_movement():
    # moving, then frozen -> a real mute/jam signature
    assert detect_jam(_ctx(history_values=[1.0, 1.5, 2.0, 2.0, 2.0, 2.0])).flag == "JAM"


def test_jam_benign_on_steady_sensor():
    """A constant reading is NOT a jam - quantized/steady sensors legitimately repeat."""
    assert detect_jam(_ctx(history_values=[2.0, 2.0, 2.0, 2.0, 2.0, 2.0])).flag is None


def test_jam_no_history_is_benign():
    assert detect_jam(_ctx()).flag is None


# --- conflict (cross-property corroboration) ---
def test_conflict_flags_lying_gauge():
    # gauge reads low (0.48) while heavy rain (80) corroborates a flood -> contradiction
    siblings = [Sibling(sensor_id="rain-gauge-2", observed_property="rain", value=80.0,
                        phenomenon_time="2026-10-20T10:03:11.000Z")]
    r = detect_conflict(_raw(value=0.48), _ctx(siblings=siblings))
    assert r.flag == "CONFLICT"


def test_conflict_none_when_healthy():
    # light rain (4.0) with a normal river (0.82) is NOT a contradiction
    siblings = [Sibling(sensor_id="rain-gauge-2", observed_property="rain", value=4.0,
                        phenomenon_time="2026-10-20T10:03:11.000Z")]
    r = detect_conflict(_raw(value=0.82), _ctx(siblings=siblings))
    assert r.flag is None


def test_conflict_single_source_is_benign():
    assert detect_conflict(_raw(), _ctx()).flag is None


# --- tamper ---
def test_tamper_flags_collapse_from_nonzero():
    """Mute signature = the device's OWN signal collapsed from nonzero to zero."""
    r = detect_tamper(_raw(value=0), _ctx(history_values=[0.8, 0.82]))
    assert r.flag == "TAMPER"


def test_tamper_benign_on_legitimate_zero_with_live_neighbour():
    """REGRESSION: a rain gauge reporting 0.0mm beside a normal river is HEALTHY.

    Zero is the normal value for rain/emergency_call/traffic_camera/water_level; a
    neighbouring non-zero sensor must never hard-gate it to MALICIOUS.
    """
    siblings = [Sibling(sensor_id="river-gauge-1", observed_property="water_level", value=0.82,
                        phenomenon_time="2026-10-20T10:03:11.000Z")]
    ctx = _ctx(reading_property="rain", profile=PROFILES.get("rain"), siblings=siblings)
    assert detect_tamper(_raw(prop="rain", value=0.0), ctx).flag is None


def test_tamper_benign_when_device_was_always_zero():
    """A sensor that has always read zero shows no collapse."""
    assert detect_tamper(_raw(value=0), _ctx(history_values=[0.0, 0.0])).flag is None


def test_tamper_benign_without_history():
    """First frame from a device: no collapse can be established."""
    assert detect_tamper(_raw(value=0), _ctx()).flag is None


def test_tamper_none_when_nonzero():
    assert detect_tamper(_raw(value=0.82), _ctx(history_values=[0.8])).flag is None


# --- consistency ---
def test_consistency_flags_implausible():
    # water RISING while the rain sensor reports exactly zero input
    siblings = [Sibling(sensor_id="rain-gauge-2", observed_property="rain", value=0.0,
                        phenomenon_time="2026-10-20T10:03:11.000Z")]
    r = _raw(value=0.9)
    assert detect_consistency(r, _ctx(siblings=siblings, history_values=[0.6, 0.75, 0.85])).flag == "IMPLAUSIBLE"


def test_consistency_ok_with_rain():
    siblings = [Sibling(sensor_id="rain-gauge-2", observed_property="rain", value=4.0,
                        phenomenon_time="2026-10-20T10:03:11.000Z")]
    assert detect_consistency(_raw(value=0.82), _ctx(siblings=siblings)).flag is None


def test_consistency_ok_when_static_and_no_rain():
    """REGRESSION: a river held high by residual/upstream flow with no local rain is NORMAL."""
    siblings = [Sibling(sensor_id="rain-gauge-2", observed_property="rain", value=0.0,
                        phenomenon_time="2026-10-20T10:03:11.000Z")]
    ctx = _ctx(siblings=siblings, history_values=[0.82, 0.82, 0.82])
    assert detect_consistency(_raw(value=0.82), ctx).flag is None


# --- replay ---
def test_replay_flags_current_digest_already_seen():
    """The CURRENT frame's digest repeated -> REPLAY (Stage A dedup keys on reading_id,
    which an attacker controls, so this digest check is the real anti-replay gate)."""
    r = _raw(digest="sha256:dup")
    assert detect_replay(r, _ctx(history_digests=["sha256:dup", "sha256:other"])).flag == "REPLAY"


def test_replay_none_when_digest_fresh():
    assert detect_replay(_raw(digest="sha256:new"), _ctx(history_digests=["sha256:dup"])).flag is None


def test_replay_none_when_no_history():
    assert detect_replay(_raw(), _ctx()).flag is None


# --- aggregator ---
def test_run_detectors_emits_all_eleven():
    results = run_detectors(_raw(), _ctx())
    assert len(results) == 11
    assert all(r.detector for r in results)


def test_healthy_multi_sensor_zone_produces_no_flags():
    """REGRESSION (end-to-end detector): a healthy two-sensor zone — a normal river level
    beside a rain gauge correctly reporting 0.0mm — must produce zero flags.

    This is the case the original tamper/jam heuristics hard-gated to MALICIOUS.
    """
    siblings = [Sibling(sensor_id="river-gauge-1", observed_property="water_level", value=0.82,
                        phenomenon_time="2026-10-20T10:03:11.000Z")]
    ctx = _ctx(reading_property="rain", profile=PROFILES.get("rain"), siblings=siblings,
               history_values=[3.0, 0.0, 0.0])
    results = run_detectors(_raw(prop="rain", value=0.0), ctx)
    flagged = [r.detector for r in results if r.flag]
    assert flagged == [], f"healthy traffic flagged by: {flagged}"
