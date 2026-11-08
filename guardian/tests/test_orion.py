"""The triplet face: device aggregation, the steady detector, stuck-sensor parity.

These pin the contract the Brain and the jury actually see:

  * `aggregate_by_device` — worst property decides the device (malice in one
    attribute is not healed by virtue in another), staleness becomes OFFLINE,
    and the wire shape keeps the three keys the Twin's mock Brain reads.
  * `detect_steady` (D11) — the g3 fake jam: pinned high, uncorroborated.
    Its falsifier is INDEPENDENT and DIRECTIONAL (a1's real jam: a sibling road
    with a high camera count or a low speed corroborates the story).
  * `detect_jam` (D7) — the g2 stuck sensor: identical reads repeated at ANY
    level, which is the Twin's own judge rule. Profiles that legitimately
    freeze (a capped bin, a resting camera) opt out as data.
"""
from __future__ import annotations

import time

import pytest

from guardian.config import load_settings, load_sensor_profiles
from guardian.detectors import DetectorContext, Sibling, detect_jam, detect_steady, detect_tamper
from guardian.orion import DeviceVerdict, _clean_text, aggregate_by_device, catalog_offline

PROFILES = load_sensor_profiles(load_settings())


# --------------------------------------------------------------------------
# aggregation: property verdicts -> one device word
# --------------------------------------------------------------------------
class Rec:
    """Minimal stand-in for a pipeline VerdictRecord (the aggregation's input)."""

    def __init__(self, sensor_id, prop, disposition, trust, at, reasons=()):
        self.sensor_id = sensor_id
        self.observed_property = prop
        self.disposition = disposition
        self.trust = trust
        self.verified_at = at
        self.reason_codes = list(reasons)
        self.evidence_digest = f"sha256:{sensor_id}{prop}"
        self.zone = "B"


def test_worst_property_decides_the_device():
    """A building whose smoke is MALICIOUS is MALICIOUS, not TRUSTED.

    The thermometer being fine does not rehabilitate a tampered smoke channel:
    the Brain acts on the device, so the device reports its worst property.
    """
    now = time.time()
    rows = aggregate_by_device([
        Rec("us-b-bldg-01", "temperature", "TRUSTED", 0.94, now - 0.5),
        Rec("us-b-bldg-01", "fire_smoke", "MALICIOUS", 0.10, now - 0.5, ["TAMPER"]),
    ], now=now, stale_after_s=20)
    row = rows["us-b-bldg-01"]
    assert row.word == "UNTRUSTED"
    assert "TAMPER" in row.reason
    assert row.properties["fire_smoke"]["disposition"] == "MALICIOUS"
    # the wire shape reports the worst disposition, not the best
    assert row.wire()["disposition"] == "MALICIOUS"
    # trust is the device's lowest, never an average that hides the bad channel
    assert row.trust == pytest.approx(0.10)


def test_latest_record_per_property_wins():
    """Re-scoring a property replaces its verdict; history is not averaged."""
    now = time.time()
    rows = aggregate_by_device([
        Rec("us-a-traf-01", "congestion", "MALICIOUS", 0.10, now - 10, ["RATE_ANOMALY"]),
        Rec("us-a-traf-01", "congestion", "TRUSTED", 0.94, now - 1),
    ], now=now, stale_after_s=20)
    assert rows["us-a-traf-01"].word == "TRUSTED"
    assert rows["us-a-traf-01"].reason == "OK"


def test_staleness_becomes_offline_and_leaves_evidence_untouched():
    """g2's dead sensor: no fresh verdict -> OFFLINE, with the reason on the ROW.

    The underlying record must not be mutated: /v1/verdict still serves it as
    the pipeline scored it. Staleness is the device face's finding.
    """
    now = time.time()
    rec = Rec("us-a-traf-02", "congestion", "TRUSTED", 0.94, now - 60)
    row = aggregate_by_device([rec], now=now, stale_after_s=20)["us-a-traf-02"]
    assert row.word == "OFFLINE"
    assert row.reason == "COMM_LOSS"
    assert rec.reason_codes == []          # evidence untouched
    assert rec.disposition == "TRUSTED"


def test_a_fresh_device_is_not_offline():
    now = time.time()
    row = aggregate_by_device(
        [Rec("us-a-traf-01", "congestion", "TRUSTED", 0.94, now - 1)],
        now=now, stale_after_s=20)["us-a-traf-01"]
    assert row.word == "TRUSTED"


def test_catalog_lists_unread_devices_as_offline_without_inventing_verdicts():
    """Nothing readable -> replay the inventory as OFFLINE, never a fabricated score."""
    sensors = {"us-a-traf-01": {"kind": "traffic"}, "us-a-light-01": {"kind": "light"}}
    rows = catalog_offline(sensors, {"traffic", "building", "camera", "bin"},
                           now=time.time(), zone_for=lambda d: "A")
    assert list(rows) == ["us-a-traf-01"]      # actuators get no verdict at all
    assert rows["us-a-traf-01"].word == "OFFLINE"
    assert rows["us-a-traf-01"].reason == "COMM_LOSS"


def test_wire_keeps_the_three_contract_keys():
    """The Twin's mock Brain reads verdict/reason/checked — nothing may rename them."""
    row = DeviceVerdict(device_id="us-b-bldg-01", word="UNTRUSTED",
                        reason="CONFLICT", trust=0.5, zone="B", checked="12:00:00")
    wire = row.wire()
    assert (wire["verdict"], wire["reason"], wire["checked"]) == ("UNTRUSTED", "CONFLICT", "12:00:00")


def test_clean_text_strips_the_brokers_forbidden_characters():
    """A diagnostic must never wedge the write path (Orion refuses < > " ' = ; ( ))."""
    cleaned = _clean_text('detail: <bad> "quote" = a;b(c)')
    for ch in '<>"\'=;()':
        assert ch not in cleaned


# --------------------------------------------------------------------------
# D11 steady — the g3 fake jam vs the a1 real jam
# --------------------------------------------------------------------------
def _ctx(prop, history, siblings, sensor_id="us-a-traf-03"):
    return DetectorContext(
        reading_time=time.time(), reading_property=prop, sensor_id=sensor_id,
        siblings=siblings, profiles=PROFILES, profile=PROFILES.get(prop),
        history_values=history, history_digests=[], ttl_s=60,
        future_tolerance_s=5, coupled_rise=False,
    )


def test_steady_fires_on_an_uncorroborated_pinned_ceiling():
    """g3: five reads near the ceiling, and no other road agrees -> STEADY_ANOMALY."""
    sibs = [Sibling("us-a-traf-01", "traffic_camera", 18.0, ""),
            Sibling("us-a-traf-01", "vehicle_speed", 49.0, "")]
    r = detect_steady(_ctx("congestion", [88, 91, 89, 90, 92], sibs))
    assert r.flag == "STEADY_ANOMALY"
    assert r.impact < 0


def test_steady_stays_silent_when_another_device_corroborates():
    """a1: a real jam is confirmed by a sibling road — a high camera count."""
    sibs = [Sibling("us-a-traf-01", "traffic_camera", 65.0, ""),
            Sibling("us-a-traf-01", "vehicle_speed", 42.0, "")]
    assert detect_steady(_ctx("congestion", [88, 91, 89, 90, 92], sibs)).flag is None


def test_steady_accepts_speed_as_inverse_corroboration():
    """Speed is congestion's inverted cousin: a SLOW sibling agrees with a jam.

    This is the bug the directional conditions fixed: a sibling speed of 12 km/h
    corroborates high congestion, while a sibling speed of 49 km/h does not.
    """
    sibs = [Sibling("us-a-traf-01", "vehicle_speed", 12.0, "")]
    assert detect_steady(_ctx("congestion", [88, 91, 89, 90, 92], sibs)).flag is None


def test_steady_ignores_the_devices_own_other_channels():
    """Independence: the fake generator fakes its own camera and speed too.

    The liar's own channels would "support" the jam (high count, low speed); an
    independent road does not. If own channels counted, g3 would be cleared.
    """
    sibs = [Sibling("us-a-traf-03", "traffic_camera", 75.0, ""),
            Sibling("us-a-traf-03", "vehicle_speed", 8.0, ""),
            Sibling("us-a-traf-01", "traffic_camera", 18.0, ""),
            Sibling("us-a-traf-01", "vehicle_speed", 49.0, "")]
    assert detect_steady(_ctx("congestion", [88, 91, 89, 90, 92], sibs)).flag == "STEADY_ANOMALY"


def test_steady_does_not_convict_without_any_independent_witness():
    """A lone device is not a liar: with no independent source, stay silent.

    (Zone A always has three roads, so this is the honest edge case rather than
    the demo path — conviction needs a falsifier, not just a suspicion.)
    """
    sibs = [Sibling("us-a-traf-03", "traffic_camera", 75.0, "")]
    result = detect_steady(_ctx("congestion", [88, 91, 89, 90, 92], sibs))
    assert result.flag is None
    assert "independent" in result.detail


def test_steady_is_silent_at_ordinary_levels_and_while_moving():
    """Calm roads and ramping jams are not pinned ceilings."""
    calm = [Sibling("us-a-traf-01", "traffic_camera", 18.0, "")]
    assert detect_steady(_ctx("congestion", [12, 13, 12, 13, 12], calm)).flag is None
    assert detect_steady(_ctx("congestion", [40, 55, 70, 84, 95], calm)).flag is None


def test_steady_requires_enough_history():
    assert detect_steady(_ctx("congestion", [90, 91], [])).flag is None


def test_steady_is_opt_in_per_profile():
    """No `steady:` block -> the detector never convicts that profile."""
    assert detect_steady(_ctx("temperature", [200, 201, 200, 200, 200], [])).flag is None


# --------------------------------------------------------------------------
# D7 jam — the g2 stuck sensor, at whatever level it freezes
# --------------------------------------------------------------------------
def test_stuck_sensor_is_flagged_even_at_an_ordinary_level():
    """g2: the Twin repeats the whole payload, so congestion repeats exactly.

    The Twin's own judge convicts on repetition alone ("did not change for 6
    reads"); quadrupling on a plateau at 13% is that same fault.
    """
    r = detect_jam(_ctx("congestion", [13.0] * 5, [], sensor_id="us-a-traf-03"))
    assert r.flag == "JAM"


def test_a_varying_sensor_is_not_stuck():
    assert detect_jam(_ctx("congestion", [13.0, 14.0, 13.0, 15.0, 14.0], [])).flag is None


def test_profiles_that_legitimately_freeze_opt_out():
    """A capped bin and a resting camera repeat by design: not a stuck sensor."""
    assert detect_jam(_ctx("fill_level", [97.0] * 5, [])).flag is None
    assert detect_jam(_ctx("camera_alert", [0.0] * 5, [])).flag is None
    assert detect_jam(_ctx("building_occupancy", [0.0] * 5, [])).flag is None


# --------------------------------------------------------------------------
# D9 tamper — a lawful decay to zero is not a mute
# --------------------------------------------------------------------------
def test_lawful_decay_to_zero_is_not_tamper():
    """b1: the building empties at 3 people/tick during an evacuation.

    Reaching 0 that way is the incident completing; hard-gating it to MALICIOUS
    would convict a real fire scene.
    """
    ctx = _ctx("building_occupancy", [15.0, 12.0, 9.0, 6.0, 3.0], [], sensor_id="us-b-bldg-01")
    assert detect_tamper({"result": {"value": 0.0}}, ctx).flag is None


def test_a_cliff_to_zero_is_still_tamper():
    """t4's muted gauge: 0.82 -> 0.0 is far beyond the 0.5/tick law."""
    ctx = _ctx("water_level", [0.80, 0.82], [], sensor_id="river-gauge-1")
    assert detect_tamper({"result": {"value": 0.0}}, ctx).flag == "TAMPER"


def test_no_rate_law_means_no_decay_allowance():
    """Without a `max_rate_per_tick`, a collapse stays the classic mute signature."""
    ctx = _ctx("water_level", [0.80, 0.82], [], sensor_id="river-gauge-1")
    ctx.profile = dict(ctx.profile or {}, max_rate_per_tick=0)
    assert detect_tamper({"result": {"value": 0.0}}, ctx).flag == "TAMPER"
