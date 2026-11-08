"""The triplet's city, frozen into pure Python — an Orion "world" for checks.

Why a local world
-----------------
`scenarios/run_check.py` must prove the Guardian's verdicts against the SAME
device semantics the real Twin publishes (twin/src/model.py), WITHOUT claiming
a live platform. This module reproduces those readings faithfully, tick by
tick, for the nine triplet scenarios (n1 a1 b1 c1 g1 g2 g3 m1 d1) — the same
formulas, the same noise, the same modes:

* jam ramps: level = min(1, 0.3 + 0.1*ticks); fake_jam pins level at 1.0;
* fire ramps: smoke = min(20*t, 500), temperature = min(22 + 12*t, 300);
* spoof_smoke: smoke 400 ppm, temperature ~22 C (the g1 spoof signature);
* stuck repeats the LAST payload with a fresh timestamp; dead publishes nothing;
* dump flips camera_alert with confidence 0.9; "full" fills a bin +15%/tick.

This is a RECORD of the twin's published physics, not a reimplementation for
fun: when the twin changes a formula, change it here and run `make checks` —
a headline difference will fail loudly instead of silently drifting.

The HTTP face lives in mocks/mock_orion.py (GET /v2/entities/{id}); this module
stays importable and dependency-free so tests can step it directly.
"""
from __future__ import annotations

import json
import random
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# the twin's device list, same order as twin/config.json snapshot
DEVICES: Dict[str, Dict[str, str]] = {
    "us-a-traf-01": {"kind": "traffic", "type": "TrafficSensor"},
    "us-a-traf-02": {"kind": "traffic", "type": "TrafficSensor"},
    "us-a-traf-03": {"kind": "traffic", "type": "TrafficSensor"},
    "us-a-light-01": {"kind": "light", "type": "TrafficLight"},
    "us-a-light-03": {"kind": "light", "type": "TrafficLight"},
    "us-a-sign-01": {"kind": "sign", "type": "EmergencyDispatch"},
    "us-b-bldg-01": {"kind": "building", "type": "BuildingSensor"},
    "us-b-alarm-01": {"kind": "alarm", "type": "FireAlarm"},
    "us-b-disp-01": {"kind": "dispatch", "type": "EmergencyDispatch"},
    "us-c-cam-01": {"kind": "camera", "type": "IPCamera"},
    "us-c-bin-01": {"kind": "bin", "type": "WasteBin"},
    "us-c-bin-02": {"kind": "bin", "type": "WasteBin"},
    "us-c-task-01": {"kind": "task", "type": "CleaningTask"},
    "us-ops-center": {"kind": "ops", "type": "OperationsCenter"},
}

SENSOR_KINDS = {"traffic", "building", "camera", "bin"}   # what gets a Guardian verdict

INITIAL_STATE: Dict[str, Dict[str, float]] = {
    "us-c-bin-01": {"fill": 5.0},
    "us-c-bin-02": {"fill": 5.0},
    "us-a-light-01": {"phase": 0, "mode": 0},
    "us-a-light-03": {"phase": 0, "mode": 0},
}


def rnd(v: float) -> float:
    return round(float(v), 1)


class World:
    """Device states + the tick loop, mirroring twin/src/model.py read()s."""

    def __init__(self, seed: int = 7) -> None:
        # Not cryptographic: the world is a simulator, so a seeded PRNG is
        # exactly right (reproducible checks beat unpredictability here).
        self.rng = random.Random(seed)          # noqa: S311
        self.devices = {}
        for device_id, cfg in DEVICES.items():
            self.devices[device_id] = {
                "kind": cfg["kind"], "type": cfg["type"],
                "mode": "normal", "ticks": 0, "last": None,
                "state": {
                    **{"fill": INITIAL_STATE.get("us-c-bin-01", {}).get("fill", 5.0)
                       if device_id == "us-c-bin-01" else
                       (INITIAL_STATE.get("us-c-bin-02", {}).get("fill", 5.0)
                        if device_id == "us-c-bin-02" else 0.0)},
                },
            }
        self.alarm = False                       # us-b-alarm-01 alarmState
        self.alarm_ticks = 0
        self.tick = 0

    # ------------------------------------------------------------------
    def set_mode(self, device_id: str, mode: str) -> None:
        d = self.devices[device_id]
        d["mode"], d["ticks"] = mode, 0
        if d["kind"] == "traffic" and mode == "jam":
            pass
        if d["kind"] == "building" and mode == "fire":
            self.alarm_ticks = 0

    def command(self, device_id: str, attrs: Dict[str, Any]) -> None:
        """The Brain acts on an actuator; some commands create real effects."""
        self.devices[device_id]["state"].update(attrs)
        if device_id == "us-b-alarm-01" and attrs.get("alarmState"):
            self.alarm = attrs["alarmState"] == "on"

    def step(self) -> None:
        """Advance one 5 s tick: regenerate every device's published payload."""
        self.tick += 1
        for device_id, d in self.devices.items():
            d["ticks"] = d["ticks"] + 1 if d["ticks"] is not None else 1
            if d["mode"] == "dead":
                d["last"] = None
            elif d["mode"] == "stuck" and d["last"] is not None:
                # the fault: the whole payload repeats verbatim, timestamps fresh
                p = dict(d["last"])
                p["timestamp"] = self._stamp()
                d["last"] = p
            else:
                d["last"] = self.reading(device_id)

    # ---- per-kind readings (twin/src/model.py, formula-faithful) --------
    def reading(self, device_id: str) -> Dict[str, Any]:
        d = self.devices[device_id]
        kind = d["kind"]
        if kind == "traffic":
            p = self._traffic(d)
        elif kind == "building":
            p = self._building(d)
        elif kind == "camera":
            p = self._camera()
        elif kind == "bin":
            p = self._bin(device_id)
        elif kind == "ops":
            p = self.ops_summary()
        else:                                  # actuators re-publish their state
            p = self.device_state(device_id)
        p["timestamp"] = self._stamp()
        d["last"] = p
        return p

    def _traffic(self, d: dict) -> Dict[str, Any]:
        level = 0.0
        t = d["ticks"]
        if d["mode"] == "jam":
            ramp = min(1.0, 0.3 + 0.1 * t)
            level = ramp
        elif d["mode"] == "fake_jam":
            level = 1.0
        flow = 20 + 55 * level + self.rng.uniform(-3, 3)
        speed = 50 - 42 * level + self.rng.uniform(-3, 3)
        occ = 15 + 75 * level + self.rng.uniform(-2, 2)
        return {
            "vehicleCount": int(max(flow, 0)),
            "avgSpeed": rnd(max(speed, 2)),
            "occupancy": rnd(min(occ, 100)),
            "congestionLevel": int(min(occ, 100)),
        }

    def _building(self, d: dict) -> Dict[str, Any]:
        t = d["ticks"]
        if d["mode"] == "fire":
            temp = min(22 + 12 * t, 300)
            smoke = min(20 * t, 500)
            occupancy = max(0, 15 - 3 * self.alarm_ticks) if self.alarm else 15
        elif d["mode"] == "spoof_smoke":
            temp, smoke, occupancy = 22 + self.rng.uniform(-0.4, 0.4), 400, 15
        else:
            temp = 22 + self.rng.uniform(-0.4, 0.4)
            smoke = max(0, 2 + self.rng.uniform(-1, 1))
            occupancy = 15
        if self.alarm:
            self.alarm_ticks += 1
        return {"smokeLevel": rnd(smoke), "temperature": rnd(temp), "occupancyCount": int(occupancy)}

    def _camera(self) -> Dict[str, Any]:
        if self.devices["us-c-cam-01"]["mode"] == "dump":
            return {"dumpingDetected": True, "confidence": 0.9, "status": "active",
                    "message": "illegal dumping detected"}
        return {"dumpingDetected": False, "confidence": 0.0, "status": "active", "message": "ok"}

    def _bin(self, device_id: str) -> Dict[str, Any]:
        d = self.devices[device_id]
        fill = d["state"].get("fill", 5.0)
        if d["mode"] == "full":
            fill = min(97.0, fill + 15.0)
        else:
            fill += 0.3
            if fill >= 70:                     # the routine collection empties a normal bin
                fill = 5.0
        d["state"]["fill"] = fill
        return {"fillLevel": int(min(100.0, fill))}

    def device_state(self, device_id: str) -> Dict[str, Any]:
        """What an actuator currently publishes: its defaults + the Brain's commands."""
        d = self.devices[device_id]
        actuator_defaults = {
            "light": {"phase": "red", "cycleTime": 60, "mode": "auto"},
            "sign": {"message": "", "roadClosed": False},
            "alarm": {"alarmState": "off"},
            "dispatch": {"status": "idle", "unitsDispatched": 0, "incidentId": ""},
            "task": {"taskStatus": "none", "location": ""},
        }
        value = dict(actuator_defaults.get(d["kind"], {}))
        for key, attr in d["state"].items():
            if attr not in (None, 0, "", False):
                value[key] = attr
        return value

    # ---- the operations centre: the city status recomputed each tick ----
    def alerts_for(self, device_id: str) -> List[Tuple[str, str, str]]:
        d = self.devices[device_id]
        last = d["last"] or {}
        if d["mode"] == "dead" and d["ticks"] >= 2:
            return [(f"{device_id}:COMM_LOSS", "critical", f"{device_id} not reporting")]
        if d["kind"] == "traffic":
            c = float(last.get("congestionLevel", 0) or 0)
            if c >= 75: return [(f"{device_id}:TRAFFIC_JAM", "critical", f"{device_id} congestion {c:g}%")]
            if c >= 50: return [(f"{device_id}:TRAFFIC_JAM", "warning", f"{device_id} congestion {c:g}%")]
        elif d["kind"] == "building":
            smoke, temp = float(last.get("smokeLevel", 0) or 0), float(last.get("temperature", 0) or 0)
            if smoke >= 100 or temp >= 60:
                return [(f"{device_id}:FIRE", "critical", f"{device_id} smoke {smoke:g} ppm, {temp:g} C")]
            if smoke >= 10 or temp >= 38:
                return [(f"{device_id}:FIRE", "warning", f"{device_id} smoke {smoke:g} ppm, {temp:g} C")]
        elif d["kind"] == "camera" and last.get("dumpingDetected"):
            return [(f"{device_id}:DUMPING", "warning", f"{device_id} dumping detected")]
        elif d["kind"] == "bin":
            f = float(last.get("fillLevel", 0) or 0)
            if f >= 95: return [(f"{device_id}:BIN_FULL", "critical", f"{device_id} fill {f:g}%")]
            if f >= 80: return [(f"{device_id}:BIN_FULL", "warning", f"{device_id} fill {f:g}%")]
        return []

    def ops_summary(self) -> Dict[str, Any]:
        counts = {"normal": 0, "warning": 0, "critical": 0, "offline": 0}
        maxima = {"maxSmokeLevel": 0.0, "maxTemperature": 0.0, "maxFillLevel": 0, "avgCongestion": 0.0}
        congs, texts = [], []
        for device_id, d in self.devices.items():
            if d["kind"] == "ops":
                continue
            found = self.alerts_for(device_id)
            level = "critical" if any(s == "critical" for _, s, _ in found) else \
                    ("warning" if any(s == "warning" for _, s, _ in found) else
                     ("offline" if d["mode"] == "dead" else "normal"))
            counts[level] += 1
            for _, _, text in found:
                texts.append(text)
            last = d["last"] or {}
            if d["kind"] == "traffic":
                congs.append(float(last.get("congestionLevel", 0) or 0))
            if d["kind"] == "building":
                maxima["maxSmokeLevel"] = max(maxima["maxSmokeLevel"], float(last.get("smokeLevel", 0) or 0))
                maxima["maxTemperature"] = max(maxima["maxTemperature"], float(last.get("temperature", 0) or 0))
            if d["kind"] == "bin":
                maxima["maxFillLevel"] = max(maxima["maxFillLevel"], int(last.get("fillLevel", 0) or 0))
        maxima["avgCongestion"] = rnd(sum(congs) / len(congs)) if congs else 0.0
        worst = {"normal": 0, "warning": 1, "critical": 2, "offline": 1}[max(counts, key=counts.get)]
        status = ("NORMAL", "WARNING", "CRITICAL")[min(worst, 2)]
        return {
            "cityStatus": status,
            "devicesNormal": counts["normal"] + counts["offline"],
            "devicesWarning": counts["warning"],
            "devicesCritical": counts["critical"],
            "devicesOffline": counts["offline"],
            "activeAlerts": len(texts),
            "activeAlertsText": "; ".join(texts) if texts else "none",
            "emergencyStatus": texts[0] if texts else "No active emergency",
            **maxima,
            "lastEventMessage": texts[0] if texts else "none",
        }

    # ---- the Orion face -------------------------------------------------
    def entities(self) -> Dict[str, Dict[str, Any]]:
        """Entities in NGSI v2 wire shape (attr dicts), ready to serve."""
        out = {}
        for device_id, d in self.devices.items():
            entity: Dict[str, Any] = {}
            for key, value in (d["last"] or {}).items():
                if isinstance(value, bool):
                    ngsi_type = "Boolean"
                elif isinstance(value, (int, float)):
                    ngsi_type = "Number"
                else:
                    ngsi_type = "string"
                entity[key] = {"type": ngsi_type, "value": value}
            out[device_id] = entity
        return out

    def _stamp(self) -> str:
        # Microsecond precision: check runs poll faster than 1/s, and both the
        # dedup key and the sequence number are derived from this string —
        # two entities read within the same second must stay distinct.
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


# ----------------------------------------------------------------------
# The nine triplet scenarios, in Guardian-checkable step form.
# Steps: (tick_index, "mode"|"cmd"|"note", target, argument)
# Durations chosen so every rule has settled by the final tick, mirroring the
# twin/scenarios.json proportions at check scale (the runner compresses the
# 5 s wall-clock tick, not the semantics).
# ----------------------------------------------------------------------
SCENARIOS: Dict[str, Dict[str, Any]] = {
    "n1": {"title": "Calm day", "duration": 12, "steps": [(0, "note", "", "Normal day: no incident, no command")]},
    "a1": {"title": "Traffic jam", "duration": 12, "steps": [
        (1, "note", "", "Rush hour jam on roads 1 and 2"),
        (1, "mode", "us-a-traf-01", "jam"), (1, "mode", "us-a-traf-02", "jam"),
        (5, "cmd", "us-a-light-01", {"phase": "green", "mode": "manual"}),
        (5, "cmd", "us-a-sign-01", {"message": "Congestion ahead, use alternate route"})]},
    "b1": {"title": "Fire incident", "duration": 10, "steps": [
        (1, "note", "", "Real fire: smoke and temperature rise together"),
        (1, "mode", "us-b-bldg-01", "fire"),
        (4, "cmd", "us-b-alarm-01", {"alarmState": "on"}),
        (4, "cmd", "us-b-disp-01", {"status": "dispatched", "unitsDispatched": 2, "incidentId": "INC-B1"})]},
    "c1": {"title": "Waste / illegal dumping", "duration": 12, "steps": [
        (1, "note", "", "Illegal dumping next to a nearly full bin"),
        (1, "mode", "us-c-cam-01", "dump"), (1, "mode", "us-c-bin-01", "full"),
        (5, "cmd", "us-c-task-01", {"taskStatus": "created", "location": "collection point 1"})]},
    "g1": {"title": "Spoofed smoke", "duration": 9, "steps": [
        (1, "note", "", "Smoke 400 ppm but temperature normal: must be untrusted"),
        (1, "mode", "us-b-bldg-01", "spoof_smoke")]},
    "g2": {"title": "Sensor faults", "duration": 12, "steps": [
        (1, "note", "", "traffic-03 stuck, traffic-02 dead: both must be flagged"),
        (1, "mode", "us-a-traf-03", "stuck"), (1, "mode", "us-a-traf-02", "dead")]},
    "g3": {"title": "Fake traffic jam", "duration": 10, "steps": [
        (1, "note", "", "Constant jam values on road 3, never corroborated"),
        (1, "mode", "us-a-traf-03", "fake_jam")]},
    "m1": {"title": "Fire + fake jam", "duration": 10, "steps": [
        (1, "note", "", "Building on fire AND a fake jam: zone split verdicts"),
        (1, "mode", "us-b-bldg-01", "fire"), (1, "mode", "us-a-traf-03", "fake_jam"),
        (4, "cmd", "us-b-alarm-01", {"alarmState": "on"}),
        (4, "cmd", "us-b-disp-01", {"status": "dispatched", "unitsDispatched": 2, "incidentId": "INC-M1"})]},
    "d1": {"title": "Brain down", "duration": 10, "steps": [
        (1, "note", "", "Fire starts and the Brain is down: sensors stay trustworthy, nothing acts"),
        (1, "mode", "us-b-bldg-01", "fire")]},
}

# What each scenario must end with. Devices not named default to TRUSTED
# (or, for "*" rows, EVERY mapped sensor device must be TRUSTED).
EXPECT: Dict[str, Dict[str, str]] = {
    "n1": {"*": "TRUSTED"},
    "a1": {"us-a-traf-01": "TRUSTED", "us-a-traf-02": "TRUSTED", "us-a-traf-03": "TRUSTED"},
    "b1": {"us-b-bldg-01": "TRUSTED"},
    "c1": {"us-c-cam-01": "TRUSTED", "us-c-bin-01": "TRUSTED"},
    "g1": {"us-b-bldg-01": "UNTRUSTED"},
    "g2": {"us-a-traf-02": "OFFLINE", "us-a-traf-03": "UNTRUSTED",
           "us-a-traf-01": "TRUSTED"},
    "g3": {"us-a-traf-03": "UNTRUSTED", "us-a-traf-01": "TRUSTED", "us-a-traf-02": "TRUSTED"},
    "m1": {"us-b-bldg-01": "TRUSTED", "us-a-traf-03": "UNTRUSTED"},
    "d1": {"us-b-bldg-01": "TRUSTED", "us-c-bin-01": "TRUSTED", "us-c-cam-01": "TRUSTED"},
}


def run_scenario(name: str, world: Optional[World] = None,
                 tick_delay: float = 0.0, emit=None) -> List[str]:
    """Step a scenario; return the log lines the runner writes around it.

    `tick_delay` spaces the wall-clock between two ticks so a concurrent
    poller sees the same 5-s-proportioned timeline the Twin plays; 0.0 steps
    instantly (unit tests of the world itself).

    `emit` receives each line AS IT HAPPENS, which is what keeps a live log in
    chronological order: the Guardian's own CYCLE/GUARDIAN lines land between
    the world's PUBLISH lines instead of after them. The returned list is the
    same lines, for callers that only want the transcript.
    """
    sc = SCENARIOS[name]
    w = world or World()
    lines: List[str] = []

    def out(line: str) -> None:
        lines.append(line)
        if emit is not None:
            emit(line)

    out(f"{_clock()} SCENARIO {name} start: {sc['title']}")
    for step in range(sc["duration"]):
        if tick_delay:
            time.sleep(tick_delay)
        for (when, action, target, arg) in sc["steps"]:
            if_when = isinstance(when, int) and when == step
            if not if_when:
                continue
            if action == "note":
                out(f"{_clock()} NOTE {arg}")
            elif action == "mode":
                w.set_mode(target, arg)
                out(f"{_clock()} MODE {target}->{arg}")
            elif action == "cmd":
                w.command(target, arg)
                out(f"{_clock()} COMMAND {target} {json.dumps(arg)}")
        w.step()
        entities = w.entities()
        for device_id in sorted(entities):
            payload = json.dumps(entities[device_id], separators=(",", ":"))
            out(f"{_clock()} PUBLISH {device_id} {payload}")
    return lines


def _clock() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")
