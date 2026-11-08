"""The simulated city: devices that produce readings, and the cause and effect between
actuators and sensors. No HTTP here (see orion_client.py) and no web page (see web.py)."""
import json
import os
import random
import sys
import threading
import time
from datetime import datetime

from orion_client import OrionClient
from schema import (ACTUATORS, ALLOWED_COMMANDS, BROKER_ATTRS, DEFAULT_EFFECTS, DEFAULT_THRESHOLDS,
                    INITIAL_STATE, from_attr, validate_command)
from settings import SECRETS_PATH, log, now_iso, rnd


# --------------------------------------------------------------------------
# One device = one NGSI entity on the broker
# --------------------------------------------------------------------------
class Device:
    def __init__(self, dev_id, cfg, secrets, conf, city):
        self.id = dev_id
        self.kind = cfg["kind"]
        self.type = cfg["type"]
        self.city = city
        sec = secrets.get(dev_id, {})
        self.client = OrionClient(dev_id, self.type, conf["orion"], sec,
                                  os.path.dirname(os.path.abspath(SECRETS_PATH)))
        self.mode = "normal"
        self.ticks = 0
        self.last = None
        self.state = dict(INITIAL_STATE.get(self.kind, {}))
        self.remote_seen = None   # last command attributes seen on the broker
        self.warned = set()       # unknown attributes already reported

    # ---- Broker access: delegated to the client ----------------------------
    def send(self, payload):
        """Push attributes to the broker. Returns True on success."""
        return self.client.send(payload)

    def fetch(self):
        """Read the entity from the broker (actuators: look for commands)."""
        return self.client.fetch()

    # ---- Commands (actuators) ------------------------------------------
    def poll_commands(self):
        """Detect values written on the actuator entity by someone else."""
        rules = ALLOWED_COMMANDS.get(self.kind)
        if rules is None:
            return
        data = self.fetch()
        if data is None:
            return
        if not isinstance(data, dict):
            log.warning("IGNORED %s: the broker answered %s instead of one entity (a JSON object)",
                        self.id, type(data).__name__)
            return
        for key in data:
            if key not in rules and key not in BROKER_ATTRS and key not in self.warned:
                self.warned.add(key)
                log.warning("IGNORED %s: unknown attribute %r on the entity; this device accepts %s",
                            self.id, key, ", ".join(rules))
        remote = {}
        for key in rules:
            attr = data.get(key)
            if isinstance(attr, dict):
                value = from_attr(key, attr.get("value"))
                if value is not None:
                    remote[key] = value
        if self.remote_seen is None:          # first look: baseline, no command
            self.remote_seen = remote
            return
        changed = {k: v for k, v in remote.items()
                   if v != self.remote_seen.get(k) and v != self.state.get(k)}
        self.remote_seen = remote
        if changed:
            log.info("RECEIVED %s %s", self.id, json.dumps(changed))
            if not self.apply_command(changed, source="broker"):
                self.publish_state()           # restore the real state on the broker

    def apply_command(self, payload, source="local"):
        problem = validate_command(self.kind, payload)
        if problem:
            log.warning("REJECTED %s: %s", self.id, problem)
            return False
        self.state.update(payload)
        log.info("COMMAND %s (%s) %s", self.id, source, json.dumps(payload))
        self.city.on_command(self, payload)
        self.publish_state()
        return True

    def publish_state(self):
        p = dict(self.state)
        p["timestamp"] = now_iso()
        self.last = dict(p)
        if self.send(p):
            self.remote_seen = {k: self.state[k] for k in ALLOWED_COMMANDS.get(self.kind, {})
                                if k in self.state}

    def set_mode(self, mode):
        self.mode = mode
        self.ticks = 0
        if self.kind == "traffic" and mode == "jam":      # a new jam starts from scratch
            self.city.relief_active, self.city.relief = False, 0
        if self.kind == "building" and mode == "fire":
            self.city.alarm_ticks = self.city.suppress = 0
        log.info("MODE %s -> %s", self.id, mode)

    # ---- Readings (sensors) ---------------------------------------------
    def reading(self):
        self.ticks += 1
        if self.mode == "dead":
            return None
        if self.mode == "stuck" and self.last is not None:
            p = dict(self.last)
            p["timestamp"] = now_iso()
            return p
        if self.kind == "traffic":
            p = self._traffic()
        elif self.kind == "building":
            p = self._building()
        elif self.kind == "camera":
            p = self._camera()
        elif self.kind == "bin":
            p = self._bin()
        elif self.kind == "ops":
            p = self.city.ops_summary()
        else:  # actuators re-publish their state
            p = dict(self.state)
        p["timestamp"] = now_iso()
        self.last = dict(p)
        return p

    def _traffic(self):
        level = 0.0
        if self.mode == "jam":
            ramp = min(1.0, 0.3 + 0.1 * self.ticks)   # builds up: warning, then critical
            level = max(0.0, ramp - self.city.relief * 0.2)
            if level == 0.0:
                log.info("RECOVERED %s: traffic back to normal", self.id)
                self.mode = "normal"
        elif self.mode == "fake_jam":  # spoofed data, never recovers
            level = 1.0
        flow = 20 + 55 * level + random.uniform(-3, 3)
        speed = 50 - 42 * level + random.uniform(-3, 3)
        occ = 15 + 75 * level + random.uniform(-2, 2)
        return {
            "vehicleCount": int(max(flow, 0)),
            "avgSpeed": rnd(max(speed, 2)),
            "occupancy": rnd(min(occ, 100)),
            "congestionLevel": int(min(occ, 100)),
        }

    def _building(self):
        if self.mode == "fire":
            t = self.ticks
            temp = min(22 + 12 * t, 300)
            smoke = min(20 * t, 500)
            occupancy = max(0, 15 - 3 * self.city.alarm_ticks) if self.city.alarm_ticks else 15
        elif self.mode == "spoof_smoke":  # smoke without heat = suspicious
            temp, smoke, occupancy = 22 + random.uniform(-0.4, 0.4), 400, 15
        else:
            temp = 22 + random.uniform(-0.4, 0.4)
            smoke = max(0, 2 + random.uniform(-1, 1))
            occupancy = 15
        return {"smokeLevel": rnd(smoke), "temperature": rnd(temp), "occupancyCount": int(occupancy)}

    def _camera(self):
        if self.mode == "dump":
            return {"dumpingDetected": True, "confidence": 0.9, "status": "active",
                    "message": "illegal dumping detected"}
        return {"dumpingDetected": False, "confidence": 0.0, "status": "active", "message": "ok"}

    def _bin(self):
        if self.mode == "full":
            self.state["fill"] = min(97.0, self.state["fill"] + 15.0)
        else:
            self.state["fill"] += 0.3
            if self.state["fill"] >= 70:      # the routine collection round empties a normal bin
                self.state["fill"] = 5.0
                log.info("EFFECT %s emptied by the routine collection round", self.id)
        return {"fillLevel": int(min(100.0, self.state["fill"]))}


# --------------------------------------------------------------------------
# The city: cause-and-effect between actuators and sensors
# --------------------------------------------------------------------------
class City:
    def __init__(self, thresholds=None, effects=None):
        self.devices = {}
        self.th = dict(DEFAULT_THRESHOLDS, **(thresholds or {}))
        self.fx = dict(DEFAULT_EFFECTS, **(effects or {}))
        self.reset()

    def reset(self):
        self.relief_active = False
        self.relief = 0          # ticks since a traffic response was applied
        self.alarm_ticks = 0
        self.suppress = 0        # ticks with alarm + units on site
        self.cleaning_ticks = 0
        self.ops_lock = threading.Lock()
        self.ops_alerts = {}     # key -> (severity, type, text), previous state
        self.alert_since = {}    # key -> time the alert was first raised
        self.last_event = ("", "")   # (time, message)

    # ---- Operations centre: the city status shown on the dashboard --------
    SEVERITY = {"normal": 0, "warning": 1, "critical": 2}

    def _alerts_for(self, d):
        """Return (level, [alerts]) for one device. alert = (key, severity, type, text)."""
        if d.mode == "dead" and d.ticks >= self.th["offline_after_ticks"]:
            return "offline", [(f"{d.id}:COMM_LOSS", "critical", "COMM_LOSS", f"{d.id} not reporting")]
        th = self.th
        last = d.last or {}
        out = []
        if d.kind == "traffic":
            c = last.get("congestionLevel", 0)
            if c >= th["traffic_critical"]:
                out.append((f"{d.id}:TRAFFIC_JAM", "critical", "TRAFFIC_JAM", f"{d.id} congestion {c}%"))
            elif c >= th["traffic_warning"]:
                out.append((f"{d.id}:TRAFFIC_JAM", "warning", "TRAFFIC_JAM", f"{d.id} congestion {c}%"))
        elif d.kind == "building":
            smoke, temp = last.get("smokeLevel", 0), last.get("temperature", 0)
            if smoke >= th["smoke_critical"] or temp >= th["temperature_critical"]:
                out.append((f"{d.id}:FIRE", "critical", "FIRE", f"{d.id} smoke {smoke} ppm, {temp} C"))
            elif smoke >= th["smoke_warning"] or temp >= th["temperature_warning"]:
                out.append((f"{d.id}:FIRE", "warning", "FIRE", f"{d.id} smoke {smoke} ppm, {temp} C"))
        elif d.kind == "camera":
            if last.get("dumpingDetected") is True:
                out.append((f"{d.id}:DUMPING", "warning", "ILLEGAL_DUMPING", f"{d.id} dumping detected"))
        elif d.kind == "bin":
            f = last.get("fillLevel", 0)
            if f >= th["fill_critical"]:
                out.append((f"{d.id}:BIN_FULL", "critical", "BIN_FULL", f"{d.id} fill {f}%"))
            elif f >= th["fill_warning"]:
                out.append((f"{d.id}:BIN_FULL", "warning", "BIN_FULL", f"{d.id} fill {f}%"))
        level = "normal"
        for _, sev, _, _ in out:
            if self.SEVERITY[sev] > self.SEVERITY[level]:
                level = sev
        return level, out

    def ops_summary(self):
        with self.ops_lock:
            counts = {"normal": 0, "warning": 0, "critical": 0, "offline": 0}
            alerts = {}
            for d in self.devices.values():
                if d.kind == "ops":
                    continue
                level, found = self._alerts_for(d)
                counts[level] += 1
                for key, sev, typ, text in found:
                    alerts[key] = (sev, typ, text)
            # events: what was raised / cleared since the previous summary
            for key, (sev, typ, text) in alerts.items():
                if key not in self.ops_alerts:
                    self.alert_since[key] = datetime.now().strftime("%H:%M:%S")
                    self.last_event = (now_iso(), f"RAISED {sev.upper()} {typ}: {text}")
                    log.info("ALERT %s", self.last_event[1])
            for key, (sev, typ, text) in self.ops_alerts.items():
                if key not in alerts:
                    self.alert_since.pop(key, None)
                    self.last_event = (now_iso(), f"CLEARED {typ}: {text}")
                    log.info("ALERT %s", self.last_event[1])
            for key, (sev, typ, text) in alerts.items():
                old = self.ops_alerts.get(key)
                if old and old[0] != sev and self.SEVERITY[sev] > self.SEVERITY[old[0]]:
                    self.last_event = (now_iso(), f"ESCALATED {sev.upper()} {typ}: {text}")
                    log.info("ALERT %s", self.last_event[1])
            self.ops_alerts = alerts

            worst = max((self.SEVERITY[a[0]] for a in alerts.values()), default=0)
            status = ("NORMAL", "WARNING", "CRITICAL")[worst]
            texts = sorted(f"{a[0].upper()} {a[1]}" for a in alerts.values())
            parts = []
            fire = [k for k, a in alerts.items() if a[1] == "FIRE"]
            if fire:
                alarm = any(d.state.get("alarmState") == "on" for d in self.of_kind("alarm"))
                units = sum(int(d.state.get("unitsDispatched", 0)) for d in self.of_kind("dispatch"))
                parts.append(f"FIRE: alarm {'ON' if alarm else 'off'}, {units} units dispatched")
            jams = [k for k, a in alerts.items() if a[1] == "TRAFFIC_JAM" and a[0] == "critical"]
            if jams:
                green = any(d.state.get("phase") == "green" for d in self.of_kind("light"))
                sign = any(d.state.get("message") for d in self.of_kind("sign"))
                parts.append(f"TRAFFIC: {len(jams)} roads jammed, light {'green' if green else 'not changed'}, "
                             f"sign {'message shown' if sign else 'no message'}")
            waste = [k for k, a in alerts.items()
                     if a[1] == "ILLEGAL_DUMPING" or (a[1] == "BIN_FULL" and a[0] == "critical")]
            if waste:
                tasks = [d.state.get("taskStatus", "none") for d in self.of_kind("task")]
                parts.append(f"WASTE: cleaning task {tasks[0] if tasks else 'none'}")
            emergency = " | ".join(parts) if parts else "No active emergency"

            def vals(kind, key):
                return [d.last[key] for d in self.of_kind(kind) if d.last and key in d.last]
            cong, smoke, temp, fill = (vals("traffic", "congestionLevel"), vals("building", "smokeLevel"),
                                       vals("building", "temperature"), vals("bin", "fillLevel"))
            return {
                "cityStatus": status,
                "devicesNormal": counts["normal"],
                "devicesWarning": counts["warning"],
                "devicesCritical": counts["critical"],
                "devicesOffline": counts["offline"],
                "activeAlerts": len(alerts),
                "activeAlertsText": "; ".join(texts) if texts else "none",
                "emergencyStatus": emergency,
                "avgCongestion": rnd(sum(cong) / len(cong)) if cong else 0,
                "maxSmokeLevel": max(smoke, default=0),
                "maxTemperature": max(temp, default=0),
                "maxFillLevel": max(fill, default=0),
                "lastEventTime": self.last_event[0],
                "lastEventMessage": self.last_event[1] or "none",
            }

    def of_kind(self, kind):
        return [d for d in self.devices.values() if d.kind == kind]

    def on_command(self, dev, payload):
        if dev.kind == "light" and (payload.get("phase") == "green" or payload.get("mode") == "manual"):
            self.relief_active = True
        if dev.kind == "sign" and (payload.get("roadClosed") is True or payload.get("message")):
            self.relief_active = True
        if dev.kind == "task" and payload.get("taskStatus") == "created":
            self.cleaning_ticks = 0

    def step(self):
        """Called once per tick, before readings are published."""
        if self.relief_active:
            self.relief += 1

        alarm_on = any(d.state["alarmState"] == "on" for d in self.of_kind("alarm"))
        units = any(d.state["status"] in ("dispatched", "onScene") for d in self.of_kind("dispatch"))
        if alarm_on:
            self.alarm_ticks += 1
        fire = [d for d in self.of_kind("building") if d.mode == "fire"]
        if fire and alarm_on and units:
            self.suppress += 1
            if self.suppress >= self.fx["fire_suppress_ticks"]:
                for d in fire:
                    d.set_mode("normal")
                for d in self.of_kind("dispatch"):
                    d.state.update({"status": "idle", "unitsDispatched": 0})
                    d.publish_state()
                log.info("EFFECT fire extinguished by dispatched units")
                self.suppress = 0

        pending = [d for d in self.of_kind("task") if d.state["taskStatus"] == "created"]
        if pending:
            self.cleaning_ticks += 1
            if self.cleaning_ticks >= self.fx["cleaning_ticks"]:
                for d in pending:
                    d.state["taskStatus"] = "done"
                    d.publish_state()
                for d in self.of_kind("camera"):
                    d.set_mode("normal")
                for d in self.of_kind("bin"):
                    d.state["fill"] = 5.0
                    d.set_mode("normal")
                log.info("EFFECT cleaning done: dumping cleared, bins emptied")