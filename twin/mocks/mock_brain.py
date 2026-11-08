#!/usr/bin/env python3
"""
Mock BRAIN - lets the Twin be tested without the real City Brain layer.

It READS the sensors from the broker, decides, and WRITES commands on the actuator
records (the Twin polls those records and applies the commands).

Rules:
  - a traffic sensor with congestionLevel >= 75   -> light-01 green + manual, sign message
  - smoke >= 100 ppm or temperature >= 60 C       -> alarm on + emergency dispatch
  - camera dumpingDetected true or a bin >= 80 %  -> cleaning task created
If a Guardian is running (http://localhost:8090/verdicts) a sensor judged UNTRUSTED or
OFFLINE is ignored: the Brain must not act on spoofed data.

Run (from the twin/ folder):   python mocks/mock_brain.py
Config : ../config.json (broker URL, device ids and types)
Secrets: mocks/brain_secrets.json -> {"us-b-alarm-01": {"k1": "...", "k2": "..."}, ...}
         ONLY the keys of the ACTUATORS. The Brain does not need the sensors' keys.
"""
import json
import os
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.environ.get("TWIN_CONFIG", os.path.join(HERE, "..", "config.json"))
SECRETS = os.environ.get("MOCK_SECRETS", os.path.join(HERE, "brain_secrets.json"))
GUARDIAN = os.environ.get("GUARDIAN_URL", "http://localhost:8090/verdicts")
TIMEOUT = 10


def load(path):
    if not os.path.exists(path):
        sys.exit(f"File not found: {path}")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class Brain:
    def __init__(self, conf, secrets):
        self.base = conf["orion"]["base_url"].rstrip("/")
        self.devices = conf["devices"]
        self.keys = secrets
        self.sent = set()           # (device, reason) already commanded
        self.verdicts = {}
        self.prev_active = set()
        self.streak = {}
        self.guardian_up = False

    # ---- read ----------------------------------------------------------
    def read(self, dev_id):
        cfg = self.devices[dev_id]
        params = {"elementid": dev_id, "type": cfg["type"]}
        if self.keys.get(dev_id):   # actuators we own; public sensors are read without keys
            params.update(k1=self.keys[dev_id]["k1"], k2=self.keys[dev_id]["k2"])
        r = requests.get(f"{self.base}/v2/entities/{dev_id}", params=params, timeout=TIMEOUT)
        r.raise_for_status()
        return {k: v.get("value") for k, v in r.json().items() if isinstance(v, dict)}

    def trusted(self, dev_id):
        return self.verdicts.get(dev_id, {}).get("verdict", "TRUSTED") == "TRUSTED"

    def refresh_verdicts(self):
        try:
            self.verdicts = requests.get(GUARDIAN, timeout=2).json()
            self.guardian_up = True
        except (requests.RequestException, ValueError):
            self.verdicts, self.guardian_up = {}, False   # no Guardian running: trust everything

    def confirmed(self, key, condition):
        """With a Guardian, act only when the condition holds on 2 reads in a row, so the
        Guardian has time to mark a spoofed value UNTRUSTED first (a few seconds of delay)."""
        self.streak[key] = self.streak.get(key, 0) + 1 if condition else 0
        return self.streak[key] >= (2 if self.guardian_up else 1)

    # ---- write (a command) --------------------------------------------
    def command(self, dev_id, attrs, reason):
        key = (dev_id, reason)
        if key in self.sent:
            return
        cfg = self.devices.get(dev_id)
        sec = self.keys.get(dev_id)
        if not cfg or not sec:
            print(f"BRAIN cannot command {dev_id}: not in config or no keys")
            return
        body = {k: {"type": "float" if isinstance(v, (int, float)) and not isinstance(v, bool) else "string",
                    "value": v} for k, v in attrs.items()}
        r = requests.patch(f"{self.base}/v2/entities/{dev_id}/attrs", timeout=TIMEOUT,
                           params={"elementid": dev_id, "type": cfg["type"], "k1": sec["k1"], "k2": sec["k2"]},
                           json=body)
        if r.status_code < 300:
            self.sent.add(key)
            print(time.strftime("%H:%M:%S"), "BRAIN COMMAND", dev_id, json.dumps(attrs), "-", reason, flush=True)
        else:
            print("BRAIN command refused", dev_id, r.status_code, r.text[:120], flush=True)

    # ---- decisions -----------------------------------------------------
    def kinds(self, kind):
        return [i for i, c in self.devices.items() if c["kind"] == kind]

    def step(self):
        self.refresh_verdicts()
        active = set()
        for i in self.kinds("traffic"):
            v = self.read(i)
            if self.confirmed(i, self.trusted(i) and float(v.get("congestionLevel") or 0) >= 75):
                active.add("traffic")
                for light in self.kinds("light")[:1]:
                    self.command(light, {"phase": "green", "mode": "manual"}, "traffic jam")
                for sign in self.kinds("sign"):
                    self.command(sign, {"message": "Congestion ahead, use alternate route"}, "traffic jam")
        for i in self.kinds("building"):
            v = self.read(i)
            if self.confirmed(i, self.trusted(i) and (float(v.get("smokeLevel") or 0) >= 100
                                                       or float(v.get("temperature") or 0) >= 60)):
                active.add("fire")
                for a in self.kinds("alarm"):
                    self.command(a, {"alarmState": "on"}, "fire")
                for d in self.kinds("dispatch"):
                    self.command(d, {"status": "dispatched", "unitsDispatched": 2, "incidentId": "INC-BRAIN"}, "fire")
        for i in self.kinds("bin"):
            v = self.read(i)
            if self.confirmed(i, self.trusted(i) and float(v.get("fillLevel") or 0) >= 80):
                active.add("waste")
                for t in self.kinds("task"):
                    self.command(t, {"taskStatus": "created", "location": f"empty {i}"}, "bin full")
        for i in self.kinds("camera"):
            v = self.read(i)
            if self.confirmed(i, self.trusted(i) and str(v.get("dumpingDetected")).lower() == "true"):
                active.add("waste")
                for t in self.kinds("task"):
                    self.command(t, {"taskStatus": "created", "location": "collection point 1"}, "dumping")
        # release: when an incident is over, put the actuators back to normal
        if "traffic" in self.prev_active and "traffic" not in active:
            for light in self.kinds("light")[:1]:
                self.command(light, {"phase": "red", "mode": "auto"}, "traffic cleared")
            for sign in self.kinds("sign"):
                self.command(sign, {"message": "Normal traffic"}, "traffic cleared")
        if "fire" in self.prev_active and "fire" not in active:
            for a in self.kinds("alarm"):
                self.command(a, {"alarmState": "off"}, "fire cleared")
        self.prev_active = active
        # forget finished incidents so a later one is handled again
        reasons = {"traffic": ("traffic jam",), "fire": ("fire",), "waste": ("dumping", "bin full")}
        self.sent = {k for k in self.sent if any(k[1] in reasons[a] for a in active)}  # "...cleared" is sent once


if __name__ == "__main__":
    brain = Brain(load(CONFIG), load(SECRETS))
    print("Mock Brain running (Ctrl+C to stop)")
    try:
        while True:
            try:
                brain.step()
            except requests.RequestException as exc:
                print("BRAIN cannot reach the broker:", type(exc).__name__, flush=True)
            time.sleep(3)
    except KeyboardInterrupt:
        pass
