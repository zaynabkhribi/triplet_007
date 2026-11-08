"""Runs the city: configuration, the tick loop, scenario control and the command line runs."""
import json
import logging
import os
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from model import City, Device
from scenarios import SCENARIOS, SCENARIO_INFO, run_step, scenario_resolved, validate_scenarios
from schema import ACTUATORS, INITIAL_STATE, KNOWN_KINDS
from settings import CONFIG_PATH, LOG_DIR, SECRETS_PATH, log, now_iso


def load_json(path, what, hint):
    if not os.path.exists(path):
        sys.exit(f"{what} not found: {path}\n{hint}")
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except ValueError as exc:
        sys.exit(f"{what} is not valid JSON ({path}): {exc}")


def load_conf():
    """Config and secrets come from the files, or from the environment variables
    TWIN_CONFIG_JSON / TWIN_SECRETS_JSON (the whole JSON text) when hosted on a server."""
    if os.environ.get("TWIN_CONFIG_JSON"):
        conf = json.loads(os.environ["TWIN_CONFIG_JSON"])
    else:
        conf = load_json(CONFIG_PATH, "Config", "config.json is part of the repository (twin/config.json). Check you run from the twin folder.")
    if os.environ.get("TWIN_SECRETS_JSON"):
        secrets = json.loads(os.environ["TWIN_SECRETS_JSON"])
    else:
        secrets = load_json(SECRETS_PATH, "Secrets file", "Copy secrets.example.json to secrets.json and fill K1/K2.")
    validate_conf(conf)
    validate_scenarios(SCENARIOS, conf)
    return conf, secrets


def validate_conf(conf):
    """Clear messages for a config.json that does not fit the Twin."""
    if not isinstance(conf.get("orion"), dict) or not conf["orion"].get("base_url"):
        sys.exit("config.json: 'orion.base_url' is missing (the Orion Broker Filter address)")
    if not conf.get("devices"):
        sys.exit("config.json: 'devices' is missing or empty")
    for dev_id, cfg in conf["devices"].items():
        if "kind" not in cfg or "type" not in cfg:
            sys.exit(f"config.json: device {dev_id} needs 'kind' and 'type'")
        if cfg["kind"] not in KNOWN_KINDS:
            sys.exit(f"config.json: device {dev_id} has unknown kind {cfg['kind']!r}; use {', '.join(sorted(KNOWN_KINDS))}")


def build_city(conf, secrets):
    city = City(conf.get("thresholds"), conf.get("effects"))
    for dev_id, cfg in conf["devices"].items():
        sec = secrets.get(dev_id, {})
        missing = [] if sec.get("cert") else [k for k in ("k1", "k2") if not sec.get(k)]
        if missing:
            log.warning("No %s for %s in secrets file", "/".join(missing), dev_id)
        city.devices[dev_id] = Device(dev_id, cfg, secrets, conf, city)
    return city


def setup_logging(log_file=None):
    log.setLevel(logging.INFO)
    log.handlers.clear()
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(asctime)s %(message)s", "%H:%M:%S"))
    log.addHandler(console)
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        log.addHandler(fh)


def cmd_list(conf):
    print("Devices:")
    for dev_id, cfg in conf["devices"].items():
        print(f"  {dev_id:16s} {cfg['kind']:9s} {cfg['type']}")
    print("Scenarios:", ", ".join(SCENARIOS))


def initial_payload(dev):
    if dev.kind in ACTUATORS:
        return dict(dev.state, timestamp=now_iso())
    return dev.reading()


def cmd_check(conf, secrets):
    setup_logging()
    city = build_city(conf, secrets)
    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(lambda d: (d.id, d.send(initial_payload(d))), city.devices.values()))
    bad = [dev_id for dev_id, ok in results if not ok]
    print(f"\nAccepted by the broker: {len(results) - len(bad)}/{len(results)}")
    if bad:
        print("FAILED:", ", ".join(bad))
        print("401 = wrong K1/K2 or wrong id/type; 404 = wrong base_url; see the lines above.")
        sys.exit(1)


def tick_device(dev):
    if dev.kind in ACTUATORS:
        dev.poll_commands()
    p = dev.reading()
    if p:
        dev.send(p)


def cmd_run(conf, secrets, name, forever=False):
    if name not in SCENARIOS:
        sys.exit(f"Unknown scenario {name}. Available: {', '.join(SCENARIOS)}")
    os.makedirs(LOG_DIR, exist_ok=True)
    log_file = os.path.join(LOG_DIR, f"{name}-{datetime.now():%Y%m%d-%H%M%S}.log")
    setup_logging(log_file)
    log.info("SCENARIO %s start", name)

    city = build_city(conf, secrets)
    steps = sorted(SCENARIOS[name]["steps"], key=lambda s: s[0])
    duration = SCENARIOS[name]["duration"]
    tick = conf.get("tick_seconds", 5)
    start, next_tick, i = time.time(), 0.0, 0
    with ThreadPoolExecutor(8) as pool:
        try:
            while True:
                el = time.time() - start
                while i < len(steps) and steps[i][0] <= el:
                    run_step(city, steps[i])
                    i += 1
                if el >= next_tick:
                    city.step()
                    list(pool.map(tick_device, city.devices.values()))
                    next_tick += tick
                if el >= duration and not forever:
                    break
                time.sleep(0.2)
        except KeyboardInterrupt:
            log.info("INTERRUPTED")
        finally:
            log.info("SCENARIO %s end", name)
    print("Log written to", log_file)


TAGS = (("SCENARIO", "SCENARIO"), ("NOTE", "SCENARIO"), ("RESET", "SCENARIO"), ("MODE", "TWIN"),
        ("ALERT", "ALERT"), ("COMMAND", "BRAIN"), ("RECEIVED", "BRAIN"), ("REJECTED", "BRAIN"),
        ("EFFECT", "EFFECT"), ("RECOVERED", "EFFECT"))


class TimelineHandler(logging.Handler):
    """Keeps the important log lines (not every PUBLISH) for the live timeline."""

    def __init__(self):
        super().__init__()
        self.events = deque(maxlen=200)

    def emit(self, record):
        msg = record.getMessage()
        word = msg.split(" ", 1)[0]
        tag = next((t for w, t in TAGS if word == w), None)
        if tag is None and word.endswith("_FAIL"):
            tag = "ERROR"
        if tag:
            rest = msg.split(" ", 1)[1] if " " in msg and tag != "ERROR" else msg
            self.events.append({"t": datetime.fromtimestamp(record.created).strftime("%H:%M:%S"),
                                "tag": tag, "msg": rest})


class Engine:
    def __init__(self, conf, secrets):
        self.conf = conf
        self.city = build_city(conf, secrets)
        self.tick = conf.get("tick_seconds", 5)
        self.lock = threading.Lock()
        self.scenario = None
        self.file_handler = None
        self.last_tick = None
        self.next_tick = 0.0
        self.mock_brain = True
        self.timeline = TimelineHandler()
        log.addHandler(self.timeline)
        self.pool = ThreadPoolExecutor(8)
        self.stop_flag = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def begin(self):
        self.thread.start()

    def loop(self):
        while not self.stop_flag.is_set():
            now = time.time()
            with self.lock:
                sc = self.scenario
                if sc:
                    el = now - sc["t0"]
                    while sc["i"] < len(sc["steps"]) and sc["steps"][sc["i"]][0] <= el:
                        step = sc["steps"][sc["i"]]
                        if step[1] == "cmd" and not self.mock_brain:
                            log.info("NOTE mock Brain is OFF: waiting for the real Brain to command %s", step[2])
                        else:
                            run_step(self.city, step)
                        sc["i"] += 1
                    if sc["resolved_at"] is None and scenario_resolved(sc["name"], self.city, sc):
                        sc["resolved_at"] = now
                        log.info("NOTE incident resolved: the city is back to normal")
                    if (sc["resolved_at"] is None and
                            sc.get("finish_after_duration") and
                            now - sc["t0"] >= sc["duration"]):
                        sc["resolved_at"] = now
                        log.info("NOTE scenario duration completed")
                    if sc["resolved_at"] is not None and now - sc["resolved_at"] >= 2 * self.tick:
                        self._end_scenario("end (resolved)")
                if now >= self.next_tick:
                    self.city.step()
                    list(self.pool.map(tick_device, self.city.devices.values()))
                    self.last_tick = time.time()
                    self.next_tick = self.last_tick + self.tick
            time.sleep(0.2)

    def _end_scenario(self, how):
        sc = self.scenario
        log.info("SCENARIO %s %s", sc["name"], how)
        if self.file_handler:
            log.removeHandler(self.file_handler)
            self.file_handler.close()
            self.file_handler = None
        self.scenario = None

    def start(self, name):
        if name not in SCENARIOS or name == "calm":
            return False, f"unknown scenario {name}"
        with self.lock:
            if self.scenario:
                return False, f"scenario {self.scenario['name']} is already running; stop it first"
            os.makedirs(LOG_DIR, exist_ok=True)
            path = os.path.join(LOG_DIR, f"{name}-{datetime.now():%Y%m%d-%H%M%S}.log")
            self.file_handler = logging.FileHandler(path, encoding="utf-8")
            self.file_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
            log.addHandler(self.file_handler)
            log.info("SCENARIO %s start", name)
            spec = SCENARIOS[name]
            self.scenario = {"name": name, "t0": time.time(), "i": 0, "duration": spec["duration"],
                             "steps": sorted(spec["steps"], key=lambda s: s[0]), "log": path,
                             "resolved_at": None,
                             "finish_after_duration": spec.get("finish_after_duration", False)}
        return True, path

    def set_brain(self, on):
        self.mock_brain = bool(on)
        log.info("NOTE mock Brain %s", "ON: the scenario commands the actuators itself"
                 if on else "OFF: the actuators wait for the real Brain or the dashboard")

    def stop(self):
        with self.lock:
            if self.scenario:
                self._end_scenario("stopped by operator")
            for d in self.city.devices.values():
                d.mode, d.ticks = "normal", 0
                if d.kind in INITIAL_STATE:
                    d.state = dict(INITIAL_STATE[d.kind])
            self.city.reset()
            log.info("RESET city back to normal")
            self.next_tick = 0.0
            for d in self.city.devices.values():
                if d.kind in ACTUATORS:
                    d.publish_state()
        return True

    # ---- data for the page ------------------------------------------------
    NAMES = {"traffic": "Traffic sensor", "light": "Traffic light", "sign": "Message sign",
             "building": "Building sensor", "alarm": "Fire alarm", "dispatch": "Emergency dispatch",
             "camera": "Dumping camera", "bin": "Waste bin", "task": "Cleaning task"}

    def device_rows(self):
        rows = []
        for d in self.city.devices.values():
            if d.kind == "ops":
                continue
            level, _ = self.city._alerts_for(d)
            parts = d.id.split("-")                      # us-a-traf-01
            zone = parts[1].upper() if len(parts) > 2 else ""
            num = parts[-1] if parts[-1].isdigit() and d.kind in ("traffic", "light", "bin") else ""
            rows.append({"id": d.id, "name": f"Zone {zone} - {self.NAMES.get(d.kind, d.kind)} {num}".strip(),
                         "kind": "actuator" if d.kind in ACTUATORS else "sensor",
                         "level": level, "online": level != "offline"})
        return rows

    def status(self):
        ops = next((d.last for d in self.city.devices.values() if d.kind == "ops" and d.last), None)
        alerts = []
        for key, (sev, typ, text) in dict(self.city.ops_alerts).items():
            alerts.append({"severity": sev, "type": typ, "where": text,
                           "since": self.city.alert_since.get(key, "")})
        alerts.sort(key=lambda a: (a["severity"] != "critical", a["since"]))
        act, sens = [], []
        for d in self.city.devices.values():
            if d.kind == "ops" or not d.last:
                continue
            vals = {k: v for k, v in d.last.items() if k != "timestamp"}
            text = ", ".join(f"{k}={v}" for k, v in vals.items())
            (act if d.kind in ACTUATORS else sens).append({"id": d.id, "text": text})
        sc = self.scenario
        scen = None
        if sc:
            info = SCENARIO_INFO.get(sc["name"], ("", sc["name"], ""))
            scen = {"name": sc["name"], "title": info[1], "elapsed": time.time() - sc["t0"],
                    "resolved": sc["resolved_at"] is not None}
        return {
            "city": ops, "alerts": alerts, "actuators": act, "sensors": sens, "scenario": scen,
            "events": list(self.timeline.events)[-200:],
            "devices": self.device_rows(),
            "modes": {d.id: d.mode for d in self.city.devices.values()},
            "raw": {d.id: {k: v for k, v in d.last.items() if k != "timestamp"}
                    for d in self.city.devices.values() if d.last and d.kind != "ops"},
            "telemetryAge": None if self.last_tick is None else time.time() - self.last_tick,
            "scenarios": [{"id": k, "zone": v[0], "title": v[1], "description": v[2]}
                          for k, v in SCENARIO_INFO.items() if k in SCENARIOS],
            "dashboard_url": self.conf.get("ui", {}).get("dashboard_url", ""),
            "mock_brain": self.mock_brain,
        }
