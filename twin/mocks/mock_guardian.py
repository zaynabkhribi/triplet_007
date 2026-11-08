#!/usr/bin/env python3
"""
Mock GUARDIAN - lets the Twin be tested without the real Guardian layer.

It READS the Twin's sensors from the broker and decides, per sensor, whether the data
can be trusted. It publishes its verdicts as JSON on http://localhost:8090/verdicts.

Rules (simple on purpose, the real Guardian is the partner's job):
  - smoke very high but temperature normal        -> UNTRUSTED  (spoofed smoke)
  - the value did not change for 6 reads          -> UNTRUSTED  (stuck sensor)
  - no new timestamp for 20 s                     -> OFFLINE    (dead sensor)

Run (from the twin/ folder):   python mocks/mock_guardian.py
Config: ../config.json (device list, broker URL). Reading public devices needs no key.
If a device has keys in MOCK_SECRETS they are used (needed on a private broker).
"""
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.environ.get("TWIN_CONFIG", os.path.join(HERE, "..", "config.json"))
SECRETS = os.environ.get("MOCK_SECRETS", os.path.join(HERE, "guardian_secrets.json"))
PORT = int(os.environ.get("GUARDIAN_PORT", "8090"))
SENSOR_KINDS = {"traffic", "building", "camera", "bin"}
VERDICTS = {}
HISTORY = {}


def load(path, default):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    return default


def read_entity(base, dev_id, dev_type, keys):
    params = {"elementid": dev_id, "type": dev_type}
    if keys.get(dev_id):
        params.update(k1=keys[dev_id]["k1"], k2=keys[dev_id]["k2"])
    r = requests.get(f"{base}/v2/entities/{dev_id}", params=params, timeout=10)
    r.raise_for_status()
    data = r.json()
    return {k: v.get("value") for k, v in data.items() if isinstance(v, dict)}


def judge(dev_id, kind, values, hist):
    ts = values.get("timestamp")
    payload = {k: v for k, v in values.items() if k not in ("timestamp", "latitude", "longitude", "model")}
    if "ts" in hist and hist["ts"] == ts:
        if time.time() - hist["since"] > 20:
            return "OFFLINE", "no new data for 20 s"
    else:
        hist.update(ts=ts, since=time.time())
    if hist.get("payload") == payload:
        hist["same"] = hist.get("same", 0) + 1
    else:
        hist.update(payload=payload, same=0)
    if kind == "building":
        smoke, temp = float(values.get("smokeLevel") or 0), float(values.get("temperature") or 0)
        if smoke >= 300 and temp < 30:
            return "UNTRUSTED", f"smoke {smoke} ppm but temperature only {temp} C"
    if kind == "traffic" and hist["same"] >= 6:
        return "UNTRUSTED", "value never changes (stuck or replayed)"
    return "TRUSTED", ""


def loop(conf):
    base = conf["orion"]["base_url"].rstrip("/")
    keys = load(SECRETS, {})
    while True:
        for dev_id, cfg in conf["devices"].items():
            if cfg["kind"] not in SENSOR_KINDS:
                continue
            try:
                values = read_entity(base, dev_id, cfg["type"], keys)
                verdict, why = judge(dev_id, cfg["kind"], values, HISTORY.setdefault(dev_id, {}))
            except requests.RequestException as exc:
                verdict, why = "OFFLINE", f"cannot read: {type(exc).__name__}"
            if VERDICTS.get(dev_id, {}).get("verdict") != verdict:
                print(time.strftime("%H:%M:%S"), "GUARDIAN", dev_id, verdict, why, flush=True)
            VERDICTS[dev_id] = {"verdict": verdict, "reason": why, "checked": time.strftime("%H:%M:%S")}
        time.sleep(3)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = json.dumps(VERDICTS).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    if not os.path.exists(CONFIG):
        sys.exit(f"Config not found: {CONFIG}")
    conf = load(CONFIG, {})
    threading.Thread(target=loop, args=(conf,), daemon=True).start()
    print(f"Mock Guardian: verdicts on http://localhost:{PORT}/verdicts  (Ctrl+C to stop)")
    try:
        ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        pass
