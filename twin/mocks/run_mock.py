#!/usr/bin/env python3
"""
Run the whole Twin with MOCKS only - no platform, no keys, no other team needed.

Starts, in one window:
  - a fake broker      (stands for the platform's Orion)         port 8099
  - the Twin           (+ the Scenario Control page)             http://localhost:8080
  - a mock Guardian    (judges the sensors)                      port 8090
  - a mock Brain       (reads the sensors, commands the actuators)

From the twin/ folder:     python mocks/run_mock.py
Open http://localhost:8080, launch a scenario, watch the Brain act. Ctrl+C stops everything.
Files it creates (safe to delete): twin/mock_run/
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
RUN = os.path.join(ROOT, "mock_run")
ACTUATORS = {"light", "sign", "alarm", "dispatch", "task"}
UI_PORT = int(os.environ.get("MOCK_UI_PORT", "8080"))


def prepare():
    os.makedirs(RUN, exist_ok=True)
    src = os.path.join(ROOT, "config.json")
    if not os.path.exists(src):
        src = os.path.join(ROOT, "config.example.json")
    with open(src, encoding="utf-8") as fh:
        conf = json.load(fh)
    conf["orion"].update(base_url="http://127.0.0.1:8099/orion-filter/orion-1", api="v2", ca=None)
    conf["tick_seconds"] = 3
    conf["guardian"] = {"verdicts_url": "http://127.0.0.1:8090/verdicts"}
    secrets = {d: {"k1": f"k1-{d}", "k2": f"k2-{d}"} for d in conf["devices"]}      # fake keys
    brain = {d: secrets[d] for d, c in conf["devices"].items() if c["kind"] in ACTUATORS}
    for name, data in (("config.json", conf), ("secrets.json", secrets), ("brain_secrets.json", brain)):
        with open(os.path.join(RUN, name), "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)


def start(cmd, env_extra, out):
    env = dict(os.environ, **env_extra)
    stream = open(os.path.join(RUN, out), "w") if out else None
    return subprocess.Popen([sys.executable] + cmd, cwd=ROOT, env=env,
                            stdout=stream, stderr=subprocess.STDOUT if stream else None)


def main():
    prepare()
    cfg, sec = os.path.join(RUN, "config.json"), os.path.join(RUN, "secrets.json")
    procs = [
        start(["mocks/fake_orion.py", "--secrets", sec], {}, "fake_orion.out"),
    ]
    time.sleep(1)
    procs.append(start(["src/twin.py", "serve", "--port", str(UI_PORT)],
                       {"TWIN_CONFIG": cfg, "TWIN_SECRETS": sec, "TWIN_LOG_DIR": os.path.join(ROOT, "logs")},
                       "twin.out"))
    procs.append(start(["mocks/mock_guardian.py"], {"TWIN_CONFIG": cfg, "MOCK_SECRETS": "none"}, None))
    procs.append(start(["mocks/mock_brain.py"], {"TWIN_CONFIG": cfg,
                                                 "MOCK_SECRETS": os.path.join(RUN, "brain_secrets.json")}, None))
    try:   # the separate mock Brain does the acting: switch the built-in one off
        for _ in range(20):
            try:
                urllib.request.urlopen(urllib.request.Request(
                    f"http://localhost:{UI_PORT}/api/brain?on=0", method="POST"), timeout=2)
                break
            except OSError:
                time.sleep(0.5)
        print(f"\nMock setup running.  Open  http://localhost:{UI_PORT}\n"
              "Launch a scenario. Lines below show the mock Guardian and the mock Brain deciding.\n"
              "Scenario logs: the 'logs' folder.  Ctrl+C stops everything.\n", flush=True)
        while all(p.poll() is None for p in procs):
            time.sleep(1)
        print("A process stopped; see twin/mock_run/*.out", flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            p.terminate()


if __name__ == "__main__":
    main()
