#!/usr/bin/env python3
"""
Twin layer simulator, US city (Chicago) on Snap4City. Command line entry point.

    python src/twin.py serve          # Scenario Control page on http://localhost:8080
    python src/twin.py list
    python src/twin.py check          # send one reading per device, report HTTP status
    python src/twin.py run a1         # run a scenario, writes a log in ../logs

Modules (all in src/):
    settings.py       paths, logger
    schema.py         data contract: allowed commands, value encoding, command validation
    orion_client.py   the only code that talks to the broker (NGSI v2, K1/K2 or certificate)
    model.py          devices and the city (cause and effect)
    scenarios.py      scenario loading and checking (data in scenarios.json)
    engine.py         configuration, tick loop, scenario control, command line runs
    web.py            Scenario Control page

Everything partner or platform specific is in config.json (no secrets) and secrets.json
(K1/K2 per device, never committed).
"""
import argparse
import os

from engine import (build_city, cmd_check, cmd_list, cmd_run, load_conf, load_json)  # noqa: F401
from settings import CONFIG_PATH, log  # noqa: F401
from schema import to_attr  # noqa: F401
from web import cmd_serve


def main():
    ap = argparse.ArgumentParser(description="Twin layer simulator")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sub.add_parser("check")
    r = sub.add_parser("run")
    r.add_argument("scenario")
    r.add_argument("--forever", action="store_true",
                   help="keep publishing after the scenario ends, until Ctrl+C")
    sv = sub.add_parser("serve")
    sv.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8080)))
    sv.add_argument("--host", default=os.environ.get("TWIN_HOST", "127.0.0.1"),
                    help="127.0.0.1 = this computer only; 0.0.0.0 = reachable from the network")
    args = ap.parse_args()
    if args.cmd == "list":
        cmd_list(load_json(CONFIG_PATH, "Config", "config.json is part of the repository (twin/config.json). Check you run from the twin folder."))
        return
    conf, secrets = load_conf()
    if args.cmd == "check":
        cmd_check(conf, secrets)
    elif args.cmd == "serve":
        cmd_serve(conf, secrets, args.port, args.host)
    else:
        cmd_run(conf, secrets, args.scenario, args.forever)


if __name__ == "__main__":
    main()
