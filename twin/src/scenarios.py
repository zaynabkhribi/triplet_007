"""Scenarios are data: twin/scenarios.json (or the file named by TWIN_SCENARIOS).

Each scenario has a duration, steps [seconds, action, target, argument] and an optional
"resolved_when": the kinds of device that must be back to normal for the incident to end.
Actions: mode (change what a sensor reports), cmd (act as the Brain), note (write a log line)."""
import json
import sys

from schema import KNOWN_KINDS, validate_command
from settings import SCENARIOS_PATH, log

MODES = {"normal", "jam", "fake_jam", "fire", "spoof_smoke", "dump", "full", "stuck", "dead"}
ACTIONS = {"mode", "cmd", "note"}


def load_scenarios(path=SCENARIOS_PATH):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        sys.exit(f"Scenario file not found: {path}. It is part of the repository (twin/scenarios.json).")
    except ValueError as exc:
        sys.exit(f"Scenario file is not valid JSON ({path}): {exc}")
    return {k: v for k, v in data.items() if not k.startswith("_")}


SCENARIOS = load_scenarios()
SCENARIO_INFO = {k: (v.get("zone", ""), v.get("title", k), v.get("description", ""))
                 for k, v in SCENARIOS.items() if v.get("zone")}


def validate_scenarios(scenarios, conf):
    """Fail early, with the name of the scenario and the step, when a scenario does not match the city."""
    devices = conf["devices"]
    for name, sc in scenarios.items():
        if "duration" not in sc or "steps" not in sc:
            sys.exit(f"Scenario {name}: needs 'duration' and 'steps'")
        for n, step in enumerate(sc["steps"], 1):
            if len(step) != 4:
                sys.exit(f"Scenario {name}, step {n}: expected [seconds, action, target, argument]")
            _, action, target, arg = step
            if action not in ACTIONS:
                sys.exit(f"Scenario {name}, step {n}: unknown action {action!r}; use {', '.join(sorted(ACTIONS))}")
            if action == "note":
                continue
            if target not in devices:
                sys.exit(f"Scenario {name}, step {n}: device {target!r} is not in config.json")
            if action == "mode" and arg not in MODES:
                sys.exit(f"Scenario {name}, step {n}: unknown mode {arg!r}; use {', '.join(sorted(MODES))}")
            if action == "cmd":
                problem = validate_command(devices[target]["kind"], arg)
                if problem:
                    sys.exit(f"Scenario {name}, step {n}: {target}: {problem}")
        for kind in sc.get("resolved_when", []):
            if kind not in KNOWN_KINDS:
                sys.exit(f"Scenario {name}: resolved_when has unknown kind {kind!r}")


def run_step(city, step):
    _, action, target, arg = step
    if action == "note":
        log.info("NOTE %s", arg)
    elif action == "mode":
        city.devices[target].set_mode(arg)
    elif action == "cmd":
        city.devices[target].apply_command(arg, source="mock-brain")


def scenario_resolved(name, city, sc):
    """A scenario started from the page lasts until the incident is really over (the Brain acted and
    the effect happened). A scenario without "resolved_when" lasts until Reset all."""
    if sc["i"] < len(sc["steps"]):
        return False
    kinds = SCENARIOS[name].get("resolved_when")
    if not kinds:
        return False
    return all(d.mode == "normal" for kind in kinds for d in city.of_kind(kind))
