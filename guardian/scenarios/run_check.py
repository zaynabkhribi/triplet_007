#!/usr/bin/env python3
"""One command per triplet scenario -> one Guardian log + a pass/fail check.

    PYTHONPATH=src:. python scenarios/run_check.py          # all nine
    PYTHONPATH=src:. python scenarios/run_check.py g1 g3    # a subset
    PYTHONPATH=src:. python scenarios/run_check.py --poll 0.25   # faster loops

How a check runs (the REAL shipping path, not a shortcut):

  1. A fake Orion broker (mocks/mock_orion.py) serves the twin's device
     semantics from mocks/orion_world.py, one tick per world step.
  2. A Guardian pipeline + the actual OrionPoller (src/guardian/orion.py) poll
     the broker over HTTP, exactly like the service does in docker compose.
  3. Every poll cycle's per-device verdicts are recorded; when a scenario's
     last tick was stepped, the final verdict face must match
     mocks/orion_world.py's EXPECT table.
  4. The log `logs/<id>-YYYYmmdd-HHMMSS.log` holds PUBLISH/MODE/COMMAND lines
     (the twin's story) plus `GUARDIAN` lines: verdict changes of the device
     face, in the same `date time TYPE text` shape the flagship triplet
     logs use.

Time is compressed, not faked: `--poll` shrinks the wall-clock between polls
(default 0.25 s) AND `--stale` shrinks the OFFLINE staleness window with the
same 4-poll proportionality the config ships (20 s / 5 s poll = 4 polls), so a
dead sensor still goes OFFLINE "after several silent polls".
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from guardian.config import load_settings                                 # noqa: E402
from guardian.errors import GuardianError                                 # noqa: E402
from guardian.ngsi import NgsiMapping                                     # noqa: E402
from guardian.orion import OrionPoller, aggregate_by_device               # noqa: E402
from guardian.pipeline import Pipeline                                    # noqa: E402
from guardian.registry import DeviceRegistry                              # noqa: E402
from guardian.dedup import SeenSet                                        # noqa: E402
from guardian.audit import AuditLog                                       # noqa: E402

from mocks.orion_world import SCENARIOS, EXPECT, World, run_scenario      # noqa: E402


def _run(world: World, scenario: str, *, poll: float, stale: float) -> tuple[list, dict, list]:
    """One check: serve the world over HTTP, poll it like the service does.

    Returns (log, final_verdicts, poller_errors).
    """
    settings = load_settings()
    import tempfile

    pipeline = Pipeline(settings,
                        DeviceRegistry.from_keyring(ROOT / "keys" / "dev_keys.json"),
                        SeenSet(window_s=settings.ttl.seen_window_s),
                        AuditLog(Path(tempfile.mkdtemp()) / "audit.jsonl"))
    mapping = NgsiMapping.load()
    from mocks.mock_orion import OrionWorldServer
    server = OrionWorldServer(world, port=0)          # ephemeral port, daemon threads
    import threading as _t
    _t.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.port}"
    poller = OrionPoller(pipeline, mapping, _WorldCatalog(), base,
                         poll_seconds=poll, timeout=5, stale_after_s=stale, writer=None)

    log: list[str] = []
    last_words: dict[str, str] = {}

    def sink(line: str) -> None:
        log.append(line)

    def on_cycle(device_verdicts) -> None:
        # GUARDIAN lines fire only when a device's verdict CHANGED, which is
        # exactly the shape the twin's own GUARDIAN lines use in its logs.
        for device_id, row in sorted(device_verdicts.items()):
            if last_words.get(device_id) != row.word:
                log.append(_clock() + f" GUARDIAN {device_id} {row.word} {row.reason} trust={row.trust}")
                last_words[device_id] = row.word
        log.append(_clock() + f" CYCLE {scenario} world_tick={world.tick} "
                              f"verdicts={len(device_verdicts)}")

    poller.cycle_hook = on_cycle
    poller.start()
    run_scenario(scenario, world, tick_delay=poll, emit=sink)

    world_end = time.time()
    # The world is done; wait only until the poller has caught up with the
    # last LIVE tick, then judge immediately. Whatever is judged later is
    # judged against a frozen broker: every repeat poll dedups, verdicts age,
    # and an honest Guardian would say OFFLINE about a city that stopped —
    # but that is the NEXT scenario's concern, not this check's.
    catchup = time.time() + max(poll * 4, 1.0)
    while time.time() < catchup and poller.last_cycle_at < world_end:
        time.sleep(0.05)
    device_face = aggregate_by_device(pipeline.all_verdicts(), now=time.time(),
                                      stale_after_s=stale)
    poller.stop(timeout=1.5)
    server.shutdown()
    body = {}
    for device_id, row in sorted(device_face.items()):
        body[device_id] = {"verdict": row.word, "reason": row.reason,
                           "trust": round(row.trust, 3), "checked": row.checked}
        log.append(_clock() + f" VERDICT {device_id} {row.word} {row.reason} trust={row.trust}")
    return log, body, poller.errors


class _WorldCatalog:
    """The scenario world's device list as an OrionPoller-compatible catalog."""

    def __init__(self) -> None:
        from mocks.orion_world import DEVICES
        self._devices = dict(DEVICES)
        self.source = "mocks/orion_world.py (the twin's device semantics)"

    def sensors(self) -> dict:
        return dict(self._devices)


def _clock() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _check(name: str, verdicts: dict) -> list:
    """Compare the last device face against the EXPECT table. Returns failures."""
    offenders = []
    for device_id, expect in EXPECT.get(name, {}).items():
        if device_id.startswith("*"):      # shorthand keys handled below
            continue
        row = verdicts.get(device_id)
        if row is None or row["verdict"] != expect:
            got = row["verdict"] if row else "(no verdict)"
            offenders.append(f"{name}/{device_id}: expected {expect}, got {got} "
                             f"({row['reason'] if row else 'absent'})")
    if EXPECT.get(name, {}).get("*") == "TRUSTED":
        for device_id, row in verdicts.items():
            if row["verdict"] != "TRUSTED":
                offenders.append(f"{name}/{device_id}: expected TRUSTED (all-calm), "
                                 f"got {row['verdict']} ({row['reason']})")
    return offenders


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Guardian against the triplet's scenarios.")
    parser.add_argument("ids", nargs="*", default=None, help="scenario ids (default: all nine)")
    parser.add_argument("--poll", type=float, default=0.25, help="compressed poll interval, seconds")
    parser.add_argument("--stale", type=float, default=1.5, help="compressed staleness window")
    args = parser.parse_args()
    ids = args.ids or [k for k in SCENARIOS if k in EXPECT]

    logs = ROOT / "logs"
    logs.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    failures: list = []
    for name in ids:
        world = World()
        try:
            log, verdicts, errors = _run(world, name, poll=args.poll, stale=args.stale)
        except GuardianError as exc:
            print(f"Guardian error running {name}: {exc}", flush=True)
            raise
        out = logs / f"{name}-{stamp}.log"
        out.write_text("\n".join(log) + "\n", encoding="utf-8")
        fails = _check(name, verdicts)
        status = "PASS" if not fails else "FAIL" + (f" ({len(fails)})" if fails else "")
        print(f"{name:>3}: {status}  -> {out.relative_to(ROOT)}")
        for f in fails:
            print("      " + f)
            failures.append(f)
        if fails:
            tail = [l for l in log if "GUARDIAN" in l or "VERDICT" in l][-12:]
            for line in tail:
                print("        " + line)
        if errors:
            print(f"      poller errors: {errors[:3]}")
    print()
    if failures:
        print(f"CHECKS FAILED: {len(failures)} expectation(s) unmet.")
        sys.exit(1)
    print("All scenario checks pass.")


if __name__ == "__main__":
    main()
