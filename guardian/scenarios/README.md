# `guardian/scenarios/` — one command per scenario, PASS/FAIL

`run_check.py` is the Guardian's Test Book runner. It replays every triplet scenario against
the **shipping** code path — real `NgsiClient`, real `OrionPoller`, real pipeline — and
compares the final device face against `mocks/orion_world.py`'s `EXPECT` table.

```bash
make checks                    # all nine, offline, PASS/FAIL, logs written
make check id=g3               # one
PYTHONPATH=src:. .venv/bin/python scenarios/run_check.py --poll 0.5 --stale 3
```

Exit code is **0 only when every expectation holds**, so this is a gate, not a print
statement. A failure prints the expectation, what was actually concluded, and the last
verdict lines of the log.

## What one run does

```
mocks/orion_world.py   the world: one tick per step
        │
mocks/mock_orion.py    fake broker on an ephemeral port
        │  real HTTP GET /v2/entities/{id}
        │
NgsiClient.poll        src/guardian/ngsi.py — the shipping reader
        │
Pipeline.process       the unchanged five stages (11 detectors, 6-factor score)
        │
OrionPoller.cycle_hook one verdict face per poll
        │
EXPECT table           PASS / FAIL
```

## Time is compressed, not faked

| Flag | Default | Meaning |
|---|---|---|
| `--poll` | `0.25` s | wall-clock between world ticks and between polls |
| `--stale` | `1.5` s | the OFFLINE window, keeping the shipped 4-poll proportionality (20 s / 5 s) |

So a dead sensor still goes `OFFLINE` "after several silent polls", exactly as it would on
stage, just faster. Nothing about the semantics is shortcut.

## The log

`logs/<id>-<YYYYmmdd-HHMMSS>.log`, in the shared `date time TYPE text` shape:

```
2026-11-08 22:39:15 SCENARIO m1 start: Fire + fake jam
2026-11-08 22:39:15 PUBLISH us-b-bldg-01 {"smokeLevel":{"type":"Number","value":1.1},…}
2026-11-08 22:39:16 GUARDIAN us-b-bldg-01 TRUSTED OK trust=0.939
2026-11-08 22:39:19 MODE us-a-traf-03->fake_jam
2026-11-08 22:39:21 GUARDIAN us-a-traf-03 UNTRUSTED STEADY_ANOMALY trust=0.729
2026-11-08 22:39:24 VERDICT us-a-traf-03 UNTRUSTED STEADY_ANOMALY trust=0.729
```

| Type | Meaning |
|---|---|
| `SCENARIO` / `NOTE` / `MODE` / `COMMAND` | the scenario and the Twin's story |
| `PUBLISH` | the entity written to the broker |
| `CYCLE` | one poller pass (world tick, verdict count) |
| `GUARDIAN` | a verdict **changed** — the line to look for |
| `VERDICT` | the final device face the Brain would read |

## Adding a scenario

1. Add the steps and an `EXPECT` row in `mocks/orion_world.py`.
2. If the Twin's real `scenarios.json` has it, mirror its duration proportions.
3. `make checks` — a mismatch is a real finding, not a nuisance.
