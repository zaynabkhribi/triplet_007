# `guardian/mocks/` — the offline world and the fake broker

Two files, one purpose: let the Guardian be demonstrated and checked with **no platform, no
network, and no partner process**. Both are test fixtures — the shipping service never
imports them.

| File | Role |
|---|---|
| `orion_world.py` | The Twin's published physics, frozen into pure Python. One `World` per scenario, stepped tick by tick. |
| `mock_orion.py` | A fake Orion broker serving that world over real HTTP: `GET /v2/entities/{id}`. |

## The world (`orion_world.py`)

`World` reproduces the readings the Twin actually publishes (`twin/src/model.py`), formula by
formula, for the nine triplet scenarios:

| Mode | Published values |
|---|---|
| `jam` | congestion ramps `0.3 + 0.1·t`, capped at 100 % |
| `fake_jam` | congestion pinned at the ceiling with ±2–3 noise (≈ 88–92 %) |
| `fire` | smoke `min(20·t, 500)` ppm, temperature `min(22 + 12·t, 300)` °C |
| `spoof_smoke` | smoke 400 ppm, temperature ≈ 22 °C |
| `stuck` | the last payload repeated verbatim, with a **fresh timestamp** |
| `dead` | nothing published (the entity's timestamp freezes) |
| `dump` | `dumpingDetected: true`, `confidence: 0.9` |
| `full` | `fillLevel` `+15 %`/tick, capped at 97 % |

It is a **record**, not a re-implementation for its own sake: when the Twin changes a
formula, change it here and run `make checks` — a divergence fails loudly instead of
silently drifting.

```python
from mocks.orion_world import World, SCENARIOS, run_scenario

world = World()
run_scenario("g3", world, tick_delay=0.25)   # steps the world, one tick at a time
world.devices["us-a-traf-03"]["last"]        # what that device published last
world.entities()                             # NGSI v2 wire shape, ready to serve
```

`SCENARIOS` holds each scenario's `duration` and its `steps` (`mode` / `cmd` / `note`), and
`EXPECT` holds what the Guardian must conclude at the end. `run_scenario` emits
`date time TYPE text` log lines — the same shape as the triplet's other logs.

## The fake broker (`mock_orion.py`)

```bash
make mock-orion                        # :8025
curl localhost:8025/v2/entities/us-a-traf-01
curl -XPOST localhost:8025/scenario -d '{"name":"g3"}'
```

It binds an ephemeral port when constructed with `port=0`, which is how `scenarios/run_check.py`
gives every scenario a clean broker. The Guardian polls it through the **real** `NgsiClient`,
so the code path under test is the shipping one.

## What is *not* here

The frame-level partner stand-ins (`python -m mocks.mock_twin` / `mock_brain`) still exist and
are still tested — they exercise the original signed-frame transport (`POST /v1/readings`),
kept as a regression path. See `src/guardian/mock/`. The triplet demo uses the broker path
above, not these.
