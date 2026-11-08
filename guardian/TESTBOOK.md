# Guardian Test Book — the nine triplet scenarios

What the Guardian must say, scenario by scenario, and how to see it say so. The scenarios are the
shared ones in the repository root (`scenarios/<id>.py`, or the Twin's Scenario Control page); this
file is the *Guardian* column of the shared [TESTBOOK.md](../TESTBOOK.md).

One command replays all nine offline, with no broker and no platform account:

```bash
make checks              # all nine  -> logs/<id>-<stamp>.log + PASS/FAIL
make check id=g3         # one
```

## How a check is run

```
mocks/orion_world.py      the Twin's published physics, frozen into Python
        │  one tick per 5 s step (compressed to 0.25 s)
        ▼
mocks/mock_orion.py       a fake Orion broker: GET /v2/entities/{id}
        │  real HTTP
        ▼
src/guardian/orion.py     the SHIPPING poller (same code docker compose runs)
        │
        ▼
pipeline.py               the unchanged five stages → per-property verdicts
        │
        ▼
orion.aggregate_by_device one verdict per device
        │
        ▼
EXPECT table              PASS / FAIL
```

Time is compressed, not faked: `--poll` shrinks the wall-clock between polls and `--stale` shrinks
the OFFLINE window with the same 4-poll proportionality the shipped config uses (20 s / 5 s), so a
dead sensor still goes `OFFLINE` "after several silent polls".

## The table

| Id | Scenario | What the Twin publishes | Guardian verdict | Reason code |
|---|---|---|---|---|
| **n1** | Calm day | normal traffic, quiet building, slowly filling bins | every sensor `TRUSTED` | `OK` |
| **a1** | Traffic jam on roads 1 and 2 | `congestionLevel` ramps 30 % → 100 % on two roads | `TRUSTED` | `OK` |
| **b1** | Fire in building 1 | smoke `20·t` ppm, temperature `22+12·t` °C, both rising | `TRUSTED` | `OK` |
| **c1** | Waste / illegal dumping | bin fills +15 %/tick to a cap of 97 %, camera reports the dump | `TRUSTED` | `OK` |
| **g1** | Spoofed smoke | smoke 400 ppm, temperature flat at 22 °C | `UNTRUSTED` | `CONFLICT` |
| **g2** | Stuck and dead sensors | `us-a-traf-03` repeats its payload; `us-a-traf-02` stops publishing | `UNTRUSTED` / `OFFLINE` | `JAM` / `COMM_LOSS` |
| **g3** | Fake traffic jam | `us-a-traf-03` pins congestion ~88–92 % forever | `UNTRUSTED` | `STEADY_ANOMALY` |
| **m1** | Real fire and a fake jam | building fire **and** a pinned fake jam, same time | building `TRUSTED`, road `UNTRUSTED` | `OK` / `STEADY_ANOMALY` |
| **d1** | Brain down | a real fire starts and nothing answers | building `TRUSTED` | `OK` |

Devices not named in a row must not be dragged down by it: in `g3` and `m1`, roads 1 and 2 stay
`TRUSTED` while road 3 does not. `make checks` asserts exactly that, so a detector that fires too
broadly fails the run.

## The two hard distinctions

### g3 fake jam vs a1 real jam — independence, not magnitude

Both publish high congestion. Magnitude alone cannot separate them, and neither can internal
consistency: the Twin's fake generator renders `vehicleCount`, `avgSpeed` and `occupancy` coherently
with its fake `congestionLevel`, so the liar's own channels always agree with the lie.

What separates them is **another device**:

| | a1 real jam | g3 fake jam |
|---|---|---|
| pinned ≥ 80 % for 5+ reads? | yes, at the ceiling | yes |
| a *sibling road* with a high camera count? | yes (both roads jam) | no |
| a *sibling* speed collapsed to ≤ 20 km/h? | yes | no |
| verdict | `TRUSTED` | `UNTRUSTED` / `STEADY_ANOMALY` |

The corroboration conditions are **directional** and live in `sensor_profiles.yaml` as data:

```yaml
steady:
  ticks: 5
  span: 6.0            # absorbs the Twin's ±2 generator noise
  min_value: 80.0      # a ceiling claim, not calm traffic
  corroborate:
    traffic_camera: { op: ">=", value: 40 }   # many vehicles on a jammed road
    vehicle_speed:  { op: "<=", value: 20 }   # and/or slowed traffic
```

Speed is congestion's *inverse* cousin: a slow sibling agrees with a jam, a fast one does not. A
plain "≥ floor" test would have cleared every fake jam — that bug was found and is pinned by
`tests/test_orion.py::test_steady_accepts_speed_as_inverse_corroboration`.

### g2 stuck vs dead — values vs freshness

| | stuck (`us-a-traf-03`) | dead (`us-a-traf-02`) |
|---|---|---|
| timestamps | fresh every tick | frozen with the entity |
| values | identical every tick | identical (the broker's last copy) |
| what gives it away | repetition alone | the absence of *fresh verdicts* |
| detector | `d06 jam` (repeat rule) | aggregation staleness |
| verdict | `UNTRUSTED` / `JAM` | `OFFLINE` / `COMM_LOSS` |

A dead sensor is why the feed has a fourth state: the broker keeps serving its last entity forever,
so "the value looks fine" is exactly the trap. Only `stale_after_s` (20 s ≈ 4 polls) reveals it.

## Three parity decisions the Twin's own judge forced

The Twin ships `twin/mocks/mock_guardian.py` as the reference judge for these scenarios. Matching it
required three deliberate changes, each pinned by a test:

1. **A repeat is the fault, at any level.** The mock convicts "the value did not change for 6
   reads". Real traffic wanders a little every tick, so five identical reads is a stuck sensor —
   `d06 jam` now takes a per-profile `jam: { repeat_ticks: 5 }` opt-in. Quantized counters that
   legitimately repeat do not opt in.
2. **Freezes that are legitimate physics opt out.** A bin capped at 97 % (c1), a camera resting at
   0, and an evacuated building resting at 0 (b1) freeze by definition — `jam: { significant: false }`
   in their profiles. Without this, the Guardian would convict a full bin and a real fire scene.
3. **A lawful decay to zero is not a mute.** `d08 tamper` convicts a collapse beyond the profile's
   rate law (t4's gauge: 0.82 → 0 m against a 0.5 m/tick limit). The building's evacuation walks
   occupancy to 0 at 3/tick, which is inside its law, so a real fire stays `TRUSTED`.

## Reading a log

Each run writes `logs/<id>-<YYYYmmdd-HHMMSS>.log`, in the same `date time TYPE text` shape the
triplet's other logs use:

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
| `SCENARIO` | run header |
| `NOTE` / `MODE` / `COMMAND` | the Twin's story (what the Brain would do) |
| `PUBLISH` | the entity the Twin wrote to the broker |
| `CYCLE` | one poller pass; the world tick it saw and how many verdicts it held |
| `GUARDIAN` | a verdict **changed** — the line a reviewer looks for |
| `VERDICT` | the final device face the Brain would read |

## Regression suite

| File | What it pins |
|---|---|
| `tests/test_ngsi_triplet.py` | every scenario's verdict through the real mapping, plus the `/verdicts` shape |
| `tests/test_orion.py` | aggregation rules (worst property, staleness, inventory), steady vs real jam, stuck vs stuck-opt-out, lawful decay |
| `tests/test_detectors.py` | all eleven detectors on hand-built contexts |
| `tests/test_testbook.py` | the older T1–T7 bands (frame-level fixtures, kept as regression) |

```bash
make test        # 200 tests
make lint        # ruff + byte-compile
```
