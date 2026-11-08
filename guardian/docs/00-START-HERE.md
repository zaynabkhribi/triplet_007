# 00 — START HERE · Guardian (triplet-07 · TSYP 14 · City Brain Convergence)

**Layer owned:** Guardian · **Team:** AEGIS LOOP
**Repository:** `zaynabkhribi/triplet_007`, folder `guardian/`
**Status:** the nine triplet scenarios pass end to end · 200 tests green

> **Every action carries its own proof.**
> Sense broadly · Trust explicitly · Act within scope · Verify reality.

This file is the entry point for a reviewer. It takes you from a clean machine to a
working, replayable system in under ten minutes, then tells you exactly which
artefact answers which scoring criterion.

---

## 1. What this layer is

The triplet's city is Chicago on Snap4City: **zone A** traffic, **zone B** a building
fire, **zone C** waste. The Twin simulates it and publishes sensor values through the
**Orion broker** (NGSI v2). The Brain decides what to do. The Guardian sits between
them and answers one question per device, every tick: *can this data be trusted?*

It answers with a per-device verdict feed — `TRUSTED` / `UNTRUSTED` / `OFFLINE`, with a
stable reason code — which the Twin's own mock Brain already consumes. Behind a
`TRUSTED` verdict stands a signed, scoped, expiring **Evidence Passport**: one issued on
suspicious evidence physically cannot authorise a full-commit action, so a validly
authenticated but lying sensor can never open a floodgate or sound a false alarm.

The numbers to check first:

| Twin scenario | What the Twin does | Our verdict | Why |
|---|---|---|---|
| **g1** spoofed smoke | `us-b-bldg-01` reports **400 ppm** smoke at **22 °C** | **UNTRUSTED** — `CONFLICT` | smoke and heat are physically coupled; smoke without heat cannot be combustion |
| **b1** real fire | smoke **and** temperature rise together | **TRUSTED** | the corroborator agrees, so the Brain may sound the alarm |
| **a1** traffic jam | `us-a-traf-01` and `-02` jam together | **TRUSTED** | a corroborated trend is the incident, not an attack |
| **c1** full bin | `us-c-bin-01` fills to a cap of 97 % | **TRUSTED** | filling is the incident, not an attack |
| **g3** fake jam | `us-a-traf-03` pins congestion near the ceiling | **UNTRUSTED** — `STEADY_ANOMALY` | no other road confirms the jam |
| **g2** stuck / dead | one sensor repeats itself, one goes silent | **UNTRUSTED** `JAM` / **OFFLINE** `COMM_LOSS` | repetition; then the absence of fresh data |
| **m1** fire + fake jam | both at once | building **TRUSTED**, fake road **UNTRUSTED** | both rules together, in one zone split |
| **n1** calm day | nothing happens | everything **TRUSTED** | we do not overreact |
| **d1** Brain down | a real fire, no Brain answering | building **TRUSTED** | trust does not depend on the consumer |

`b1` matters as much as `g1`: a Guardian that refused everything would block the Brain's
alarm and fail the triplet's own fire scenario. Both halves are asserted, and both are
reproducible offline.

---

## 2. Run it (under 10 minutes, no partner, no network)

Everything below runs **inside this folder**. Nothing outside `guardian/` is read at
run time.

```bash
cd guardian
make setup        # venv + deps              (~20 s on a clean machine)
make test         # 200 tests, all green     (~8 s)
make checks       # all nine scenarios     -> logs/<id>-<stamp>.log + PASS/FAIL
```

Then run the service and read the live feed it produces:

```bash
make demo                                     # :8090
curl -s localhost:8090/verdicts | python3 -m json.tool | head -20
curl -s localhost:8090/orion/status           # poller health in one read
```

To demo with **no platform access at all**, use the bundled fake broker:

```bash
make mock-orion                               # terminal 1: fake Orion on :8025
GUARDIAN_BROKER_URL=http://127.0.0.1:8025 make demo    # terminal 2
curl -XPOST localhost:8025/scenario -d '{"name":"g3"}' # terminal 3: trigger a scenario
watch -n1 'curl -s localhost:8090/verdicts | python3 -m json.tool | grep -A2 traf-03'
```

Nothing is installed on stage beyond Python 3.9+. No cloud dependency, no database
engine. Everything is local-first by design, because the spec forbids relying on venue
Wi-Fi.

---

## 3. Reading the Twin's broker (the triplet's interface)

The Twin does not post to us; it writes to Orion. The Guardian **polls** it once per tick
(5 s, matching the Twin's step), so no partner has to call us.

| Our term | Their term |
|---|---|
| `sensor_id` | NGSI entity id, e.g. `us-b-bldg-01` |
| `zone` | derived from the id prefix: `us-a-` → `ZONE-A`, `us-b-` → `ZONE-B`, `us-c-` → `ZONE-C` |
| `observed_property` | mapped attribute: `smokeLevel` → `fire_smoke`, `temperature` → `temperature`, `congestionLevel` → `congestion`, `avgSpeed` → `vehicle_speed`, `fillLevel` → `fill_level` |
| `phenomenon_time` | the entity's `timestamp` (ISO 8601, UTC) |
| `provenance.firmware` | the NGSI entity type, e.g. `BuildingSensor` |

The mapping is **data**, in `ngsi.yaml`: adding a device or renaming an attribute is a
config edit, never a code change. The device list ships as `orion_devices.json` (a
snapshot of `twin/config.json`) and can point at any Twin-style config.

We publish the shape the Twin's mock Brain already reads
(`twin/mocks/mock_guardian.py`), so a Brain written against the mock works unchanged:

```bash
curl localhost:8090/verdicts
# {"us-b-bldg-01": {"verdict": "UNTRUSTED", "reason": "CONFLICT", "checked": "20:08:59",
#                   "trust": 0.539, "disposition": "SUSPECT", "zone": "ZONE-B", ...}}
```

`verdict`, `reason` and `checked` are the documented three keys. The extra fields are the
evidence behind the verdict, for anyone who wants to check it rather than trust it.

---

## 4. Where everything lives

All paths are relative to `guardian/`.

| I want to… | Open |
|---|---|
| Connect a Twin or Brain to us | [`INTERFACE.md`](INTERFACE.md) |
| See the exact wire examples and JSON Schemas | [`shared/schema/`](shared/schema/) + `GET /describe` |
| See the NGSI mapping | [`ngsi.yaml`](ngsi.yaml) |
| Read the Guardian Test Book | [`TESTBOOK.md`](TESTBOOK.md) |
| Read the shared triplet Test Book | [`../TESTBOOK.md`](../TESTBOOK.md) |
| Verify our claims as a reviewer | [`docs/05-REVIEWER-VERIFICATION.md`](05-REVIEWER-VERIFICATION.md) |
| See the live timeline | `/ui/` (running) |
| Read the raw evidence | [`logs/`](logs/) — one log per scenario |
| Read the security matrix | [`docs/03-SECURITY-MATRIX.md`](03-SECURITY-MATRIX.md) |
| Understand the offline world + fake broker | [`mocks/README.md`](../mocks/README.md) |
| Understand the check runner | [`scenarios/README.md`](../scenarios/README.md) |

---

## 5. How this maps to the 50-point rubric

| # | Criterion | Pts | Where the evidence is |
|---|---|---|---|
| 1 | **Individual prototype functionality** | 10 | `make checks` (nine scenarios, offline) + `make demo`; the Guardian reads, judges and isolates — alone |
| 2 | Technical implementation & features | 5 | 5-stage pipeline, 11 detectors, 6-factor score, Evidence Passport — `src/guardian/` |
| 3 | **Interoperability & collaboration** | 15 | `INTERFACE.md`, `GET /describe`, `ngsi.yaml` (config, not code), `/verdicts` in the Twin's own shape, optional `TrustVerdict` write-back |
| 4 | Security & trust mechanisms | 10 | `docs/03-SECURITY-MATRIX.md` — threat → control → the test that proves it |
| 5 | Documentation & code quality | 5 | `README`, `INTERFACE`, `TESTBOOK`, typed code, `make lint`, this index |
| 6 | Demonstration & presence | 5 | `docs/04-DEMO-RUNBOOK.md` — minute-by-minute plan |

---

## 6. Reviewer's five-minute path

```bash
cd guardian && make setup && make test    # 200 pass
make checks                               # nine scenarios, PASS/FAIL, logs written
make demo &                               # server up on :8090
curl -s localhost:8090/orion/status | python3 -m json.tool
```

Then read, in order: this file → `docs/05-REVIEWER-VERIFICATION.md` (each claim, and the
one command that re-proves it) → `TESTBOOK.md` → `INTERFACE.md`.
