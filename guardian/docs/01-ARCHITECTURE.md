# 01 — Architecture

**Layer:** Guardian · **Position:** between the Twin (evidence) and the City Brain (decisions)

---

## 1. Where we sit in the triplet

```
┌────────────────────── LIVE TIMELINE (R2) ───────────────────────┐
│  reading → Guardian verdict → Brain decision → Twin action      │
└─────────────────────────────────────────────────────────────────┘

  TWIN                ORION               GUARDIAN (this layer)        BRAIN
  simulated city      shared state        trust plane                  decisions
  ┌──────────┐        ┌──────────┐        ┌──────────────────┐        ┌──────────┐
  │ sensors  │ write  │ entities │  GET   │ 5-stage pipeline │  GET   │ plan     │
  │          │ ─────► │ per tick │ ◄───── │ 11 detectors     │ ─────► │ within   │
  │ actuators│        │ (NGSI v2)│  poll  │ 6-factor score   │ /verdicts│ allowed │
  └────▲─────┘        └────▲─────┘        │ signed passport  │        └────┬─────┘
       │                   │              └──────────────────┘             │
       │  actuator write   │  (optional) TrustVerdict write-back           │
       └───────────────────┴───────────────────────────────────────────────┘
                           ▲
                           └── the Twin re-verifies a passport before acting
                               (no passport = no metal)
```

**The invariant.** No matching, fresh, in-scope passport ⇒ no Brain-originated action.
Enforced in three independent places: the passport's `allowed_actions`, the Brain's
planner, and the Twin's re-verification before actuation.

---

## 2. The five-stage pipeline

Each reading (or small batch) traverses five stages. Every stage emits **stable reason
codes**, so a verdict is explainable and testable — never "the model said so".

| Stage | Name | Job | Emits |
|---|---|---|---|
| **A** | Charter check | Schema, identity, signature, provenance, TTL/freshness, sequence, dedup | `SCHEMA_INVALID`, `SIG_INVALID`, `UNKNOWN_DEVICE`, `DUPLICATE`, `STALE` |
| **B** | Calibrate | Apply calibration/firmware; unit conversion; range normalisation | `CAL_OK`, `OUT_OF_RANGE` |
| **C** | Corroborate | Compare independent sources in the same feature of interest | `CORROBORATED`, `CONFLICT`, `SINGLE_SOURCE` |
| **D** | Scrutinize | Run the 11 detectors | `DRIFT`, `SPOOF`, `JAM`, `STEADY_ANOMALY`, `REPLAY`, `TAMPER`, `IMPLAUSIBLE`, `RATE_ANOMALY` |
| **E** | Consolidate | Compute T, apply hard gates, map to disposition, build + sign passport, audit | verdict + `allowed_actions` |

**Design rule:** Stage A is a *gate*, not a score. A forged frame never reaches the
scoring maths where a "good enough" number might save it.

---

## 3. The trust score

```
T = 0.30·corroboration + 0.20·consistency + 0.18·plausibility
  + 0.12·provenance + 0.10·freshness + 0.10·history
  − 0.25·conflict
```

| Factor | Meaning |
|---|---|
| corroboration | fraction of independent sources agreeing within tolerance |
| consistency | physical/domain feasibility (0 if impossible) |
| plausibility | range + rate-of-change + cross-domain |
| provenance | signature valid ∧ firmware/cal known ∧ not quarantined |
| freshness | `1 − age/TTL` |
| history | device reliability; halves on a MISMATCH, recovers slowly |
| conflict | penalty when sources disagree, not a factor |

All weights and thresholds live in `policy.yaml`, are versioned (`policy_version`, stamped
on every passport), and are validated at boot. Re-calibration is a config change, never a
code edit.

---

## 4. Disposition → authority

| Disposition | Trust | What it can authorise |
|---|---|---|
| **TRUSTED** | ≥ 0.80 | full + reversible + precautionary |
| **SUSPECT** | 0.50–0.79 | reversible + precautionary — **never full** |
| **RESTRICT** | < 0.50 (or STALE) | precautionary only |
| **MALICIOUS** | hard flag (`TAMPER`/`SPOOF`/`REPLAY`), capped 0.49 | nothing; device quarantined |

This table is the whole product in four rows.

---

## 5. Source-agnostic sensors

The Guardian does not hard-code "five sensors". `sensor_profiles.yaml` declares, per
sensor type: units, range, max rate of change, corroborating peers, and physics coupling.
New sensor types are **data, not code** — which is what makes a Phase 2 rematch cheap.

This triplet maps the Twin's real attributes onto profiles — `congestionLevel` →
`congestion`, `avgSpeed` → `vehicle_speed`, `smokeLevel` → `fire_smoke`,
`occupancyCount` → `building_occupancy`, `dumpingDetected` → `camera_alert`,
`confidence` → `camera_confidence`, `fillLevel` → `fill_level` — and each profile also
carries the opt-ins some detectors need: a `steady:` block (the g3 fake-jam rule) and a
`jam:` block (`repeat_ticks` for the g2 stuck rule; `significant: false` for values that
freeze by design, such as a capped bin). No detector has a device name inside it.

---

## 6. Separation of logic and transport

The scored interoperability requirement is a clean split between what we *decide* and how
we *talk*. Our shape:

```
src/guardian/
├─ pipeline.py   five stages           ← pure logic, no HTTP
├─ detectors.py  eleven pure functions ← unit-testable in isolation
├─ score.py      trust maths           ← policy-driven
├─ passport.py   build/sign/verify     ← pure crypto + clock injection
├─ registry.py   devices, keys, quarantine
├─ audit.py      hash-chained JSONL
├─ ngsi.py       NGSI v2 read/mapping  ← the ONLY broker-aware reader
├─ orion.py      poller + device face  ← the ONLY device-aggregation module
├─ api.py        FastAPI surface       ← the ONLY HTTP-server module
└─ mock/         frame-level Twin + Brain stand-ins (regression path)
```

Two modules now speak transport, because the triplet has two transports: `ngsi.py` reads
the broker and `api.py` serves HTTP. Everything between them — pipeline, detectors, score,
passport, audit — takes plain data and returns plain data, which is why 200 tests exercise
the trust logic with no server and no broker at all.

---

## 7. Failure behaviour (by design, not by accident)

| Trigger | Guardian behaviour |
|---|---|
| Twin silent | frames age → `STALE`; devices go `OFFLINE`/`COMM_LOSS` while `/healthz` stays `ok` |
| Broker unreachable | each cycle is recorded on `/orion/status`; the poller retries next tick, `/verdicts` keeps its last face |
| Brain absent | nothing auto-acts; passports expire in 6 s; Twin holds safe state |
| Forged / replayed frames | stable code, HTTP 200+code or 4xx; **never 500** |
| Actuator lies | witness MISMATCH → history halves → 3× quarantines the device |
| Guardian restart | audit log persists; run-scoped state re-opens cleanly; old passports expire |
| Malformed burst | schema gate + bounded queues; critical traffic preserved |

---

## 8. What we deliberately did **not** build

No shared database (coupling), no message broker (stage risk), no LLM in the verdict path
(non-determinism), no 3D engine (effort ≠ evidence), no custom cryptography (invented
crypto is a vulnerability, not a feature). Each omission is a deliberate trade for
determinism and stage reliability.
