# AEGIS LOOP — Guardian layer

The **trust layer** of the TSYP14 *City Brain Convergence* triplet. It reads the city's sensors
from the Orion broker, decides per device whether the data can be trusted, and publishes one
verdict per entity — so *one lying sensor can never steer the city.*

> **"Sense broadly. Trust explicitly. Simulate consequences. Act within proof. Verify reality."**
> Every action carries its own proof.

**Status: the nine triplet scenarios pass end to end.** 199 tests and `make lint` are green, and
`make checks` replays every scenario offline into `logs/` with a PASS/FAIL verdict.

| Scenario | What the Guardian must say | Result |
|---|---|---|
| n1 calm day | every sensor `TRUSTED` | PASS |
| a1 traffic jam | real jam stays `TRUSTED` (two roads agree) | PASS |
| b1 fire | `TRUSTED` — smoke and heat rise together | PASS |
| c1 waste | `TRUSTED` — a filling bin is the incident, not an attack | PASS |
| g1 spoofed smoke | `UNTRUSTED` — smoke without heat | PASS |
| g2 stuck + dead | `UNTRUSTED` (stuck) and `OFFLINE` (dead) | PASS |
| g3 fake jam | `UNTRUSTED` — a pinned ceiling no other road confirms | PASS |
| m1 fire + fake jam | zone split: building `TRUSTED`, fake road `UNTRUSTED` | PASS |
| d1 Brain down | `TRUSTED` — sensors stay trustworthy with no Brain | PASS |

---

## Quick start (two commands, no platform account)

```bash
make setup      # venv + dependencies
make checks     # all nine scenarios offline -> logs/<id>-<stamp>.log + PASS/FAIL
```

Then run the service and read the live verdict feed:

```bash
make demo       # http://localhost:8090/verdicts
curl -s localhost:8090/verdicts | python3 -m json.tool | head -20
```

With Docker, the root compose file brings the Guardian up beside the Twin:

```bash
docker compose up -d guardian
```

---

## The contract with the other layers

The layers never call each other; they share state through Orion.

```
                  Orion broker (NGSI v2)
   Twin ──writes sensors──▶  ◀──GET /v2/entities/{id}── Guardian
                                │
                                └──GET /verdicts──▶ Brain ──writes actuators──▶ Twin
```

| Face | Where | Shape |
|---|---|---|
| per-device verdicts | `GET /verdicts` | `{"us-b-bldg-01": {"verdict": "TRUSTED", "reason": "OK", "checked": "12:00:04", ...}}` |
| broker health | `GET /orion/status` | poller cycles, unreachable devices, published count |
| one manual read | `POST /v1/ngsi/poll` | runs one broker → pipeline → summary cycle |
| frame transport | `POST /v1/readings` | the original signed-frame contract (kept, still tested) |
| passports | `POST /v1/passport` | signed Evidence Passport for an `evidence_digest` |
| live timeline | `GET /ui/` | reading → verdict → decision, timestamped |
| capability card | `GET /describe` | machine-readable interface description |

`verdict` is one of `TRUSTED`, `UNTRUSTED`, `OFFLINE` — the exact vocabulary the Twin's own mock
Guardian uses, so the Brain works against this layer unchanged. `reason` carries stable codes
(`CONFLICT`, `RATE_ANOMALY`, `STEADY_ANOMALY`, `JAM`, `COMM_LOSS`, `STALE`, …). Full details, with
examples and the optional `TrustVerdict` write-back, are in [INTERFACE.md](INTERFACE.md).

---

## How a verdict is made

Per device, per tick, over the unchanged five-stage pipeline:

```
broker entity ─▶ frames ─▶ A charter ─▶ B calibrate ─▶ C corroborate ─▶ D scrutinize ─▶ E consolidate
              (ngsi.py)                    range          cross-device         11 detectors      6-factor score
```

**Stage D — the eleven detectors** (`src/guardian/detectors.py`, all pure functions):

| Detector | Flags | What it catches in this triplet |
|---|---|---|
| d01 range | `OUT_OF_RANGE` | a value outside the profile's physics |
| d02 rate | `RATE_ANOMALY` | g3: congestion jumping 14 → 89 in one tick |
| d03 drift | `DRIFT` | slow, steady divergence from a corroborator |
| d04 spoof | `SPOOF` | a claimed value the physics forbids |
| d05 stale | `STALE` | a reading older than its TTL |
| d06 jam | `JAM` | g2: identical reads repeated (stuck sensor), at any level |
| **d11 steady** | `STEADY_ANOMALY` | **g3: a jam pinned at the ceiling that no other road confirms** |
| d07 conflict | `CONFLICT` | g1: smoke 400 ppm while temperature stays at 22 °C |
| d08 tamper | `TAMPER` | t4: a gauge collapsing 0.82 → 0 far beyond its rate law |
| d09 consistency | `IMPLAUSIBLE` | a value violating a stated physical coupling |
| d10 replay | `REPLAY` | a byte-identical frame replayed later |

**Stage E — the score** (`policy.yaml` is the single source of truth, validated at startup):

- `T = 0.30·corroboration + 0.20·consistency + 0.18·plausibility + 0.12·provenance + 0.10·freshness + 0.10·history − 0.25·conflict`
- `TRUSTED ≥ 0.80` · `SUSPECT 0.50–0.79` · `RESTRICT < 0.50` · `MALICIOUS` when a hard flag
  (`TAMPER`/`SPOOF`/`REPLAY`) fires, with `trust` capped at 0.49
- Every `SUSPECT`, `RESTRICT` and `MALICIOUS` passport is **structurally incapable** of carrying a
  full-commit action, so a Brain cannot cite it for an irreversible command.

### The two decisions this triplet turns on

**g3 — fake jam vs a1 — real jam.** Both publish high congestion. The difference is
*independence*: a real jam is confirmed by another device (a sibling road with a high vehicle
count, or a speed that has collapsed), while the fake one is a story only one device tells — and
the liar's own channels don't count. `d11 steady` encodes exactly that, and both scenarios pass
against the same thresholds.

**g2 — stuck vs dead.** A stuck sensor repeats its payload with fresh timestamps, so it looks
alive; only the *values* give it away (`d06 jam`). A dead sensor publishes nothing, so the broker
keeps serving the last entity; only *freshness* gives it away, and it becomes `OFFLINE` after four
silent polls.

---

## Layout

```
guardian/
├─ INTERFACE.md          # the partner contract (verdict format, config, auth)  ⬅ read first
├─ config.yaml           # endpoints, poll cadence, TTLs (no hard-coded hosts)
├─ ngsi.yaml             # Orion attribute → observed property mapping (data, not code)
├─ sensor_profiles.yaml  # per-property physics: range, rate, corroborators, steady/jam rules
├─ policy.yaml           # trust model: weights, thresholds, dispositions
├─ orion_devices.json    # snapshot of the triplet's device list (data)
├─ src/guardian/         # api, orion, ngsi, pipeline, detectors, score, passport, audit, …
├─ static/               # live timeline UI (dependency-light)
├─ mocks/                # orion_world.py (the twin's physics) + mock_orion.py (fake broker)
├─ scenarios/            # run_check.py — one command per scenario, PASS/FAIL
├─ tests/                # 199 passing tests
└─ Makefile              # setup / checks / check id=… / demo / mock-orion / lint
```

## Configuration (env overrides)

| Env var | Default | Purpose |
|---|---|---|
| `GUARDIAN_PORT` | `8090` | API port |
| `GUARDIAN_BROKER_URL` | the triplet's Orion filter | Broker to read |
| `GUARDIAN_POLL_SECONDS` | `5` | One tick (matches the Twin's step) |
| `GUARDIAN_STALE_AFTER_S` | `20` | ~4 silent polls → `OFFLINE` |
| `GUARDIAN_DEVICES_CONFIG` | `orion_devices.json` | Device list to poll (any Twin `config.json`) |
| `GUARDIAN_ORION_ENABLED` | `true` | Start the background poller |
| `GUARDIAN_PUBLISH_VERDICTS` | `false` | Write `TrustVerdict` entities back to Orion |
| `GUARDIAN_VERIFY_SIGNATURES` | `false` | Enforce per-reading signatures |
| `GUARDIAN_SHARED_DIR` | `shared/` | Schemas/fixtures (shipped inside this folder) |

## What is delivered

| Capability | Where to look | Evidence |
|---|---|---|
| Broker face (read + publish) | `src/guardian/orion.py`, `ngsi.py` | `tests/test_orion.py`, `tests/test_ngsi_triplet.py` |
| 5-stage trust pipeline | `src/guardian/pipeline.py` | `tests/test_pipeline.py` |
| 11 detectors (pure functions) | `src/guardian/detectors.py` | `tests/test_detectors.py`, `tests/test_orion.py` |
| 6-factor score + hard gates | `src/guardian/score.py`, `policy.yaml` | `tests/test_score.py` |
| Signed, expiring Evidence Passport | `src/guardian/passport.py` | `tests/test_passport.py` |
| Append-only hash-chained audit | `src/guardian/audit.py` | `tests/test_audit.py` |
| Effect Witness → history decay → quarantine | `api.py`, `pipeline.note_effect` | `tests/test_adversarial.py` |
| Nine triplet scenarios + logs | `scenarios/run_check.py` | `make checks`, `logs/` |
| Live 4-lane timeline | `static/`, `/ui/` | `make demo`, then open `http://localhost:8090/ui/` |

## Further reading

* [INTERFACE.md](INTERFACE.md) — the exact wire contract (verdict format, errors, auth)
* [TESTBOOK.md](TESTBOOK.md) — the nine scenarios with expected Guardian verdicts
* [docs/00-START-HERE.md](docs/00-START-HERE.md) — orientation for a reviewer
* [docs/05-REVIEWER-VERIFICATION.md](docs/05-REVIEWER-VERIFICATION.md) — how to verify each claim
* [mocks/README.md](mocks/README.md) — the offline world and the fake broker
* [scenarios/README.md](scenarios/README.md) — the check runner
