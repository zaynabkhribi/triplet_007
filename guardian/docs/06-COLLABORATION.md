# 06 — Collaboration process (R3)

**Spec requirement (R3).** Each triplet documents how the three teams coordinated, how a
partner failure or change was handled, and provides proof of a successful joint run.

This file records the **Guardian team's** side of that process. It is written so that a
reviewer can distinguish what we did from what we expect from partners — and so that
nothing here is a vague promise.

---

## 1. How the three teams coordinated

| Element | Practice |
|---|---|
| **Single written contract** | The repository-root [`INTEGRATION.md`](../../INTEGRATION.md) is the triplet's contract; our side of it is [`INTERFACE.md`](../INTERFACE.md). It changes only with a reviewer from each layer (`CODEOWNERS`). |
| **The broker is the boundary** | The Twin's contract is NGSI v2 entities on Orion, not a function call. We adapted to it rather than asking them to change: `ngsi.yaml` maps their attribute names, and `orion_devices.json` mirrors their device list. |
| **Offline by default** | `mocks/orion_world.py` freezes the Twin's published physics and `mocks/mock_orion.py` serves it as a broker, so every one of our nine checks runs with no platform and no partner. Integration only changed *fidelity*, never *availability*. |
| **One-command demo as a checkpoint** | A layer is "integrated" only when `make demo` + one `run scenario <id>` works on a clean clone. Verbal readiness does not count. |
| **Log files as shared evidence** | Every run writes `logs/<id>-<stamp>.log` in the shared `date time TYPE text` shape. Disagreements about behaviour are settled by opening a log, not by recollection. |
| **Config, not code, at the boundary** | All partner hosts, TTLs and thresholds are environment/config. A partner change is a config diff — reviewable in seconds. |

**Cadence:** interface freeze before feature work; integration checks at each milestone;
a full joint dry-run before the submission freeze. The written contract is the source of
truth in between — not a chat thread.

---

## 2. How a partner failure or change is handled

This is the part the spec is really testing: does the triplet survive contact with
reality? Our answer is structural.

| Partner event | Our response | Cost to us |
|---|---|---|
| Twin/Brain **late** | We run against the frozen world + fake broker; the layer is fully demonstrable | none to our score |
| Partner **changes the broker** | `GUARDIAN_BROKER_URL` — one env var | a config change, no code change |
| Partner **renames or adds an attribute** | `ngsi.yaml` (+ a profile if it is new physics) | one YAML edit, no code change |
| Partner **adds a device** | `orion_devices.json` (or point at their `config.json`) | one data edit, no code change |
| Partner **goes silent** | No fresh verdicts → `OFFLINE`/`COMM_LOSS` on the device face; the loop continues | reduced fidelity, never a crash |
| Partner **sends malformed data** | Schema gate returns a stable code; server stays up | a rejected frame, logged |
| Partner **lies about an effect** | Witness `MISMATCH` → history decay → quarantine | the partner's device loses trust, correctly |
| **Re-matched to a new team** (Phase 2) | Re-point by config, run `GET /describe` handshake, replay golden + attack fixtures | target: under 45 minutes |

**The design consequence we would defend on stage:** no partner-specific logic exists
inside our core. If it did, a rematch would be a rewrite. This is why the interoperability
work is the same work as the resilience work — they are not two features.

---

## 3. Proof of a successful joint run

Reproducible with one command, with no platform and no partner binary:

```bash
cd guardian && make checks      # nine scenarios -> logs/<id>-<stamp>.log + PASS/FAIL
```

Each log is a timestamped artefact containing:

1. the complete chain for that scenario — the entity the Twin published (`PUBLISH`), the
   Guardian's verdict changes (`GUARDIAN`), and the final device face the Brain would read
   (`VERDICT`);
2. the pass/fail verdict of the run, against the shared Test Book's expectations;
3. the shared triplet vocabulary — `TRUSTED` / `UNTRUSTED` / `OFFLINE` with reason codes —
   which is exactly what the Twin's own mock Brain consumes.

The committed artefacts from the final green run are in [`logs/`](../logs/).

**A note a reviewer should read honestly:** this joint run uses the Twin's *published
semantics* (frozen from `twin/src/model.py`) served by our fake broker — not the partner
teams' live deployment. The claim it supports is *"our layer completes and closes the loop
against the triplet's real NGSI contract, and stays healthy when a partner is absent"*,
which is what the spec lets a team prove offline. It does not claim we have run against a
partner's live binary, and we will not say we have.

---

## 4. What we need from partners (stated for the Phase 2 handshake)

**From a Twin:** keep publishing the sensor entities we poll (nothing to call); if you add
a device, tell us its kind and attributes so `ngsi.yaml` can map them; if you want push
semantics, `POST /v1/readings` runs the same pipeline.

**From a Brain:** read `GET /verdicts` each tick; treat `UNTRUSTED` as "do not act on this
alone" and `OFFLINE` as "no data" — never as "normal"; when you want a signed proof behind
a decision, cite the `evidence_digest` and ask for a passport.

Both checklists are in [`INTERFACE.md`](../INTERFACE.md).

---

## 5. Division of work inside the Guardian team

Ownership by area, so a reviewer can see who is answerable for what (and so bus-factor is
not one person):

| Area | Owns |
|---|---|
| Trust pipeline | `pipeline.py`, `score.py`, `detectors.py`, `policy.yaml` |
| Triplet integration | `ngsi.py`, `orion.py`, `ngsi.yaml`, `sensor_profiles.yaml` |
| Contract & evidence | `INTERFACE.md`, `/describe`, `mocks/`, `scenarios/`, `logs/` |
| Validation & evidence | `tests/`, acceptance targets, logs, replay determinism |
| Passport, registry & audit | `passport.py`, `registry.py`, `witness`, `audit.py` |

*Team names and handles are maintained in the submission form and repository settings;
they are intentionally not duplicated into this document, which describes process rather
than personnel.*
