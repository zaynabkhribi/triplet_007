# 02 — Test Book index

A one-page index into the Guardian Test Book ([`../TESTBOOK.md`](../TESTBOOK.md)) and into the
shared triplet one ([`../../TESTBOOK.md`](../../TESTBOOK.md)). The shared book defines the nine
scenarios; this layer must produce the Guardian column for every one of them.

---

## Coverage of the four required demonstrations

| Spec category | Proven by |
|---|---|
| The city runs normally and the Brain reacts correctly | **n1** calm · **a1** traffic jam · **b1** fire · **c1** waste |
| The Guardian recognises healthy **and** unhealthy data | **n1/a1/b1/c1** (yes) vs **g1/g2/g3** (no) |
| Trust verdicts change decisions, and decisions stay safe | **g1**, **g3**, **m1** — the fake claims never become commands |
| The whole city works as one system, including failure | **m1** fire + fake jam · **d1** Brain absent |

## Coverage of every interaction

| Interaction | Scenario |
|---|---|
| Twin → Guardian (write → poll) | all nine (the Guardian reads the broker) |
| Guardian → Brain (`/verdicts`) | all nine |
| Guardian keeps working with the Brain absent | **d1** |
| Guardian separates two truths and one lie at once | **m1** |
| Guardian is not fooled by a *coherent* fake | **g3** (the fake generator also fakes its own camera and speed) |

---

## The nine scenarios

| ID | Name | Guardian verdict | Reason | Proves |
|---|---|---|---|---|
| **n1** | Calm day | every device `TRUSTED` | `OK` | we do not overreact |
| **a1** | Traffic jam, roads 1 and 2 | `TRUSTED` | `OK` | a real jam, corroborated by a sibling road |
| **b1** | Fire in building 1 | `TRUSTED` | `OK` | we say **yes** as confidently as no |
| **c1** | Waste / illegal dumping | `TRUSTED` | `OK` | an incident is not an attack |
| **g1** | Spoofed smoke (400 ppm, 22 °C) | `UNTRUSTED` | `CONFLICT` | smoke without heat is not combustion |
| **g2** | Stuck and dead sensors | `UNTRUSTED` / `OFFLINE` | `JAM` / `COMM_LOSS` | repetition, then silence |
| **g3** | **Fake traffic jam** | `UNTRUSTED` | `STEADY_ANOMALY` | a pinned ceiling nobody else confirms |
| **m1** | Real fire + fake jam | building `TRUSTED`, fake road `UNTRUSTED` | `OK` / `STEADY_ANOMALY` | two truths and one lie, separated |
| **d1** | Brain down, fire burning | building `TRUSTED` | `OK` | trust does not depend on the consumer |

---

## Reproduce any of it

```bash
cd guardian
make checks               # all nine, offline, PASS/FAIL
make check id=g3          # one scenario
```

Each run emits `logs/<id>-YYYYmmdd-HHMMSS.log` in the shared `date time TYPE text` shape.
The runner exits **non-zero** on any mismatch, so this is a pass/fail gate, not a print
statement — `make checks` is what CI would run.

Every row above is pinned by `tests/test_ngsi_triplet.py` and `tests/test_orion.py`; if a
detector or profile change moves a scenario, the suite fails rather than the demo silently
drifting.

---

## Why these nine, and what makes them hard

The easy half (n1, b1, c1) proves the Guardian does not block the city. The hard half
(g1, g2, g3, m1) is where a trust layer earns its place:

- **g1** — a *physically impossible* pair. Easy to catch, and a good baseline.
- **g2** — two failures that look like success: a stuck sensor keeps publishing fresh
  timestamps, and a dead one keeps an entity on the broker. Only repetition and freshness
  separate them.
- **g3** — the real test. The Twin's fake generator renders congestion, vehicle count and
  speed *coherently*, so internal consistency cannot expose it. Only a second **device**
  can. This is why the detector's corroboration is directional and device-independent, and
  why `a1` (a genuine jam at the same levels) must still pass.
- **m1** — g3 and b1 in the same tick, so a rule that fires globally instead of per device
  fails immediately.

---

## What we do not test (and say so)

- **Organiser-supplied scenarios** — we cannot see them. The mapping is data
  (`ngsi.yaml` + `sensor_profiles.yaml`), so a new device is a config edit.
- **Coherent collusion across multiple devices** — the corroboration model assumes
  independence. If two devices lie *together*, and consistently, we trust them; no
  cross-device scheme is detectable from values alone at this scale.
- **Real hardware actuators** — the Twin is a simulation, by design of the challenge.
- **The older T1–T7 / S1 fixture bands** — kept as frame-level regression tests
  (`tests/test_testbook.py`), not as the triplet demo path.
