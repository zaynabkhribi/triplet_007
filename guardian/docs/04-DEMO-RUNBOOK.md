# 04 — Demo runbook (CSTAM, 14 November 2026 · 10-minute slot)

**Format:** 2-minute pitch (strict) + 8-minute live demo, judges may interrupt.
**Rule:** nothing is installed on stage. If the live link fails you get 2 minutes to
recover, then the jury falls back to code and logs.

**Operating principles**
1. **Local-first.** Laptop + guardian only. No venue Wi-Fi, ever — the offline fake broker exists for that.
2. **Two machines.** Demo laptop and a warm backup, both pre-run.
3. **One narrator, one operator.** The narrator never touches the keyboard.
4. **Every state on screen must be explainable.** If you cannot explain a lane, do not show it.

---

## 0. T-minus 20 minutes (setup area)

```bash
cd repo/guardian && make setup          # only if the venv is missing
make test                               # 200 passed — do this BEFORE the slot
make checks                             # all nine scenarios -> logs/, PASS/FAIL
make demo                               # :8090 up
# second terminal, warm the feed:
curl -s localhost:8090/orion/status | python3 -m json.tool
```

If the venue has no route to the Smartopia broker, run the **offline demo** instead — this
is the safe default, and it is the same shipping code:

```bash
make mock-orion                                   # terminal 1: fake Orion on :8025
GUARDIAN_BROKER_URL=http://127.0.0.1:8025 make demo   # terminal 2
curl -XPOST localhost:8025/scenario -d '{"name":"g3"}'   # terminal 3: trigger
```

Checklist — tick every line:

- [ ] `localhost:8090/verdicts` returns JSON with real devices, not an empty object
- [ ] `make test` green in the last 10 minutes
- [ ] `logs/` contains the nine scenario logs from `make checks`
- [ ] `docs/05-REVIEWER-VERIFICATION.md` open in a viewer (each claim + its command)
- [ ] Backup laptop: same commands already run, server already up
- [ ] Offline fake broker started and one scenario already triggered once
- [ ] Screen resolution readable at distance; browser zoom ≥ 110 %
- [ ] Notifications silenced, second monitor mirroring checked

**Readiness check the jury will make:** the feed shows a live face. Make sure it does *not*
show everything `OFFLINE` (that means the broker is unreachable — switch to the offline
demo). Run `n1` as the resting state: it is the honest "city running normally" picture.

---

## 1. The 2-minute pitch (0:00–2:00)

| Time | Slide | Say |
|---|---|---|
| 0:00–0:20 | 1 Cover | "Three systems, one city. We are the layer that decides whether data deserves power." |
| 0:20–0:50 | 2 Problem | "Every smart city treats a **well-formed** message as a **true** one. A sensor with valid credentials can lie — and the operations centre will still raise its alert." |
| 0:50–1:30 | 3 Solution | "So the Guardian reads the broker itself, judges every device every tick, and answers with one word and a reason code. Anything suspicious is `UNTRUSTED` — and behind a `TRUSTED` verdict stands a signed, scoped, 6-second Evidence Passport." |
| 1:30–1:50 | 4 Proof | "Real: a road reporting a permanent jam that no other road sees — caught in seconds, marked `STEADY_ANOMALY`, and the Brain never touches a light because of it." |
| 1:50–2:00 | 6 Close | "Other cities react to data. Ours asks whether the data deserves power." |

**Do not** read slide text aloud. The deck carries the detail; you carry the argument.

---

## 2. The 8-minute live demo (2:00–10:00)

### 2:00–3:00 · The resting city (n1) — *it must not overreact*

```bash
make check id=n1
```

Point at the verdict lines: every device `TRUSTED`, `trust≈0.94`.

> Say: "A trust layer that cries wolf is worse than none. This is the same pipeline
> saying *yes* to the whole city."

### 3:00–4:30 · Spoofed smoke (g1) — *the impossible pair*

```bash
make check id=g1
```

Walk the log:

1. Twin publishes **smoke 400 ppm at 22 °C**.
2. Guardian: `us-b-bldg-01` → **`UNTRUSTED` / `CONFLICT`**, `trust≈0.54`.
3. The reason is a physical law, not a threshold: smoke and heat are coupled; heat never rises.

> Say: "The data was well-formed and the credentials were valid. **And it lied.** Crypto
> proves who spoke, never what is true — that is why this layer exists."

### 4:30–6:00 · The fake jam (g3) vs the real jam (a1) — *the money minute*

```bash
make check id=g3     # fake: UNTRUSTED / STEADY_ANOMALY
make check id=a1     # real: TRUSTED, both roads agree
```

Put the two logs side by side. The fake generator renders congestion, vehicle count and
speed **coherently**, so nothing inside the device looks wrong. Only a second device can
tell — and it does not confirm it.

> Say: "Same numbers as a real jam. The difference is **independence**: a real jam is
> confirmed by another road. This one is a story only one device tells."

### 6:00–7:00 · Two failures that look like success (g2)

```bash
make check id=g2
```

One road repeats its payload forever → `UNTRUSTED / JAM`. The other goes silent, and the
broker keeps its last entity — so the value still looks perfectly healthy. → `OFFLINE /
COMM_LOSS`.

> Say: "A dead sensor that keeps answering is the trap. Only freshness catches it."

### 7:00–8:00 · Interoperability — *the 15-point row*

```bash
curl -s localhost:8090/describe        # capability card
curl -s localhost:8090/orion/status    # broker + poller health in one read
```

Read the status aloud: broker, polled devices, cycles, unreachable list. Then state the
re-point: one variable (`GUARDIAN_BROKER_URL`), one mapping file (`ngsi.yaml`), no code.

> Say: "Nothing about your platform is in our code. Point us at your broker with one
> variable, and add a device in a YAML file."

### 8:00–9:00 · All of it at once (m1) — *depth without risk*

```bash
make check id=m1
```

Real fire **and** a fake jam in the same tick: building `TRUSTED`, fake road `UNTRUSTED`,
everything else untouched. This is the answer to "does it fire too broadly?".

### 9:00–10:00 · Questions, with the server still live

Leave the server running, and keep `docs/03-SECURITY-MATRIX.md` open. If asked to re-run
anything — do it. It is deterministic. That re-run is your strongest answer to "is this a
canned demo?"

---

## 3. Failure playbook

| Failure | Do this | Say this |
|---|---|---|
| Server won't start | `cd guardian && make setup && make demo` | "Give us thirty seconds." |
| Port 8090 taken | `make demo PORT=8091` and reload | nothing — just do it |
| Broker unreachable (everything `OFFLINE`) | switch to the offline demo (`make mock-orion` + `GUARDIAN_BROKER_URL=…`) | "The platform route is down, so here is the same code against a local broker." |
| A check FAILs live | **stop**, show the committed log from `logs/` | "That run failed; here is the committed trace from a green run." |
| Laptop dies | switch to backup (already running) | "Second machine, same commit." |
| Total network loss | the offline demo needs no network | "Everything is local." |
| A judge asks about something you can't explain | say so | "I'll show you the log for that event." — never invent |

**Never** debug in silence, never claim a number you cannot open in a log, and never blame
a partner team on stage. The spec scores our layer, not theirs.

---

## 4. Rehearsal protocol

1. Full timed run ×3, on the actual demo hardware, starting from the T-minus checklist.
2. One run with a deliberate failure injected (kill the server mid-scenario).
3. One run in **offline mode** (fake broker) — this is the mode most likely to be needed.
4. One run where the operator is a different team member.
5. Record the fourth run as video backup.
6. Freeze code after rehearsal 5. Only blocking fixes after that.

---

## 5. Numbers to have memorised

| Fact | Value |
|---|---|
| g3 fake jam | `UNTRUSTED`, `STEADY_ANOMALY`, `trust≈0.73` |
| g1 spoofed smoke | `UNTRUSTED`, `CONFLICT`, `trust≈0.54` |
| g2 stuck / dead | `UNTRUSTED` `JAM` / `OFFLINE` `COMM_LOSS` |
| Healthy device | `TRUSTED`, `trust≈0.94` |
| Poll cadence | **5 s** (= the Twin's tick) |
| `OFFLINE` after | **20 s** ≈ 4 silent polls |
| Passport TTL | **6 s** |
| Tests | **200**, of which **19** adversarial |
| Full commits on false evidence | **0** (asserted by test) |
| Scenarios | **9**, all replayable offline with one command |
| Trust thresholds | `TRUSTED ≥ 0.80` · `SUSPECT 0.50–0.79` · `RESTRICT < 0.50` · hard flag → `MALICIOUS` (capped 0.49) |
