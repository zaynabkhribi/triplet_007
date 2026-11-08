# 05 — Reviewer verification

**Purpose.** Every substantive claim this submission makes is listed here with the one
command that re-proves it, and with the exact output a reviewer should see. Nothing in this
document is asserted without a check beside it.

Run everything from `guardian/`. Times are measured on a laptop, Python 3.9/3.11.

---

## A. Build, quality and regression

| # | Claim | Prove it | Expected |
|---|---|---|---|
| A1 | Clean setup in well under 10 minutes | `make setup` | finishes in ~20 s |
| A2 | The whole suite passes | `make test` | **199 passed** |
| A3 | No static-analysis findings | `make lint` | `All checks passed!` |
| A4 | Every scenario is reproducible, not lucky | `make checks` twice | identical verdicts both times |
| A5 | Checks are a gate, not a print | `PYTHONPATH=src:. .venv/bin/python scenarios/run_check.py` | exit code 0 only when all nine pass |

> **A4** holds because the runner builds a fresh pipeline, a fresh world and a fresh dedup
> set per scenario: the nine scenarios cannot contaminate one another, and no state leaks
> between runs.

---

## B. Functional correctness — the nine scenarios

```bash
make checks        # one command, all of it
```

| # | Claim | Prove it | Expected |
|---|---|---|---|
| B1 | A fake jam is caught | `make check id=g3` | `us-a-traf-03` → `UNTRUSTED` / `STEADY_ANOMALY`, `trust≈0.73` |
| B2 | A real jam is **not** flagged | `make check id=a1` | all three roads `TRUSTED` |
| B3 | Spoofed smoke is caught | `make check id=g1` | building `UNTRUSTED` / `CONFLICT`, `trust≈0.54` |
| B4 | A real fire stays trusted | `make check id=b1` | building `TRUSTED`, `trust≈0.94` |
| B5 | A stuck sensor is caught | `make check id=g2` | `us-a-traf-03` → `UNTRUSTED` / `JAM` |
| B6 | A dead sensor is caught | `make check id=g2` | `us-a-traf-02` → `OFFLINE` / `COMM_LOSS` |
| B7 | Filling a bin is not an attack | `make check id=c1` | bin `TRUSTED` |
| B8 | Two truths and one lie, one tick | `make check id=m1` | building `TRUSTED`, fake road `UNTRUSTED` |
| B9 | No Brain still means trustworthy sensors | `make check id=d1` | building `TRUSTED` |
| B10 | We do not overreact | `make check id=n1` | every device `TRUSTED` |

> B2 and B4 matter as much as B1: a trust layer that only ever says *no* would block the
> Brain's real fire alarm and fail the triplet's own b1. We must say **yes as confidently as
> we say no** — decided by evidence alone.

---

## C. Security invariants

| # | Claim | Prove it | Expected |
|---|---|---|---|
| C1 | No full commit on untrusted evidence, across all scenarios | `make test` → `test_no_full_commit_ever_dispatched_on_untrusted_passport` | 0 violations |
| C2 | 19 adversarial cases held, none returns a 500 | `make test` → `tests/test_adversarial.py` | 19 passed |
| C3 | A forged signature is rejected | same, `test_forged_signature_rejected` | code `SIG_INVALID` |
| C4 | Replays and duplicates are rejected | same | `DUPLICATE` / replay flag |
| C5 | Tampering is detectable | same, `test_three_mismatches_quarantine_and_downgrade` | 3× MISMATCH → quarantined |
| C6 | The audit chain detects a byte flip | same, audit tests | tamper detected, chain invalid |
| C7 | A coherent lie does not clear itself | `make test` → `test_steady_ignores_the_devices_own_other_channels` | `STEADY_ANOMALY` (own channels never corroborate) |
| C8 | A lawful decay is not convicted | `make test` → `test_lawful_decay_to_zero_is_not_tamper` | no `TAMPER` on b1's evacuation |
| C9 | Secrets are not committed | `git ls-files guardian | grep -i 'secrets\|\.env'` | nothing (the dev keyring holds synthetic values) |

Full threat → control → proof table: [`03-SECURITY-MATRIX.md`](03-SECURITY-MATRIX.md).

---

## D. Interoperability (the 15-point row)

| # | Claim | Prove it | Expected |
|---|---|---|---|
| D1 | Capability card is machine-readable | `curl localhost:8090/describe` | layer, protocol, endpoints, accepted sensor types, latency contract |
| D2 | The feed is the Twin's own shape | `curl localhost:8090/verdicts` | `{device: {verdict, reason, checked, …}}` |
| D3 | Broker wiring is inspectable, not assumed | `curl localhost:8090/orion/status` | broker, polled count, cycles, unreachable list |
| D4 | Re-point at a broker without touching code | `GUARDIAN_BROKER_URL=… make demo` | works unchanged |
| D5 | Add a device without touching code | edit `ngsi.yaml` + `orion_devices.json` | new device appears in `/verdicts` |
| D6 | The layer runs with no platform account | `make checks` (offline fake broker) | all nine pass, no network |
| D7 | A manual read is explainable per frame | `curl -XPOST localhost:8090/v1/ngsi/poll -d '{}'` | per-frame `accepted`/`code` plus the verdicts |
| D8 | Container path works | `docker compose up -d guardian` (repo root) | serves on :8090, poller starts |
| D9 | Malformed input fails with a code, not a crash | `make test` → malformed-body sweep | stable code, HTTP 4xx, never 500 |

Searchable proof that no host is hard-coded:

```bash
grep -rn "127.0.0.1\|localhost" src --include=*.py | grep -v mock
```

The only hits are config **defaults** and CLI defaults for the stand-ins — every value is
overridable by environment variable.

---

## E. Documentation & demo

| # | Claim | Where |
|---|---|---|
| E1 | The contract a partner needs, with wire examples | [`INTERFACE.md`](../INTERFACE.md) |
| E2 | The nine scenarios with the Guardian column | [`TESTBOOK.md`](../TESTBOOK.md) |
| E3 | Shared triplet book (Twin side) | [`../../TESTBOOK.md`](../../TESTBOOK.md) |
| E4 | Minute-by-minute demo, including an offline path | [`04-DEMO-RUNBOOK.md`](04-DEMO-RUNBOOK.md) |
| E5 | Threat → control → proving test | [`03-SECURITY-MATRIX.md`](03-SECURITY-MATRIX.md) |
| E6 | Offline world + fake broker explained | [`../mocks/README.md`](../mocks/README.md) |
| E7 | Check runner explained | [`../scenarios/README.md`](../scenarios/README.md) |

---

## F. Honest limitations (stated, not hidden)

We would rather a reviewer hear these from us than find them:

1. **Coherent collusion.** If *every* source in a zone lies consistently, the Guardian cannot
   detect it from content alone. g3 shows the good case: one device lies, another device is
   the falsifier. Two devices lying together are not detectable at this scale.
2. **Broker authentication is not truth.** The Orion filter authenticates the writer with
   K1/K2; it says nothing about the value. We do not fabricate a per-frame signature we
   cannot compute. g1 is exactly that: a correctly authenticated lie.
3. **Simulation is not certification.** Safety interlocks are modelled, not certified for
   real infrastructure.
4. **Weights and thresholds are v1.** `policy.yaml` and the `steady`/`jam` profile blocks are
   versioned data, calibrated against the nine scenarios and pinned by tests — not against
   field data.
5. **Single-source zones** cannot corroborate a claim; the Guardian deliberately becomes
   conservative rather than confident there.
6. **Local audit needs an external checkpoint.** The hash chain makes tampering evident; it
   does not prevent deletion of the whole file.
7. **Write-back is off by default.** Publishing `TrustVerdict` entities needs the Guardian's
   own K1/K2, which are never committed; `/verdicts` is the delivery path that ships armed.

---

## G. If a check above fails

That is a defect, and the honest response is to report it. Capture:

```bash
cd guardian && make test 2>&1 | tail -40
make checks 2>&1 | tail -20
```

and include the relevant `logs/<id>-<stamp>.log` — it is the exact entity timeline for that
run, and it is sufficient to reproduce any verdict deterministically.
