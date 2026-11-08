# 03 — Security matrix: threat → control → the test that proves it

**Scoring row:** Security & Trust Mechanisms (10 pts). **Principle:** a control that is
not tested is a claim, not a control. Every row below names the exact automated test
that would fail if the control regressed.

Run all of it with one command: `cd guardian && make test` (**199 tests, 19 of them
the adversarial matrix below**).

---

## 1. Threats, controls and proofs

| # | Threat | Control | Proving test / evidence |
|---|---|---|---|
| 1 | Forged signature on a reading | HMAC-SHA256 verified against the per-device keyring; failure is a hard gate, not a score deduction | `test_forged_signature_rejected` → `SIG_INVALID` |
| 2 | Value tampered after signing | Digest recomputed and compared; any byte change invalidates | `test_tampered_value_after_signing_rejected` |
| 3 | Exact replay of a frame | `reading_id` seen-set + digest window | `test_duplicate_reading_id_rejected` |
| 4 | Replay under a **fresh** id | Freshness gate + sequence + digest history, not id alone | `test_replay_under_fresh_id_is_malicious` |
| 5 | Stale frame kept alive | Age > TTL → `STALE` → `RESTRICT` | `test_stale_frame_rejected` |
| 6 | Frame stamped in the future | Skew guard rejects future phenomenon time | `test_future_stamp_rejected` |
| 7 | Sequence gap (dropped or injected frames) | Monotonic watermark per sensor | `test_sequence_gap_rejected` |
| 8 | Unknown / rogue device | Registry lookup is a hard gate before any scoring | `test_unknown_device_rejected` |
| 9 | Physically impossible value | Range profile per sensor type (`sensor_profiles.yaml`) | `test_out_of_range_downgraded_not_trusted` |
| 10 | Missing or forged provenance (firmware/cal) | Provenance factor + gate; unknown → downgraded | `test_missing_provenance_rejected_at_pipeline` |
| 11 | Malformed / hostile payload | Strict schema validation; stable code, HTTP 4xx, **never 500** | `test_schema_invalid_is_400_never_500` + `test_no_attack_returns_500` (fuzz sweep) |
| 12 | Expired passport reused | Half-open window `[issued, issued+ttl)`; 6 s default | `test_expired_passport_rejected` |
| 13 | Tampered passport | Passport signature re-verified before honouring | `test_tampered_passport_signature_rejected` |
| 14 | Action outside the evidence scope | `allowed_actions` is a class set; full commit absent on non-TRUSTED | `test_out_of_scope_action_refused_by_brain` |
| 15 | Actuator acknowledges and does nothing | Effect Witness: requested vs acknowledged vs **observed**; 3× MISMATCH quarantines | `test_three_mismatches_quarantine_and_downgrade` |
| 15a | A **coherently** faked sensor (g3): congestion, count and speed all agree with the lie | The corroborator that can clear a pinned ceiling must be a **different device**; a device's own channels never corroborate it | `test_steady_ignores_the_devices_own_other_channels`, `test_steady_fires_on_an_uncorroborated_pinned_ceiling` |
| 15b | A **stuck** sensor keeps publishing fresh timestamps, so freshness alone cannot catch it | Repetition rule per profile: identical values for N reads is the Twin's own stuck signature | `test_stuck_sensor_is_flagged_even_at_an_ordinary_level` |
| 15c | A **dead** sensor keeps its last entity on the broker forever | Device aggregation turns the absence of fresh verdicts into `OFFLINE`/`COMM_LOSS` — never "looks fine" | `test_staleness_becomes_offline_and_leaves_evidence_untouched` |
| 15d | A lawful decay is mistaken for a mute, convicting a real fire scene (b1) | TAMPER requires a collapse **beyond** the profile's own rate law | `test_lawful_decay_to_zero_is_not_tamper`, `test_a_cliff_to_zero_is_still_tamper` |
| 16 | Slow verdict (contract breach) | p95 design target 300 ms; **contractual floor 10 s** | `test_ingest_latency_within_contractual_floor`; measured 0.7–2.2 s |
| 17 | Audit-log tampering | Hash-chained JSONL; each record commits to the previous hash | `test_audit_chain_survives_attacks_and_detects_tampering` |
| 18 | **A full commit authorised by false evidence** | Passport scope ∩ Brain planning ∩ Twin re-verification | `test_no_full_commit_ever_dispatched_on_untrusted_passport` (cross-scenario) |

Row 18 is the one we consider the headline. It is not a unit test of one gate: it replays
six scenarios into one server, then joins the audit trail (`passport.issued` →
`action.requested`) exactly as a jury would. Measured over the committed evidence:
**0 violations** (`test_no_full_commit_ever_dispatched_on_untrusted_passport`).

Rows 15a–15d are the triplet's own adversarial set, and they are the reason this layer is
worth its place in the city: they are the attacks that *look healthy* from a single
device's point of view.

---

## 2. The non-bypassable rule (why this is enforcement, not a badge)

A dashboard that paints a row red changes nothing. The chain here is structural:

```
Guardian issues passport  →  allowed_actions ⊆ {full, reversible, precautionary}
        │                                  │
        │                        SUSPECT/RESTRICT/MALICIOUS ⇒ no "full"
        ▼                                  ▼
Brain may only plan inside allowed_actions ⇒ refuses with a recorded reason
        │
        ▼
Twin re-verifies passport signature + expiry + evidence digest + action class
        │
        └── mismatch ⇒ DENIED with a stable code
```

Three independent layers must agree before metal moves. No single layer can escalate.

---

## 3. Cryptographic design (and what it does not claim)

| Property | Implementation | Honest limit |
|---|---|---|
| Integrity | HMAC-SHA256 over the canonical frame digest | Symmetric; a compromised device key forges its own frames |
| Identity | Per-device keyring (`keys/dev_keys.json`, synthetic values) | Real deployments inject via `GUARDIAN_HMAC_KEY` / secret manager |
| Non-repudiation | Stated target: per-device **Ed25519** | Not yet wired; HMAC today |
| Evidence binding | Passport binds `zone + evidence_digest + policy_version + disposition + TTL` | — |
| Freshness | 6 s passport TTL, half-open interval | A clock difference between hosts breaks it (documented) |

**What cryptography does *not* give us — and we say so on stage:** a valid signature
proves *who sent a message*, never *that the message is true*. The entire trust pipeline
exists because of that distinction. T5 is a correctly signed lie.

---

## 4. Containment and "rollback"

We do not pretend to roll back physics. The spec asks for rollback of a **falsified
reading**, which we implement as three auditable steps:

1. **Supersede** — the reading is marked superseded; it can no longer mint a passport.
2. **Quarantine** — the device is excluded from provenance until it proves itself;
   the quarantine overlay is visible in `GET /describe` and on the timeline.
3. **Stabilise** — the affected zone is held to its safe state (barrier hold, pump
   standby), never driven further on doubtful evidence.

Recovery requires fresh, monotonic, corroborated evidence — not a timer.

---

## 5. Least privilege

| Identity | May | May not |
|---|---|---|
| Sensor (Twin) | POST readings, POST witness | request passports, decide, actuate |
| Brain | poll verdicts, request passport, propose **within** scope | authorise its own action, raise its own trust |
| Twin (actuator side) | execute only with a valid passport | execute on raw readings |
| Judge / console | read everything | write anything |
| Guardian | issue verdicts and passports | command actuators directly |

The Guardian has **no actuator credential**. It cannot move the city; it can only decide
what the city may be allowed to do. That is the point of a trust layer.

---

## 6. Residual risk (stated, not hidden)

1. **Coherent collusion** — if every source in a zone lies consistently, content-based
   detection fails. Mitigated (never solved) by requiring two corroborating sources and a
   `TRUSTED` verdict for full commits.
2. **Single-source zones** — cannot reach `TRUSTED` for high-stakes actions. Deliberate;
   costs coverage, buys safety.
3. **Simulation ≠ certification** — interlocks are modelled, not certified.
3a. **Broker trust is platform trust** — the Orion filter authenticates the *writer* with
   K1/K2, so we know who published a value, not that it is true. We do not fabricate a
   per-frame signature we cannot compute; the pipeline exists precisely because
   authentication ≠ truth (g1 is a correctly authenticated lie).
4. **Weights are v1** — calibrated on our own suite, versioned in `policy.yaml` and
   stamped on every passport so a reviewer can see which policy produced which verdict.
   The triplet-specific thresholds (`steady`, `jam`, profile ranges) are likewise data in
   `sensor_profiles.yaml`, tuned against the nine scenarios and pinned by tests.
5. **Local audit** — the hash chain makes tampering *evident*, not impossible; deleting
   the whole file is undetectable without an external checkpoint.
6. **Clock skew** — freshness assumes roughly synchronised hosts; documented, not solved.

---

## 7. Standards alignment (context, not compliance claims)

Design shaped by: NIST IR 8356 (digital-twin trust), NIST SP 800-82 Rev.3 (OT safety
constraints), NIST SP 800-207 (zero trust at the resource boundary), NIST IES-City
(pivotal interoperability points), MITRE ATT&CK for ICS T1692.002 (spoofed reporting),
W3C SSN/SOSA + OGC SensorThings (observation modelling). We align with their *reasoning*;
we claim no certification.
