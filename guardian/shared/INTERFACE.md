# AEGIS LOOP — shared interface contract (owner: all three teams)

This folder is the only coupling between Twin, Brain and Guardian. Each side
may evolve freely behind it; nothing here changes without all three teams.

## Frames

| File | Who writes | Who reads | Purpose |
|---|---|---|---|
| `schema/reading.json` | Twin | Guardian | one sensor frame; `digest` = `sha256` of the frame minus digest/signature; `signature` = HMAC or `ed25519:*` over the digest |
| `schema/passport.json` | Guardian | Brain, Twin | signed verdict: `disposition` (`TRUSTED/SUSPECT/RESTRICT/MALICIOUS`), `trust`, `reason_codes`, `allowed_actions` (`full/reversible/precautionary`), `conditions`, 5–7 s expiry |
| `schema/action.json` | Brain | Guardian, Twin | `action_id + passport_id + evidence_digest + action + idempotency_key + target + target_version`; Twin re-verifies before touching hardware |
| `schema/witness.json` | Twin | Guardian | `requested vs acknowledged vs observed`; `CONFIRMED/MISMATCH` feeds trust history, 3× mismatch quarantines the device |
| `schema/describe.json` | Guardian | anyone | machine-readable contract served at `GET /describe` |

## Verdict legend

`TRUSTED ≥ 0.80` (full allowed) · `SUSPECT 0.50–0.79` (reversible only) ·
`RESTRICT < 0.50` (precautionary only) · `MALICIOUS` (TAMPER/SPOOF/REPLAY;
trust capped 0.49). Trust formula (v1, stamped on every passport):

```
T = 0.30·corroboration + 0.20·consistency + 0.18·plausibility
  + 0.12·provenance + 0.10·freshness + 0.10·history − 0.25·conflict
```

## Fixtures and truth hiding

`fixtures/*.json` are Twin-authored streams. Each carries
`ground_truth` for the jury/Twin only — the Guardian and Brain must never read
it; verdicts depend on frame content alone. Frames ship canonically dated and
are re-stamped + re-signed at run time (`mock_twin --rebase`), so a joint run
replays bit-identically from `logs/*-latest.jsonl`.

## Adding a sensor

Twin: add the device to `guardian/keys/dev_keys.json` and its profile to
`guardian/sensor_profiles.yaml` (`min/max`, `max_rate`, corroborators).
Guardian: no code change — profiles and keyring are data. The scenario that
exercises it goes in `TESTBOOK.md` with its expected band.
