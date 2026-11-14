# Real integration checkpoint — 2026-11-14

This records executed evidence, not a claim that the jury demo is complete.

## Executed and observed

- Generated a non-default 256-bit shared HMAC key. The key and preserved original
  service environments are encrypted using Windows current-user DPAPI in
  `%LOCALAPPDATA%\AEGISCITY\runtime\profiles.dpapi`, outside the repository and
  OneDrive. The directory has restricted ACLs. No plaintext key was printed.
- Restarted Guardian only after checking its command, environment and console
  isolation. Guardian PID at this checkpoint: 47980. Twin was not restarted.
- Real production evidence matching produced 30 exact / 29 TRUSTED matches in
  the successful verification window; counts are historical, not fixed targets.
- Real temperature Passport for audit sequence 106481: HTTP 200, TRUSTED, exact
  digest, `SIGNATURE VERIFICATION: VALID`, `DEFAULT_KEY_NOT_MATCHED`.
  The issuance time was 2026-11-14T02:28:46.416854Z.
- Brain was restarted with the same protected key. Its initial graceful shutdown
  stalled after closing the listener. A consistent SQLite backup passed
  `PRAGMA quick_check` before the drained process was terminated. No database was
  reset, replaced or seeded. Backup: `logs/pre-brain-restart-1794623589365460800.db`.
  Brain PID at this checkpoint: 43748.
- At 2026-11-14T02:35:17.998612Z, the real City State returned trusted smoke
  1.9 ppm and temperature 22.0 degC, each with one `guardian_passport` evidence
  reference. This is momentary native eligibility, not a fabricated durable
  GuardianVerdict or a permanent trust grant.
- Smoke was below the configured thresholds. No real incident was created.
  A real decision evaluation returned REJECTED / NO_ACTION / policy_not_approved.
- No live actuator PATCH, emergency action, automatic approval or remote Twin
  scenario trigger was performed.
- Final real verification: audit sequence 110617, Passport issued
  2026-11-14T02:46:33.189217Z, exact digest, signature VALID, development key
  NOT MATCHED. The default-key probe's generic “issuer unverified” wording refers
  only to that probe; step [5] separately verified the configured protected key.
- Final tested Brain code deployed as PID 23264. Graceful shutdown again drained
  the listener but timed out after 120 seconds. The verified old Brain process
  alone was terminated after a consistent SQLite backup and successful quick
  check: `logs/pre-final-brain-restart-1794624548839026000.db`. This shutdown hang
  remains an operational limitation; do not launch duplicate processes.
- At 2026-11-14T02:49:32.215484Z, restarted Brain was ready and reported smoke
  2.9 ppm and temperature 22.2 degC as available/trusted through native Passports,
  with one evidence reference each and no active incident. Process environment
  confirmed execution=false, auto-approval=false, Passport=true, evidence age=30.
  Guardian PID 47980 remained running; no further Guardian restart was needed.

## Runtime settings applied through the process environment

```
ENV_FILE=<brain>/.env.real-readonly
GUARDIAN_PASSPORT_ENABLED=true
GUARDIAN_PASSPORT_MAX_EVIDENCE_AGE_SECONDS=30
ACTUATOR_EXECUTION_ENABLED=false
OPERATIONAL_AUTO_APPROVE=false
INCIDENT_RULES_FILE=config/incidents.real-zoneb.candidate.yaml
DECISION_POLICY_FILE=config/policies.real-zoneb.candidate.yaml
ORION_ENTITY_PREFIX=
ORION_ACTUATOR_SECRETS_FILE=<repository>/twin/secrets.json
```

The HMAC key is injected privately. The dotenv file was not rewritten. The
candidate action policy remains `approved: false`, with no invented approval
reference or incident-policy approval hash. The smoke rule is active for
supervised observation only; its thresholds are Twin-demo thresholds, not
validated physical fire-safety criteria.

## Security and remaining acceptance blockers

The signed digest binds the original observation timestamp. Brain limits its age
to 30 seconds and caps eligibility by both that deadline and Passport expiry.
Network time consumes validity; newly issued Passports are checked at receipt.
Existing explicit rejection, revocation, conflicting verdict and quarantine
checks cannot be overridden by the native Passport path. Failed refreshes clear
eligibility. No TrustEngine logic was weakened.

Guardian does **not** sign an original assessment timestamp, revision/revocation
state or current quarantine assertion in this contract. Bounding original
observation age is not proof that the assessment has been refreshed. Accordingly,
the native-Passport path cannot enqueue or dispatch live Orion commands;
`guardian_passport_execution_contract_incomplete` is an explicit rejection.
Removing that restriction requires a separately verified safe simulation-only
execution scope or a sufficient Guardian authorization contract, not disabling
the checks.

The inspected Twin source models simulation state, but the operator has not
confirmed the absence of other physical/emergency consumers of the shared broker
entities. Do not command us-b-alarm-01 or us-b-disp-01 on that assumption.
If isolation cannot be confirmed, the platform operator must register a separate,
clearly labeled demo actuator, issue its own device credentials privately, and
identify its allowed attributes and Twin readback contract. Existing device K1/K2
values are not authority to register a different entity or log into Smartopia.

The configured Snap4City dashboard is:
https://smartopia.polytecsousse.dev/dashboardSmartCity/view/index.php?iddasboard=Mjc%3D
It redirected to Smartopia login. No dashboard account access is available, so no
widget or visible state change has been verified. A dashboard operator must
provide access or witness the approved demo and capture the actual indicator.

The repository identifies Twin owner `zaynabkhribi`. No coordination message was
sent: the detailed public issue was blocked by approval review; the reduced
non-sensitive contact request failed with GitHub integration HTTP 403. Relay this
privately: confirm isolated device scope (or provision a new demo entity), arrange
the approved b1 scenario and its stop/reset procedure, and identify the dashboard
indicator showing applied state plus publication time. Never post keys publicly.

## Repeatable commands (Windows PowerShell 5.1)

Use the same Windows account that provisioned DPAPI. Python requires `psutil`
(included in the project's development dependencies). Never run the combined
three-layer launcher: it would also start Twin.

```powershell
cd 'C:\Users\moham\OneDrive\Desktop\New folder (12)\triplet_007\brain'

# Uses the existing protected key; refuses absent/unreadable profiles.
python scripts/secure_runtime.py verify

# Only when a restart is required. Preserves the captured environment and argv.
python scripts/secure_runtime.py restart guardian
python scripts/secure_runtime.py verify
python scripts/secure_runtime.py restart brain --observe

# Inspect real City State; no scenario trigger or action approval.
python scripts/report_real_state.py

# Persist an evaluation only; never approves or executes it.
python scripts/report_real_state.py --evaluate
```

`--observe` requires a successful real non-default signature verification within
the last ten minutes and always pins execution/auto-approval off. Without it,
Brain starts with native Passport eligibility disabled. `start <service>` is for
an already stopped service and refuses an occupied port or draining old process.
`provision` is one-time and refuses to overwrite an existing protected profile.
Do not copy a profile to a different Windows user or machine and expect DPAPI
decryption to work. No automatic fallback to the development key exists here.

If graceful shutdown fails, do not launch a duplicate service or delete SQLite
files. Inspect the verified process and take a consistent backup before any
separately supervised forced termination.

## Tests

Full regression command executed successfully:

```
python -m pytest -q --basetemp=.pytest-final-complete -o addopts= -o faulthandler_timeout=60
```

Result: 340 passed in 242.32 seconds. A diagnostic stack dump appeared for a slow
traffic-inference test, but the test finished and the suite exited successfully.
Sandboxed tests initially stalled while Windows asyncio created a local socket
pair; those test processes alone were stopped and the suite ran with the required
host loopback permission.

Final full regression run (`python -m pytest -q --basetemp=.pytest-final-delivery
-o addopts=`): **343 passed in 168.89 seconds**. The subsequently added entity
mapping safeguard was checked with the focused Passport safety and transport
logging suite: **10 passed in 5.13 seconds**. Final Ruff: all checks passed.
The diagnostic script parsed successfully using Windows PowerShell
**5.1.26100.9818** (also checked with PowerShell 7.6.9).

Transport logging suppresses HTTPX/HTTPCORE verbose request logs and redacts
device K1/K2 query values from formatted messages and tracebacks. Candidate
resource availability remains false/expired pending operator confirmation.

The isolated outbox/Orion regression requires exact NGSI wire values and a Twin
publication timestamp later than broker delivery before recording EXECUTED. An
immediate broker echo cannot acknowledge execution. These are offline tests, not
evidence of a command applied to a live device or shown in Snap4City.
