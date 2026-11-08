# Service interfaces

## Model inspection and inference

TRAFFIC_MODEL_DIR configures the directory containing traffic_xgboost_15min.json,
traffic_xgboost_30min.json and traffic_xgboost_60min.json.
WATER_MODEL_PATH configures a directory or ZIP containing metadata.json and
lgbm_delta_1h.txt, lgbm_delta_3h.txt, lgbm_delta_6h.txt.
Only native JSON/TXT artifacts are parsed; no pickle, joblib or archive code is loaded or executed.
Each configured model loads once per application lifespan. SHA-256 identifies the artifact,
not a verified training release version. Supplied filenames label intended horizons.

Authenticated routes: GET /v1/models, GET /v1/models/status,
POST /v1/forecasts/traffic, POST /v1/forecasts/water, GET /v1/forecasts/history.
All existing service roles have access. Requests contain sensor_id, horizons_minutes and optional
correlation_id. Traffic horizons: 15/30/60; water horizons: 60/180/360 minutes.
Invalid horizons return 422. History is capped by limit (1–1000).

Water inference implements the supplied CityBrain_Inference_Handoff.md USGS V3 definitions:
hourly UTC medians, normalized stage lags/deltas, full-window sample standard deviation,
centered log1p discharge, and hourly/yearly temporal encodings. LightGBM normalized deltas
are reconstructed into station-specific gage height in feet, never flood probability.
Nine archived reference predictions (three per horizon) match within 1e-8 feet.
Run scripts/verify_water_parity.py with the supplied ZIP path to reproduce the comparison.

Register stage sensors with measurement=water_level, unit=ft, training_source=USGS,
training_id equal to the original station ID, and training_compatible=true only after confirming
the same physical station, parameter 00065 and vertical datum. Optional discharge sensors use
measurement=water_flow, unit=cfs, parameter 00060 and the same validated station mapping.
There is no automatic mapping from arbitrary Twin sensor names.

Requests accept optional origin, an aware UTC timestamp on an hourly grid. The default is the
previous completed hour. The entire origin hour must be complete: an origin 10:00 summarizes
observations in [10:00,11:00), is available at 11:00, and forecasts timestamps origin + horizon.
Future samples are excluded. Required stage bins are origin and 1/2/3/6 hours earlier.
Optional gaps remain NaN internally (null in persisted feature arrays); missing flow is not invented.
History extends at most 168 hours. Every supplied observation in that interval must remain
Guardian-trusted, unexpired and unquarantined; rejected evidence cannot masquerade as missing data.
Set sensor freshness_seconds and EVENT_FRESHNESS_SECONDS explicitly for the approved historical
window, and renew Guardian verdicts as required. Default short freshness does not admit week-old data.

Successful requests persist feature order/values, evidence and verdict IDs, model content hashes,
preprocessing version, station mapping and predictions. Failed or blocked requests persist without
predictions and return 503. History retains original outputs and exposes currently_eligible based
on current evidence and mapping; revisions and revocations invalidate prior forecasts.
Inference and persistence share a serialized transaction to avoid concurrent trust changes.

Traffic inference validates model/metadata/NPZ SHA-256 checksums, feature order, all 207 sensor
identities, neighbor indices and training statistics. NPZ loads with allow_pickle=False.
Each XGBoost prediction uses iteration_range=(0,best_iteration+1), matching the exports.
Run scripts/verify_traffic_parity.py with the configured traffic directory to verify all 72
archived reference predictions. Preprocessing reference tests independently check horizon-specific
yesterday values and target weekly slots; archived references contain features, not raw histories.

Register exactly the original 207 METR-LA sensors with unique training_id mappings,
training_source=METR-LA, training_compatible=true, measurement=traffic and
unit=METR-LA_native_speed. This explicit unit label attests that integration verified native
dataset speed units; it does not assume mph or convert traffic counts to speed.
Every mapping must specify the same training_timezone (IANA name), validated against the
original HDF5 clock. There is no default clock. Windows deployments may need the tzdata package
for non-UTC IANA zones. Histories crossing a DST discontinuity are rejected as ambiguous.

The API requires 289 five-minute timestamps (origin minus 24 hours through origin inclusive)
for all 207 sensors. Origin must be aware, on a five-minute grid, and not in the future;
default origin is the latest five-minute boundary. Missing rows, duplicate timestamps,
incompatible mappings, stale readings and any ineligible evidence block the entire request.
All raw observations are rechecked by the existing Trust Engine in the inference transaction.
Choose historical freshness and Guardian verdict validity explicitly; the short development
defaults do not authorize a 24-hour history. Never increase them merely to admit revoked evidence.

Observed zero speeds become NaN as in training, with no invented fills. Target speed_now must
be observed. Only the documented yesterday-value fallback and exported climatology are used.
Rolling windows include origin; std_12 uses ddof=1 and minimum three valid samples.
Each horizon gets its own yesterday-at-target-minus-288 and target-weekly-climatology features.
Outputs are absolute speed in native units, with per-horizon features, model/preprocessing hashes,
best_iteration and all evidence references persisted. Model status reports ready only after
successful artifact validation. No compatible live sensor grid is created automatically.

Inference serializes database writes for consistency. Full-grid evidence and history are large;
high-volume serving and shorter provenance representations require future performance work.

## City state and fusion

Authenticated GET routes: /v1/city/state, /v1/city/zones, /v1/city/zones/{zone_id},
/v1/city/sensors, /v1/city/sensors/{sensor_id}, /v1/city/history.
All three service roles have read access. Unknown registered identifiers return 404.
History uses after_version (exclusive, default 0) and limit (1–1000).
Snapshots represent knowledge at the time of computation; later revocations do not rewrite history.
Current responses recompute eligibility before returning and persist a new version only on change.

CITY_REGISTRY_FILE points to YAML containing zones (unique string IDs), sensors, window_seconds
and ema_alpha. Each sensor has sensor_id, zone_id, measurement, unit, positive weight and
freshness_seconds. See app/state/registry.py for the supported type/unit combinations.
Registration is configuration-driven and loaded on restart; no public registration endpoint exists.
Unknown sensors remain raw events for backwards compatibility but never contribute to city state.
Known sensors with incompatible type, unit or attributes.zone_id receive 422.

Fusion groups only identical measurement types and units within a zone; no unit conversion occurs.
Each sensor uses trusted observations inside both its rolling window and freshness deadline.
Statistics are population standard deviation, arithmetic mean, chronological EMA and first-to-last
rate per second. Zone fusion is a weighted mean of the latest usable observations, with weights
renormalized over available contributors. Correlation is Pearson correlation on exact timestamp
matches only (at least two pairs and nonzero variance); no interpolation or imputation occurs.
Missing results are null and contributors/evidence IDs are explicit.
An ineligible newest observation suppresses that sensor rather than falling back to older data.
Quarantine, revocation and expired verdicts are evaluated by the existing Trust Engine.

City snapshots store registry metadata, sensor statistics, raw-event/verdict references and zone
aggregates. The latest snapshot is current state; older versions form history without a duplicate
current-state table. Raw observations remain in sensor_events, with eligibility in event_lifecycle.
The worker refreshes state every polling cycle; API reads also refresh it to fail closed.
Large-history scans and unbounded snapshot retention remain scalability limitations.
The isolated scripts/check_city_flow.py check exercises Mock Twin, Mock Guardian, Brain and the
city-state API using generated registry identifiers and temporary credentials.

## Authentication and transport

Every event route requires X-API-Key. BRAIN_API_KEY authenticates Brain to mocks;
TWIN_API_KEY authenticates Twin to Brain; GUARDIAN_API_KEY authenticates Guardian to Brain.
Keys must be distinct and at least 32 characters. Missing configuration fails closed.
Roles come from credentials; role headers are ignored. Health and OpenAPI are public.

HTTP is for loopback development only. TLS/mTLS authenticates transport peers; API keys authorize
service roles. Neither proves sensor trust. Guardian verdicts are stored separately and bound to
reading IDs, correlation IDs and SHA-256 hashes. Rejected and unknown verdicts are valid messages.
Only processed, fresh, trusted readings enter the read-only operational-state view.
No actuator orchestration is implemented.

## Endpoints

| Service | POST path | Role | Request | Success |
|---|---|---|---|---|
| Brain | /readings | twin | SensorReading | 202 receipt |
| Brain | /verdicts | guardian | GuardianVerdict | 202 receipt |
| Brain | /feedback | twin | ActuatorFeedback | 202 receipt |
| Mock Twin | /readings | brain | SensorReading | 200 Brain receipt |
| Mock Twin | /commands | brain | ActuatorCommand | 200 ActuatorFeedback |
| Mock Guardian | /evaluate | brain | SensorReading | 200 GuardianVerdict |
| Mock Guardian | /quarantines | brain | QuarantineNotification | 200 Brain receipt |

Mock Twin relays readings and posts simulated command feedback to Brain.
Mock Guardian evaluates a supplied reading and posts its deterministic verdict to Brain.
Readings and verdicts may arrive in either order. These are mock controls, not production algorithms.
POST /evaluate replaces the previous GET mock verdict route.

Errors: 401 missing/invalid key; 403 wrong role or Guardian identity; 404 unknown status target;
409 duplicate ID or verdict binding mismatch; 413 body too large; 415 non-JSON;
422 malformed/invalid/stale event; 502 partner unavailable; 503 partner configuration missing.
Success means the database transaction committed. Duplicate IDs remain rejected after restart.
IDs are unique per event type; identical content with a new ID is a new event.

## Contracts

Contracts forbid extra fields and primitive coercion. UUIDs, timezone-aware ISO-8601 timestamps
and enums use JSON strings. Only schema_version 1.0.0 is supported. Timestamps normalize to UTC;
nonfinite numbers are rejected, including nested metadata.

Common fields: schema_version, correlation_id (UUID).

| Contract | Required fields beyond common |
|---|---|
| SensorReading | event_id, occurred_at, sensor_id, sensor_type, value (finite number), unit |
| GuardianVerdict | verdict_id, event_id, event_hash (64 lowercase hex), issued_at, status, reason_code, guardian_id |
| ActuatorCommand | command_id, decision_id, issued_at, actuator_id, action, expires_at |
| ActuatorFeedback | feedback_id, command_id, occurred_at, status |

Optional JSON objects: reading attributes and command parameters; feedback detail is optional.
Verdict status: trusted/rejected/unknown/revoked. Feedback status: accepted/executed/failed.
Command expiry must follow issue time; Mock Twin rejects expired commands.
Brain accepts events within REPLAY_WINDOW_SECONDS (default 300), with 30 seconds future tolerance.
MAX_REQUEST_BYTES defaults to 65536 and applies to chunked bodies too.

Hash: SHA-256 of UTF-8 JSON after validation, UTC normalization and default insertion,
sorted keys, comma/colon separators without spaces, Python ensure_ascii=True.
app.security.event_hash.event_hash is canonical. Hashes bind content; they are not signatures.
Receipts contain status=stored, event_id and sha256. Database payloads contain event and sha256.
Feedback is an observation; command existence and orchestration are deferred.

Example reading (replace IDs and timestamp for each request):

```json
{"schema_version":"1.0.0","event_id":"4aacd5b0-e20a-4aa6-9a7a-d592d9f35320","correlation_id":"b7cc824a-736d-4d46-822e-87f5fdde7dfe","occurred_at":"2026-11-06T10:00:00Z","sensor_id":"traffic-001","sensor_type":"traffic_flow","value":12.5,"unit":"vehicles/min"}
```

Send Content-Type: application/json and X-API-Key from the authorized service environment.
Run python scripts/run_sample.py for fresh reading, verdict and command/feedback requests against
all three services. It also checks unauthenticated rejection. Exact schemas and examples are at
each service's /docs and /openapi.json.

## Durable processing and trust

POST responses still acknowledge durable receipt (202), not completed processing.
The worker advances RECEIVED -> VALIDATED -> PENDING_VERDICT ->
TRUSTED / UNTRUSTED / UNCERTAIN / EXPIRED. Revisions and quarantine changes route final states
through PENDING_VERDICT. All transitions and acknowledgments have ordered, structured audit history.

GuardianVerdict has optional revision (nonnegative integer, default 0) and expires_at (aware timestamp).
The authenticated Guardian key must match guardian_id through GUARDIAN_IDENTITY.
The greatest (revision, issued_at) pair wins regardless of arrival order; ambiguous equal pairs
fail closed as UNCERTAIN. Older verdicts remain in history and cannot restore eligibility.
Revocation uses status=revoked and persists until a newer verdict explicitly supersedes it.
An expired latest verdict never falls back to an older trusted one.
Early verdicts are buffered with 202; hashes and correlation IDs are checked once the reading exists.
Known mismatches return 409; buffered mismatches become UNCERTAIN.

Any new verdict immediately invalidates existing eligibility in the same ingestion transaction.
The worker reestablishes eligibility only after verification. Sensor and verdict expiration are
checked independently; reads also enforce eligibility deadlines even if the worker is stopped.
Missing Guardian evidence remains pending until VERDICT_TIMEOUT_SECONDS, then EXPIRED.
Late evidence may recover a missing-verdict event only while its sensor reading remains fresh.
Guardian disconnection never authorizes new evidence; existing evidence lasts only to its deadline.

POST /quarantines (Guardian role) accepts:

```json
{"schema_version":"1.0.0","notification_id":"77a76acb-1860-489c-bd91-31ccbf55a37d","correlation_id":"b7cc824a-736d-4d46-822e-87f5fdde7dfe","guardian_id":"mock-guardian","issued_at":"2026-11-06T10:00:00Z","target_type":"sensor","target_id":"traffic-001","action":"quarantine","revision":1,"reason_code":"guardian_notification"}
```

target_type is sensor or actuator; action is quarantine or release. Quarantine persists without a
timeout until a newer release. Ordering uses (revision, issued_at); ties favor quarantine.
Future-dated notifications are rejected. Sensor quarantine immediately invalidates all affected
evidence. Actuator quarantine is persisted and exposed for future safety checks; it does not trigger
actuator orchestration or duplicate Guardian detection. Feedback remains an observation.

Authenticated read-only routes (any configured service role):

| GET path | Result |
|---|---|
| /events/{event_id} | Lifecycle, trust state, eligibility, processing, attempts, acknowledgment |
| /events/{event_id}/history?limit=100&offset=0 | Immutable verdicts and ordered audit (each paginated) |
| /state/trusted | Latest eligible reading per sensor |
| /quarantines/{sensor-or-actuator}/{target_id} | Current quarantine state |

Older readings cannot replace newer readings in operational state. Invalidating the newest reading
removes that sensor from the view; there is no fallback to older evidence. Equal newest timestamps
are ambiguous and omitted. Lifecycle state is persisted; trust_state reflects expired eligibility or
processing failure at read time. Only eligible=true is usable evidence.

Configuration defaults:

| Variable | Default |
|---|---|
| GUARDIAN_IDENTITY | mock-guardian |
| EVENT_FRESHNESS_SECONDS | 300 |
| VERDICT_TIMEOUT_SECONDS | 60 |
| VERDICT_TTL_SECONDS | 300 |
| WORKER_ENABLED | true |
| WORKER_POLL_SECONDS | 0.25 |
| WORKER_BATCH_SIZE | 100 |
| WORKER_MAX_ATTEMPTS | 3 |
| WORKER_RETRY_SECONDS | 1 |

Processing states are queued, processing, acknowledged, retry and failed. Processing and its
acknowledgment commit atomically, so processing is not normally externally visible.
Unexpected event failures roll back their savepoint, then retry with bounded exponential backoff.
After the attempt limit, failed events stay durably ineligible for inspection; fresh authenticated
evidence requeues them. Database outages leave work unacknowledged and the worker resumes polling.
Restarts resume the stored queue, deadlines and retry counts. History has no automatic retention.

SQLite BEGIN IMMEDIATE and a PostgreSQL transaction advisory lock serialize short state mutations.
This is deliberately a single logical writer across workers. No network call occurs under the lock.
The worker runs synchronous SQLAlchemy work in a thread, outside the asyncio event loop.
PostgreSQL locking is implemented but has not been integration-tested against a live PostgreSQL server.
The JetStream delivery boundary acknowledges only after an injected durable-ingestion callback succeeds;
broker connection, subscriptions and NATS credentials remain deferred. The callback must enforce the
same authentication/validation and treat already-persisted duplicate deliveries as successful receipts.

## Local certificates and TLS proxy

Run python scripts/setup_dev.py once after installing development dependencies.
It creates random credentials in ignored .env, a local CA and three 30-day certificates in ignored
certs/. It refuses to overwrite existing certs or .env. Never commit private keys.
For renewal, archive local artifacts securely, rerun setup, and restart all services together.
On Windows restrict certs and .env ACLs to your user before using them on a shared machine.
POSIX permissions: 0600 for keys/environment; 0700 for the certificate directory.
The CA is development-only and is not installed into the system trust store.

Run docker compose -f docker-compose.secure.yml up --build (a standalone Compose file).
Only proxy ports 8443/8444/8445 are exposed on loopback; backend HTTP stays on the internal network.
Nginx requires a CA-signed client certificate and TLS 1.3. API credentials are also required.
For a host-side sample set:

```powershell
$env:BRAIN_BASE_URL="https://localhost:8443"
$env:TWIN_BASE_URL="https://localhost:8444"
$env:GUARDIAN_BASE_URL="https://localhost:8445"
$env:TLS_CA_FILE="certs/ca.crt"
$env:TLS_CERT_FILE="certs/brain.crt"
$env:TLS_KEY_FILE="certs/brain.key"
python scripts/run_sample.py
```

The secure Compose file supplies each mock its client certificate for calls to Brain.
TLS_CA_FILE, TLS_CERT_FILE and TLS_KEY_FILE configure outbound HTTPS verification.
The proxy trusts the development CA; API keys enforce roles independently of certificate names.
Production requires deployment-managed certificates, secrets and network isolation.

Verification: real loopback TLS 1.3/mTLS socket tests and authenticated live REST exchange.
Nginx/Compose mTLS is configured but not end-to-end verified here because Docker is unavailable.
Before deployment run the sample through the proxy, then confirm requests without a client
certificate, with an untrusted certificate and with TLS 1.2 fail.

# Operational incidents

Authenticated readers (`brain`, `guardian`, `twin`) may use:

- `GET /v1/incidents?limit=100`: latest state of each incident episode.
- `GET /v1/incidents/active`: DETECTED, ACTIVE and ESCALATED episodes.
- `GET /v1/incidents/{incident_id}`: one incident; unknown IDs return 404.
- `GET /v1/incidents/history?incident_id=<UUID>&limit=100`: immutable revisions, newest first.

The legacy `/incidents` list remains available with authentication. Limits range from 1 to 1000.
Responses include incident/correlation IDs, detection/update timestamps, rule version and content,
zone, classification, severity, lifecycle state, confidence basis, sensor counts, event/verdict
references and forecast IDs. Historical revisions preserve the evidence valid at that revision;
they are not assertions of current eligibility. Reads refresh current state before responding.

`INCIDENT_RULES_FILE` selects a YAML/JSON configuration loaded on startup. Rules match an exact
measurement/unit pair and optionally specified zones. `above`/`below` use inclusive thresholds;
`rise`/`fall` use consecutive-observation change magnitudes in units per second. Severity levels
must increase in anomaly magnitude. Missing history is never filled. Consecutive breaches must
satisfy `min_samples`, `persistence_seconds` and `max_gap_seconds`; repeated polling is not a sample.
The effective history is bounded by City State's window, sensor freshness and Guardian deadlines.
Ensure these windows cover the configured persistence and recovery periods.

`min_sensors` and `correlation_seconds` require compatible sensors in the same zone. Confidence
is `provisional`, `rule_confirmed` or `corroborated`, based on these explicit checks, never a probability.
A first breach creates DETECTED; confirmation produces ACTIVE; higher severity produces ESCALATED.
Recovery requires `recovery_samples` and `recovery_seconds` of nonbreaching observations.
RESOLVED records distinguish observed recovery, invalidated evidence, lost confirmation and removed
rules/zones. Withdrawal due to missing evidence does not establish physical recovery. Reopening
creates a new episode after `cooldown_seconds`; unchanged evidence creates no duplicate revisions.

Forecast rules use `source: forecast`, `min_samples: 1`, `persistence_seconds: 0` and absolute
traffic/water thresholds. Only the latest request per sensor is considered; failed, expired,
untrusted or incompatible forecasts cannot support warnings. Rules bound forecast age and horizon.
Outputs are `early_warning` classifications, not confirmed observations, accidents or flood
probabilities. Observation rules continue when models are unavailable.

The default `config/incidents.yaml` has no operational thresholds. Example values in
`config/incidents.simulation.yaml` are simulation-only and rejected in production mode.
Deployments must supply reviewed site-specific thresholds, sensor semantics and an updated version.

# Decisions

`POST /v1/decisions/evaluate` accepts the `brain` service role only. An empty JSON object evaluates
all ACTIVE/ESCALATED eligible incidents as one resource-constrained portfolio. `correlation_id`
is optional. Other authenticated services receive 403; missing/invalid keys receive 401.

`GET /v1/decisions`, `GET /v1/decisions/{decision_id}` and
`GET /v1/decisions/history?decision_id=<UUID>&limit=100` allow authenticated brain/guardian/twin
readers. The legacy `/decisions` list is retained with authentication. List limits are 1–1000.
Unknown decision IDs return 404. Current reads refresh city and incident eligibility first.

Responses include lifecycle status, input fingerprint, city snapshot version, incident/evidence
references, full reviewed policy, objective score, constraints, selected actions, rejected alternatives,
and `approved_actions`. `execution_enabled` is always false in Step 7. `ACTION_PLAN` denotes a plan;
only APPROVED records have approved actions. `NO_ACTION` records explain why no response was authorized.

Safety-critical or approval-required plans remain EVALUATED. Explicit approval uses a separate request:

```json
{"approval":{"decision_id":"<returned UUID>","reason":"<authorization rationale>"}}
```

Approval is attributed to the authenticated `brain` service, not to an independently verified human.
It applies only to that exact evaluated snapshot. Stale approvals return 409. Duplicate evaluations
and repeated approvals reuse the same decision. Noncritical actions may be automatically approved
only when the reviewed policy explicitly sets both `safety_critical` and `requires_approval` false.

Lifecycle: PROPOSED → EVALUATED → APPROVED or REJECTED. Pending/approved decisions become CANCELLED
when incidents, state, policy, trust, quarantine or availability change. New planning requires another
evaluate request. Immutable revisions and audit events retain every transition; historical approvals
are not current authorization. No commands are created or sent.

`DECISION_POLICY_FILE` selects versioned YAML/JSON loaded on startup. Approval requires `approved: true`,
a nonempty `approval_reference` and `approved_incident_config_sha256` matching the normalized incident
configuration hash returned in evaluation inputs. Empty incident rules cannot authorize actions.
These are deployment-managed review attestations, not digital signatures. Simulation incident rules
require simulation policies, and simulation policies cannot authorize production decisions.

Resources and actuators require explicit `available`, `observed_at`, and `valid_until` declarations.
These are administrator-attested availability snapshots, not inferred live capacity; refresh the file
and restart before expiry. Actuators declare zone, action capabilities and inclusive numeric parameter
ranges. Policies declare exact parameters, resource demands, allowed zones, minimum severity, costs,
conflicts and authorization requirements. Missing priorities/capabilities or stale availability fail closed.

The score is severity weight + incident-type urgency weight + zone weight + action benefit − weighted
cost. All weights/capacities are explicit bounded integers. CP-SAT maximizes total score with a stable
candidate-order tie-break, one worker and fixed seed. Constraints enforce resource capacities, maximum
actions, one response per incident, one action per actuator and explicit incompatibilities. Only OPTIMAL
results pass to independent constraint and current-evidence verification. Timeout, infeasibility, invalid
results and missing solver dependencies produce `NO_ACTION`; required actions are never forced.

Forecast-based responses require `allow_forecast_warning: true` and an eligible early-warning incident.
Observation responses work without forecasts. No congestion is promoted to a confirmed accident;
water predictions are not flood probabilities. Demonstration policies are deliberately unapproved,
unavailable and expired until configured for an explicit simulation.

# Actuator execution and Orion NGSI v2

The `brain` role creates commands with `POST /v1/actions/execute` and an approved `decision_id`.
`GET /v1/actions`, `GET /v1/actions/{command_id}` and
`GET /v1/actions/history?command_id=<UUID>&limit=100` allow authenticated service readers.
The `twin` role submits `POST /v1/actions/{command_id}/feedback`; the legacy `/feedback` contract is
retained. Command IDs are deterministic per decision candidate, so repeat execution requests return
the existing command. Unknown decisions return 409; unapproved or invalidated decisions return 403.

Lifecycle states are PENDING, DISPATCHING, DELIVERED and EXECUTED, with REJECTED, FAILED, EXPIRED and
UNKNOWN outcomes. Each transition has an immutable revision and audit event. DELIVERED means the
transport accepted the update. Only matching execution feedback or a matching Orion actuator-state
attribute can mark EXECUTED. Missing feedback becomes UNKNOWN after the configured timeout.

Every dispatch rebuilds city state and rechecks the approved decision fingerprint, Guardian evidence,
policy, resource availability, actuator capability, zone, quarantine and explicit critical-action
approval. Conflicting active commands for an actuator are rejected. Deterministic commands are not
recreated after restart. Interrupted idempotent actions return to PENDING; interrupted non-idempotent
actions become UNKNOWN. Retryable idempotent failures use bounded exponential delays. Uncertain
non-idempotent delivery is never retried automatically. Expired commands are never sent.

External dispatch remains off unless `ACTUATOR_EXECUTION_ENABLED=true`. Orion uses:

- `ORION_BASE_URL` and NGSI v2 `PATCH /v2/entities/{entityId}/attrs`.
- `ORION_ENTITY_PREFIX`, `ORION_COMMAND_ATTRIBUTE`, and `ORION_STATE_ATTRIBUTE` for mapping.
- `ORION_BEARER_TOKEN` or `ORION_API_KEY` plus `ORION_API_KEY_HEADER`, never both.
- Optional `ORION_FIWARE_SERVICE` and `ORION_FIWARE_SERVICE_PATH` headers.
- Standard HTTPS verification through `ORION_TLS_CA_FILE`. A client certificate/key is used only when
  both `ORION_TLS_CERT_FILE` and `ORION_TLS_KEY_FILE` are explicitly configured and supported upstream.

The command attribute is a `StructuredValue` containing the complete versioned ActuatorCommand and a
command-ID metadata value. A valid Orion 204 response records broker delivery only. State reconciliation
expects the configured state attribute to contain `command_id` and `status`. Malformed responses fail
closed. Production execution requires Orion over HTTPS. Credentials, entity IDs and device mappings are
environment/policy configuration; none are hardcoded.

Mock Twin accepts only operations listed in `MOCK_TWIN_ALLOWED_ACTIONS`, rejects duplicate/conflicting
or expired commands, applies parameters to simulated in-memory actuator state, and returns separate
execution feedback. `MOCK_TWIN_FAILURE_MODE=fail_once|always` and `MOCK_TWIN_DELAY_SECONDS` support
recovery tests. Mock state is simulation-only and does not survive Mock Twin process restart.

# Dashboard and scenarios

`GET /dashboard` serves the monitoring console. `POST /dashboard/session` accepts the existing
`X-API-Key` service credential and returns a CSRF token while setting an HttpOnly, SameSite session
cookie. `GET /dashboard/session` restores an active browser session. Dashboard state, timeline, and
SSE routes require that cookie. Scenario control and logout also require `X-Dashboard-CSRF`; only the
`brain` role can control simulations. API keys are not stored in browser storage.

The dashboard reads operational state from the database and existing engines. It does not synthesize
forecasts, verdicts, incidents, decisions, or command outcomes. `/dashboard/events` streams the
persistent audit and scenario timeline as `timeline` SSE events.

Authenticated service APIs are `GET /v1/scenarios`, `POST /v1/scenarios/{scenario_id}/run`,
`POST /v1/scenarios/reset`, and `GET /v1/scenarios/executions/{execution_id}`. Control routes require
the `brain` role. Every run has an isolated simulation database, a unique execution ID, expected and
actual outcomes, and ordered logs persisted in `scenario_executions` and `scenario_logs`.

The browser uses `POST /dashboard/api/scenarios/{scenario_id}/start` to return a RUNNING execution
immediately, then polls `GET /dashboard/api/scenarios/executions/{execution_id}` while SSE continues
to refresh the global audit timeline. `GET /dashboard/api/scenarios` supplies persistent run history.
Stage details are a simulation-only projection copied from the isolated run: readings, verdicts,
trusted state, incident evidence, decision explanation, approval, command, and Mock Twin feedback.

Dynamic dashboard starts use the seeded `TwinTimeSeries` generator in Mock Twin. The simulation emits
one authenticated event per configured simulated sensor and tick, then waits for Guardian verdicts and
the durable event processor before persisting the projection. The control endpoint is
`POST /dashboard/api/scenarios/executions/{execution_id}/control` with `pause`, `resume`, `stop`, or
`speed` and an optional speed of 1, 2, or 5. Only one dynamic worker may run at a time. External Orion
execution stays disabled; confirmed state changes come only from Mock Twin feedback.

Simulation assumptions are demonstration-only: traffic speed is bounded by the selected profile while
count and occupancy are derived attributes; fire temperature rises with smoke; water level is a gauge
series whose rate is computed by City State; power utilization uses a 28 kW simulated capacity; air
quality is a bounded baseline. These values are not operational thresholds or production forecasts.

