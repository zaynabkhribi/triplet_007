# AEGISCITY City Brain — Technical Explanation from the Implemented Source

**Repository inspected:** `triplet_007`  
**Report scope:** City Brain, with Twin and Guardian inspected only at their Brain-facing contracts  
**Investigation date:** 2026-11-14  
**Evidence labels used below:** **[CODE]** direct source/configuration inspection; **[TEST]** automated test evidence; **[LIVE]** observation of the running local services or hosted Orion; **[HISTORICAL]** a recorded earlier result that was not reproduced in the final investigation window.

## Executive summary

City Brain is the decision and control layer of AEGISCITY. It polls explicitly allowlisted NGSI v2 sensor attributes from the shared Orion Context Broker, converts them to strict internal events, persists them, waits for trustworthy evidence, builds a fused City State, detects configured incidents, selects constrained responses with OR-Tools CP-SAT, requires an explicit approval when policy says so, and can place approved actuator commands in a persistent outbox. It also exposes authenticated APIs and a live operations dashboard.

The implementation is deliberately fail-closed. A raw reading is not trusted merely because it came from Orion or because Guardian reports a device-level `TRUSTED` word. Brain either requires a durable observation-level `GuardianVerdict`, or—in the supervised development path—a short-lived Guardian Evidence Passport whose HMAC signature, evidence digest, disposition, observation binding, and expiry all verify. Audit-tail reconciliation proves that Guardian and Brain saw the same observation, but does not itself grant authorization.

The running system is a development integration runtime. **[LIVE]** Brain returned `{"status":"ready"}` on port 8000 and Guardian returned `status=ok` on port 8090. The Brain process had `GUARDIAN_PASSPORT_ENABLED=true`, while `ACTUATOR_EXECUTION_ENABLED=false` and `OPERATIONAL_AUTO_APPROVE=false`. The loaded Zone B incident and response files are candidates; the action policy is explicitly unapproved and its resources and actuators are unavailable. Real sensor ingestion, exact evidence matching, a real non-default-key Passport signature, Passport-backed City State, and accurate dashboard transitions have been observed. No live actuator PATCH and no Snap4City actuator visualization have been verified.

The latest complete test process that finished during this investigation reported **345 passed, 2 failed**; Ruff passed. Both failures are in `tests/integration/test_passport_safety_regression.py`, in the dashboard-expiration assertion for the `rejected` and `unknown` parameter cases. Therefore the later dashboard/Passport regression cannot currently be called fully fixed, even though focused runs and earlier full runs passed.

## 1. What City Brain is

City Brain is the component that turns observations into controlled decisions. Its boundary is visible in `app/main.py`: one FastAPI application assembles the database, event processor, City State engine, model registry, incident detector, decision engine, actuator manager, external integration workers, dashboard, and scenario runner.

Brain receives:

- `SensorReading` events from the Twin role (`app/schemas/sensor.py`, `POST /readings`). In the real integration, its own NGSI worker first reads the Twin-published entity from Orion and posts the normalized event back through this authenticated API.
- Observation-level `GuardianVerdict` and `QuarantineNotification` messages from the Guardian role (`app/schemas/guardian.py`, `/verdicts`, `/quarantines`) when the full durable verdict contract is available.
- Guardian audit evidence and short-lived Evidence Passports through compatibility adapters (`app/integration/guardian_compat.py`, `guardian_passport.py`).
- Forecast requests, decision-evaluation requests, explicit approval data, execution requests, and actuator feedback through authenticated APIs.

It performs:

1. schema, timestamp, role, duplicate, and canonical-hash checks;
2. durable buffering and asynchronous lifecycle processing;
3. trust evaluation and quarantine checks;
4. City State fusion over registered, recent, uniquely-timestamped, eligible readings;
5. model inference when valid artifacts and complete trusted histories are configured;
6. rule-based incident lifecycle evaluation;
7. policy filtering and CP-SAT response optimization;
8. independent revalidation, approval, outbox delivery, retry, recovery, and feedback/readback reconciliation.

It produces current and historical City State, incidents, forecasts, evaluated/approved/rejected decisions, actuator command records, audit records, and dashboard snapshots. These are persisted through SQLAlchemy models in `app/database/models.py`.

Brain is not the Twin and is not Guardian:

- The **Digital Twin** owns simulated city devices and publishes their NGSI state to Orion. Brain does not simulate the real Zone B sensor publisher.
- **Guardian** assesses observation trust and issues evidence/verdict material. Brain does not reimplement Guardian’s anomaly scoring.
- **City Brain** consumes observations plus trust evidence and decides whether the evidence is eligible to influence state, incidents, decisions, and commands.

## 2. Architecture and execution model

### 2.1 FastAPI application and endpoints

`app/main.py::create_app()` builds the service. Startup initializes the database and registry, recovers scenario and command state, loads model artifacts, and starts only the workers enabled by configuration. Shutdown cancels and awaits those workers.

Important endpoint groups are:

| Method and route | Purpose | Required role |
|---|---|---|
| `GET /health/live`, `GET /health/ready` | process and dependency health | public |
| `POST /readings`, `POST /readings/batch` | submit strict sensor events | Twin |
| `POST /verdicts`, `/verdicts/batch` | submit durable observation verdicts | Guardian |
| `POST /quarantines` | quarantine or release sensor/actuator | Guardian |
| `GET /events/{event_id}`, `/history` | event lifecycle and revisions | Brain/Guardian/Twin readers |
| `GET /state/trusted` | trusted-state compatibility view | readers |
| `GET /v1/city/state`, `/zones`, `/sensors`, `/history` | current fused City State and versions | readers |
| `GET /v1/incidents`, `/active`, `/history`, `/{id}` | incident views | readers |
| `POST /v1/decisions/evaluate` | evaluate or explicitly approve current decision | Brain |
| `GET /v1/decisions...` | decision/history views | readers |
| `POST /v1/actions/execute` | enqueue approved decision actions | Brain |
| `GET /v1/actions...` | command/history views | readers |
| `POST /v1/actions/{id}/feedback`, `POST /feedback` | execution feedback | Twin |
| `GET /v1/models/status` | artifact readiness | readers |
| `POST /v1/forecasts/{traffic|water}` | trusted model inference | readers |
| `GET /v1/forecasts/history` | persisted forecast results and current eligibility | readers |
| `/dashboard...` | session-authenticated operations UI and APIs | dashboard session derived from a service role |

The schemas use Pydantic v2 with `extra="forbid"`, strict values, finite numbers, timezone-aware timestamps, UUID parsing, bounded strings/lists, and semantic validators (`app/schemas/base.py` and sibling schema files).

### 2.2 Synchronous requests versus background work

- API handlers validate and persist input synchronously inside a serialized database transaction, then normally return `202` or a current query result.
- `EventProcessor.run()` is an asynchronous polling loop. It claims queued sensor lifecycles in bounded batches, re-evaluates trust, rebuilds state, updates incidents, invalidates stale decisions, and writes audit state.
- `NgsiTwinIngestWorker` polls Orion at `snap4city_poll_seconds` and posts readings to Brain.
- `AuditTailShadowWorker` or `GuardianShadowWorker` periodically reconciles external Guardian evidence for observability only.
- Passport observation mode runs an asynchronous refresh loop. It collects recent candidates, requests and verifies Passports, atomically replaces an in-memory eligibility snapshot, and then rebuilds City State.
- `ActuatorManager.run()` exists only when `actuator_execution_enabled` is true. It claims due outbox records, delivers, retries when permitted, and reconciles feedback/readback.
- `OperationalCoordinator` exists only for explicit demo automation; production settings forbid this mode. The current runtime has it disabled.

### 2.3 Persistence

`app/database/session.py` creates a SQLAlchemy engine. The real runtime uses SQLite at `real_integration.db`; PostgreSQL is also supported by the dependency and URL mechanism. SQLite uses `StaticPool` and a process-level lock to serialize transactions. ORM expressions and bound parameters are used rather than string-concatenated SQL for application data.

Major persisted models in `app/database/models.py`:

- `sensor_events`, `guardian_verdicts`, `event_lifecycle`;
- `city_states` and versioned `city_snapshots`;
- `incidents` plus `incident_revisions`;
- `decisions` plus `decision_revisions`;
- `actuator_commands`, `actuator_feedback`, `command_revisions`;
- `quarantine_notifications`, `forecasts`, `audit_events`;
- `city_registry`, `scenario_executions`, and `scenario_logs`.

The common event records carry a UUID primary key, correlation UUID, timezone-aware occurrence time, and JSON payload. Correlation IDs link records belonging to one flow; deterministic event IDs make Orion polling idempotent.

### 2.4 City State engine

`app/state/engine.py::CityEngine` combines the registry, Trust Engine, incident detector, decision engine, and optional Passport eligibility index.

For each configured sensor it:

1. selects recent sensor events inside the registry and per-sensor freshness windows;
2. rejects timestamps duplicated for the same sensor, schema/unit/zone mismatches, missing lifecycle rows, stale values, and quarantined sensors;
3. asks `TrustEngine.evaluate()` for durable trust and optionally accepts a currently valid Passport only when the durable result is merely `awaiting_guardian` or `verdict_missing`;
4. fuses eligible values, calculates statistics, records evidence references and trust source, and labels the sensor `available`, `stale`, `missing`, or `quarantined`;
5. aggregates registered sensor measurements into zones;
6. updates incidents and persists a new City Snapshot only when state changes.

Unknown sensors may remain as raw stored events, but cannot contribute to registered City State.

### 2.5 Dashboard

The dashboard backend is `app/dashboard/api.py`; the UI is `app/dashboard/static/index.html`, `app.js`, and `app.css`. Login exchanges an existing service API key for an in-memory, hashed-token session cookie plus CSRF token. The cookie is HttpOnly, SameSite Strict, scoped to `/`, and marked Secure when served over HTTPS.

The current frontend distinguishes raw observations from eligible fused values, displays Twin/Guardian/Brain status, disables mock controls when no mock Twin control URL exists, labels the trust mode as time-limited Guardian Passports, reports execution and automatic-approval flags, and expires visible authorization at the supplied deadline. Its live charts accept only currently eligible events.

## 3. Brain communication with the Digital Twin

### 3.1 Network path

The real path is not a direct Brain-to-Twin sensor call:

```text
Twin publisher --PATCH sensor attributes--> hosted Orion Context Broker
Brain NGSI poller --GET entity-----------> hosted Orion Context Broker
Brain poller --POST normalized event-----> Brain /readings
```

Twin’s own `INTERFACE-DETAILS.md` says all layers share Orion and “nobody calls the Twin directly.” Brain’s `app/integration/ngsi_twin.py` implements the read side.

### 3.2 Exact read request and normalization

For the Zone B building Brain uses:

```http
GET /v2/entities/us-b-bldg-01
    ?type=BuildingSensor
    &elementid=us-b-bldg-01
```

A sanitized Orion response consistent with the implementation is:

```json
{
  "id": "us-b-bldg-01",
  "type": "BuildingSensor",
  "smokeLevel": {"type": "float", "value": 2.4},
  "temperature": {"type": "float", "value": 21.8},
  "timestamp": {"type": "string", "value": "2026-11-14T03:25:47+00:00"}
}
```

`config/devices.real-readonly.yaml` maps:

| Orion identity | Brain identity | Guardian identity |
|---|---|---|
| `us-b-bldg-01.smokeLevel` | `us-b-bldg-01:fire_smoke`, measurement `smoke`, unit `ppm`, zone `B` | property `fire_smoke`, unit `ppm`, zone `ZONE-B` |
| `us-b-bldg-01.temperature` | `us-b-bldg-01:temperature`, measurement `temperature`, unit `degC`, zone `B` | property `temperature`, unit `C`, zone `ZONE-B` |

The adapter flattens `{type,value}`, validates entity type, rejects booleans/non-numeric/NaN/infinite values, requires an aware and fresh entity timestamp, and constructs:

```json
{
  "schema_version": "1.0.0",
  "event_id": "<deterministic UUID5>",
  "correlation_id": "<deterministic UUID5>",
  "occurred_at": "2026-11-14T03:25:47+00:00",
  "sensor_id": "us-b-bldg-01:fire_smoke",
  "sensor_type": "smoke",
  "value": 2.4,
  "unit": "ppm",
  "attributes": {
    "zone_id": "B",
    "source": "snap4city",
    "entity_id": "us-b-bldg-01",
    "attribute": "smokeLevel",
    "entity_timestamp": "2026-11-14T03:25:47+00:00"
  }
}
```

UUID5 identity includes entity, attribute, and timestamp, so smoke and temperature in the same entity tick remain separate. An unchanged timestamp/value is skipped. Reuse of the same identity with a different value is a contract error. A Brain `409` is accepted as an idempotent replay only when the stored canonical SHA-256 equals the submitted event hash.

Missing mapped attributes are skipped; malformed values and stale/missing timestamps are rejected; network failure raises `PollError`; there is no mock fallback. Valid readings enter the same authenticated `/readings` pipeline as any Twin event and are stored in `sensor_events` with an `event_lifecycle` row.

### 3.3 Approved actuator command path

The implemented real write path is:

```text
approved Decision -> persistent command outbox -> OrionAdapter PATCH
                  -> hosted Orion actuator entity -> Twin polls entity
                  -> Twin validates/applies/publishes later state
                  -> Brain GET entity -> timestamp/value readback
```

For the alarm, `OrionAdapter.deliver()` creates:

```http
PATCH /v2/entities/us-b-alarm-01/attrs
    ?elementid=us-b-alarm-01
    &type=FireAlarm
    &k1=<device-specific secret>
    &k2=<device-specific secret>
Content-Type: application/json

{"alarmState":{"type":"string","value":"on"}}
```

For dispatch the candidate payload is consistent with:

```json
{
  "status": {"type": "string", "value": "dispatched"},
  "unitsDispatched": {"type": "float", "value": 2.0}
}
```

The adapter derives the NGSI type from the actuator allowlist, URL-encodes the identifier, loads only that device’s K1/K2 from the configured git-ignored JSON file, and uses plain NGSI attributes. A `204` proves broker acceptance only. Brain subsequently performs:

```http
GET /v2/entities/us-b-alarm-01?elementid=us-b-alarm-01&type=FireAlarm
```

It records `EXECUTED` only when the expected values match and the entity timestamp is later than delivery. An immediate broker echo cannot satisfy that rule. Otherwise it remains delivered until feedback timeout, then becomes `UNKNOWN`.

**Implemented/tested:** payload, K1/K2 query parameters with synthetic credentials, retry/error mapping, exact readback, post-delivery timestamp, and idempotent single-PATCH behavior are covered in `tests/integration/test_actions.py`.  
**Not live-verified:** no authorized real PATCH/readback/Snap4City indicator has been completed. In the current Passport mode, `ActuatorManager.enqueue()` raises `guardian_passport_execution_contract_incomplete`, and `tick()` also refuses Orion dispatch.

## 4. Brain communication with Guardian

### 4.1 How Guardian sees the observation

Guardian independently polls the same hosted Orion entities. Its assessment produces observation evidence and also a device-level summary. The device-level word is not an observation authorization: one device contains several attributes and its summary can be an aggregation of property states.

### 4.2 Three distinct trust layers

1. **Audit reconciliation** (`AuditTailVerifier`): Brain reads `/v1/verdict?since=<seq>`, reconstructs Guardian’s canonical evidence digest, and finds the exact persisted Brain observation. This proves identity consistency but is explicitly verification-only.
2. **Authenticated durable `GuardianVerdict`**: a Guardian-role API message binds verdict ID, Brain event ID/hash, correlation ID, issuer, revision, status, issue/expiry time. This can set durable lifecycle eligibility when all checks pass.
3. **Evidence Passport**: in supervised development, Brain requests a signed, short-lived Passport for an exact evidence digest and holds eligibility only in memory.

### 4.3 Exact audit matching

`app/integration/guardian_compat.py` validates accepted audit rows against an explicit sensor/property mapping. For a smoke reading it reconstructs Guardian’s canonical body from:

```json
{
  "sensor_id": "us-b-bldg-01",
  "zone": "ZONE-B",
  "observed_property": "fire_smoke",
  "timestamp": "<verbatim Orion timestamp>",
  "value": 2.4,
  "unit": "ppm"
}
```

Canonical JSON uses sorted keys and compact separators; SHA-256 yields `evidence_digest`. The digest must equal Guardian’s row. Brain then matches its stored event by mapped sensor, value, timestamp, and canonical Brain event hash. `B` is Brain’s registry zone while `ZONE-B` is Guardian’s contract zone; guessing one from the other would change the digest and is forbidden, which is why both are explicit in the mapping file.

The durable cursor only advances over accounted rows. Mapped audit events without a Brain observation remain in a bounded pending JSONL store and are retried. Malformed/unmapped/gapped/reset sequences fail visibly. Audit rows do not create `GuardianVerdict` objects and produce zero durable trust grants.

### 4.4 Evidence Passport request and verification

After an exact digest is known, Brain requests:

```http
POST http://127.0.0.1:8090/v1/passport
Content-Type: application/json
[optional X-Integration-Token according to configuration]

{"evidence_digest":"<64 lowercase hexadecimal characters>"}
```

A sanitized Passport is:

```json
{
  "passport_id": "psp-xxxxxxxx",
  "issued_at": "2026-11-14T03:25:52.000000Z",
  "ttl_s": 6,
  "zone": "ZONE-B",
  "disposition": "TRUSTED",
  "trust": 0.91,
  "reason_codes": ["OK"],
  "evidence_digest": "<exact digest>",
  "source_ids": ["<sanitized source id>"],
  "policy_version": "v1.0",
  "allowed_actions": [],
  "conditions": [],
  "signature": "hmac-sha256:<not shown>"
}
```

Guardian signs canonical Passport JSON excluding `signature` with HMAC-SHA256 (`guardian/src/guardian/passport.py`). Brain mirrors the canonical algorithm in `app/integration/guardian_passport.py` and verifies with `hmac.compare_digest`, which avoids ordinary early-exit string comparison. Brain rejects a missing, blank, or documented development-default key.

Brain also enforces:

- exact entity/attribute/sensor type/unit mapping;
- recomputed evidence digest from the persisted observation;
- `TRUSTED` disposition only;
- positive bounded TTL and the half-open validity interval `[issued_at, issued_at + ttl)`;
- original entity timestamp age capped by `GUARDIAN_PASSPORT_MAX_EVIDENCE_AGE_SECONDS`;
- ordinary event freshness and no future timestamps;
- Brain quarantine and durable rejection/revocation precedence;
- atomic, short-lived in-memory eligibility snapshots cleared on failed refresh.

When Guardian is unavailable, returns non-200, has evicted the digest (`404`), returns malformed JSON, an invalid signature/digest/disposition, or expired evidence, authorization fails closed. No previous failed refresh is silently retained.

### 4.5 Secure key provisioning

`scripts/secure_runtime.py` generates 32 random bytes, Base64-encodes them, injects the same value into Guardian’s configured HMAC environment variable and Brain’s `GUARDIAN_PASSPORT_HMAC_KEY`, and stores the key plus captured service profiles in `%LOCALAPPDATA%\AEGISCITY\runtime\profiles.dpapi` encrypted with Windows current-user DPAPI. It removes inherited ACLs and grants only the current account, writes atomically, refuses implicit reprovisioning, does not place the key on argv, and prints no key value.

Before observation mode, the helper requires a recent real verification containing signature `VALID`, exact digest match, `TRUSTED`, and `DEFAULT_KEY_NOT_MATCHED`. It pins execution and automatic approval false.

### 4.6 Limitations of the Passport contract

Guardian mints a Passport from its in-memory cached verdict. The Passport signs issuance time and TTL, but does not sign a new original assessment time, current revision/revocation state, or a current Guardian quarantine assertion. Reissuing a Passport can extend short-lived eligibility for an older cached assessment, subject to Brain’s original-observation age cap. Brain’s own durable rejection/revocation/quarantine checks still take precedence, but Brain cannot query a complete current Guardian revocation contract on every request.

For that reason, native Passports support supervised City State and decision inspection but do not open real Orion execution. This limitation is enforced in code, not merely documented.

## 5. Security controls implemented in Brain

| Threat | Brain control and location | Evidence | Limitation/current status |
|---|---|---|---|
| Unauthorized API caller | `X-API-Key` matched with `secrets.compare_digest`; role dependencies in `authentication.py` and `authorization.py` | `tests/security/test_api_rejections.py`, contract/integration tests | Shared service keys, not per-human identity. Current dashboard inherits one service role. |
| Role escalation | Each mutation endpoint declares allowed role; caller-supplied role headers are ignored | wrong-role tests | Role is determined by key ownership. |
| Dashboard session theft/CSRF | random token stored only as SHA-256 digest, HttpOnly/SameSite cookie, expiry, random CSRF token and constant-time check | dashboard integration tests | In-memory sessions disappear on restart; Secure cookie depends on HTTPS deployment. |
| Weak/default service secrets | settings require distinct keys of at least 32 characters when present; production requires all three | `app/core/config.py`, config tests | Development remains a development deployment. |
| Oversized or wrong-content request | middleware requires JSON for mutating methods and buffers up to configurable 64 KiB default | chunked body test | Not a full rate limiter. |
| Malformed event/data coercion | strict Pydantic schemas, forbidden extras, bounded fields, aware timestamps, finite numbers | unit/schema/security tests | Business semantics still depend on registry/policy mapping. |
| Replay/duplicate events | UUID primary key, canonical event SHA-256, deterministic Orion UUID5, lifecycle idempotency, revision checks | ingestion, trust-edge, NGSI tests | `InMemoryReplayProtector` alone is capacity-bounded; database identity is the durable control. |
| Event substitution | Guardian durable verdict includes `event_id`, `correlation_id`, and SHA-256; Passport digest is recomputed from persisted data | trust pipeline, Guardian audit and Passport tests | Audit reconciliation alone is not authentication. |
| Signature forgery/tampering | HMAC-SHA256 canonical Passport signature and constant-time comparison | Passport tests and real verification | Symmetric key; Guardian source names Ed25519 as a future production target. Passport mode is forbidden by Brain in `production`. |
| Stale/future/replayed trust | timestamp window, verdict issue/expiry, Passport TTL, observation-age cap, short snapshot, refresh before sensitive use | trust-edge and Passport pipeline tests | Latest full suite has two dashboard-expiry test failures; see verification section. |
| Default public HMAC key | Brain refuses documented default; DPAPI provisioning supplies random shared key | diagnostic and secure-runtime code; real Passport previously validated | DPAPI is tied to this Windows user/machine and is operational tooling, not a network HSM. |
| Guardian outage | all trust adapters fail closed; Passport snapshot cleared | mocked network failure tests | Availability is sacrificed for safety. |
| Guardian rejection/revocation | durable status/revision and expiry checks; native Passport can supplement only missing verdicts | trust pipeline and Passport safety tests | Current regression failures concern dashboard metrics after clock manipulation, not the durable Trust Engine’s basic rejection logic. |
| Quarantined sensor/actuator | ordered Guardian quarantine/release records; City State excludes sensor; policy and execution exclude actuator | `test_trust_pipeline.py`, decision tests | Native Passport lacks a signed Guardian-current quarantine claim; Brain uses its own records. |
| SQL injection | SQLAlchemy ORM/expressions and bound parameters; no user input interpolated into application SQL | database/integration tests | PostgreSQL TLS is not configured or proven in the current runtime. SQLite is local-file storage. |
| Transport interception | client helper enforces TLS 1.3 and optional client cert; nginx sample requires client certificates; Orion adapter verifies HTTPS and optional CA/client cert | `tests/security/test_tls.py`, `config/nginx.conf` | Current Brain/Guardian are loopback HTTP; current TLS/mTLS paths are tested/configurable, not deployed live. Hosted Orion uses HTTPS but no custom CA/client certificate is configured. |
| Unsafe model artifact loading | XGBoost JSON, LightGBM text, JSON metadata, checksum verification, NPZ `allow_pickle=False`, ZIP member size bound | artifact/inference tests | Artifacts are absent from current runtime, so no live inference. |
| Unapproved/altered policy | `approved`, nonblank reference, incident-rule SHA-256, simulation/production compatibility, current availability | decision/config tests | Current Zone B candidate remains unapproved/unavailable. |
| Optimizer error | deterministic single-worker CP-SAT, timeout, accepts only `OPTIMAL`, independent `verify()` for selection/resources/conflicts | decision tests | Optimization quality depends on approved policy data. |
| Unsafe/stale decision | decision fingerprint over current incidents/policy/quarantine/availability; invalidation; safety recheck before approval and enqueue | decision/action tests | Human approval is represented by authenticated Brain role plus reason, not a named end-user account. |
| Automatic execution | explicit approval for marked actions; auto-approval disabled; separate execution flag default false | settings and execution-flag tests | Demo files can automate isolated scenarios, but production rejects demo automation. |
| Duplicate/conflicting commands | deterministic command UUID5, one active command per actuator, state machine | action tests | Non-idempotent uncertain delivery ends `UNKNOWN`, intentionally not retried blindly. |
| Delivery loss/restart | persistent outbox, bounded attempts, exponential retry for safe idempotent actions, restart recovery | action/recovery tests | Real external execution remains unverified. |
| False execution acknowledgement | broker `204` means `DELIVERED`; only post-delivery exact state/timestamp or valid feedback yields `EXECUTED` | Orion readback regression | Requires Twin to publish a later timestamp. |
| Credential leakage in logs | K1/K2 URL redactor, HTTPX/HTTPCORE verbose logs suppressed, arbitrary secure-runtime errors withheld | `tests/security/test_transport_logging.py` | Other future transports must preserve this discipline. |

## 6. AI models and predictive intelligence

### 6.1 Traffic

Brain expects three native XGBoost JSON Boosters: 15, 30, and 60 minute horizons. Artifact loading validates file SHA-256 values against metadata, METR-LA dataset identity, exact 24-feature order, 207 unique sensor IDs, two neighbors per sensor, preprocessing array shapes/finiteness, five-minute sampling, best iteration, and preprocessing digest.

Inference requires exactly 289 five-minute rows for all 207 mapped METR-LA sensors, ending at an aware five-minute origin. Every observation must still be eligible. Features include current and lagged speed, rolling statistics, missing count, network speed, neighbor speeds, sensor training statistics, hour/day cycles, yesterday-at-horizon, and weekly climatology. Each model predicts absolute speed in `METR-LA_native_speed`, using only boosting rounds through `best_iteration`.

### 6.2 Water

Brain expects LightGBM text models for 1, 3, and 6 hours plus metadata, from a directory or bounded ZIP. It validates stage unit `ft`, hourly frequency, horizon declarations, and exact feature order. The output is station gage height in feet, reconstructed as current stage plus a model-predicted normalized delta; it is not a flood probability.

Features include normalized stage, stage lags/deltas through 168 hours, rolling means/sample standard deviations, optional centered `log1p` discharge lags, flow-known flag, and hour/year cyclic encodings. Station mapping must explicitly identify the USGS training site and compatible physical measurement.

### 6.3 Trust and operational connection

`app/intelligence/inference.py` and `traffic_inference.py` re-read every evidence event inside the inference transaction, check registry/training mappings and freshness, and require durable trust or a currently valid Passport snapshot. Missing required history, duplicate timestamps, incompatible mappings, stale/revoked/quarantined evidence, absent artifacts, or invalid horizons block inference and persist a blocked/failed forecast record. Forecasts can supply early-warning signals only when incident rules explicitly use forecast sources; historical forecast eligibility is recalculated.

**Current runtime:** `TRAFFIC_MODEL_DIR` and `WATER_MODEL_PATH` are unset. Direct artifact-status inspection returned six `FileNotFoundError` slots. Therefore algorithms and isolated inference tests exist, but no live operational forecast is available now.

**Recorded parity evidence:** `INTERFACE.md` states nine archived water reference predictions matched within `1e-8` feet and 72 traffic archived predictions are supported by the parity script. These are project records and reproducible scripts, not results rerun during this read-only investigation. No accuracy metric such as RMSE/MAE is invented here.

## 7. Incidents, optimization, approval, and execution

The concepts are different:

- A **forecast** is a model-produced future numeric value with model and evidence provenance.
- An **incident** is a rule/lifecycle conclusion based on current trusted measurements or eligible forecasts.
- An **optimization result** is a constrained selection among policy-defined response candidates.
- A **human-authorized action** is an approved decision whose fingerprint and safety conditions still match when command creation/execution is requested.

The implemented flow is:

1. Trusted observations enter City State.
2. `IncidentDetector` applies validated rules: measurement/unit/direction thresholds, zone scope, window, persistence, sample/sensor count, gaps, correlation, escalation, and recovery.
3. Incident records and revisions contain severity, rule, signals, evidence and lifecycle status.
4. `policy_engine.candidates()` excludes mismatched incident type/zone/severity, unavailable/expired resources or actuators, quarantined actuators, unsupported parameters, conflicts, and other policy violations; it calculates deterministic candidate scores.
5. `optimizer.optimize()` creates one Boolean variable per candidate, constrains action count, resource capacity, conflicts, and actuator/incident compatibility, then maximizes weighted score with deterministic tie-breaking. Only a proven `OPTIMAL` result is accepted.
6. `safety_shield.eligible_incident()` independently rechecks active/escalated status, current evidence, forecast continuity, observation windows, registry mapping, trust, and Passport snapshot.
7. `DecisionEngine.context()` blocks absent/unapproved policy, rule-hash mismatch, unsafe simulation policy, and stale availability. The context is hashed into a fingerprint.
8. `POST /v1/decisions/evaluate` first creates an evaluated result. Approval is a second request containing the exact current decision ID and a nonblank reason. It rechecks the fingerprint and safety before transitioning to `APPROVED`.
9. `POST /v1/actions/execute` calls `ActuatorManager.enqueue()`, which again requires the approved decision and current safety verification.
10. The outbox delivers only if execution is enabled, and records every state transition and feedback/readback.

### Zone B smoke example

The candidate rule in `config/incidents.real-zoneb.candidate.yaml` requires at least two samples, one sensor, ten seconds persistence, and smoke above thresholds 10/30/100/200 ppm for low/medium/high/critical severity. Normal values around 2 ppm do not trigger it.

At medium severity the policy can propose `us-b-alarm-01 alarmState=on`. At high severity it can also propose `us-b-disp-01 status=dispatched, unitsDispatched=2`, subject to capacity two. Both require approval.

This is not currently executable: the policy has `approved: false`, empty approval hash/reference, unavailable expired resources/actuators, execution is false, and Passport mode blocks Orion execution. The earlier live calm readings therefore correctly produced no incident and no action.

## 8. End-to-end JSON and sequence reference

```mermaid
sequenceDiagram
    participant T as Digital Twin
    participant O as Hosted Orion NGSI v2
    participant G as Guardian
    participant B as City Brain
    participant H as Human operator
    participant A as Actuator entity/Twin

    T->>O: PATCH sensor /attrs (K1/K2)
    par Independent observation
      G->>O: GET sensor entity
      B->>O: GET sensor entity
    end
    B->>B: normalize, hash, persist SensorEvent
    G->>G: assess and retain evidence digest
    B->>G: GET audit tail (verification-only)
    B->>G: POST /v1/passport {evidence_digest}
    G-->>B: signed short-lived Passport
    B->>B: verify signature/digest/freshness; build City State
    B->>B: incident rules -> CP-SAT -> Safety Shield
    H->>B: explicit approval with decision_id + reason
    B->>B: enqueue persistent command (only if all execution gates pass)
    B->>O: PATCH actuator /attrs (device K1/K2)
    A->>O: later Twin-published actuator state
    B->>O: GET actuator entity
    B->>B: exact post-delivery readback -> EXECUTED
```

The diagram shows implemented calls, but the final actuator section has not been completed live.

## 9. Verification status as of this report

| Capability | Implemented | Unit/integration tested | Verified live | Remaining issue |
|---|---:|---:|---:|---|
| FastAPI, auth, roles, strict schemas | Yes | Yes | Brain ready | Development HTTP runtime; no deployed mTLS |
| Orion Zone B polling/normalization | Yes | Yes | Yes, historical and recent observations | Publisher was stale in the final observation window |
| SQLite persistence/lifecycle | Yes | Yes | Yes | Local SQLite, not a live PostgreSQL/TLS deployment |
| Audit-tail exact evidence matching | Yes | Yes | Yes | Verification-only; pending rows can remain |
| Durable per-observation verdict contract | Yes | Yes | No complete live feed verified | Audit endpoint is not this authenticated contract |
| Non-default HMAC Passport | Yes | Yes | Yes: real signature/digest/default-key rejection recorded | Development-only; cached-assessment/revocation limits |
| Passport-backed City State | Yes | Focused tests mostly pass | Yes: dashboard previously showed 2/2 eligible; final stale state expired to 0/2 | Latest full suite has two expiration-metric failures |
| Dashboard backend/frontend | Yes | Yes, with current failures noted | Yes: eligible and stale transitions visually observed | Current source publisher must be fresh to show eligibility |
| Incident detection | Yes | Yes | No real Zone B incident | Candidate rule activation exists, but live smoke remained calm/stale |
| CP-SAT decisions/Safety Shield | Yes | Yes | Real evaluation rejected due unapproved policy; no live optimal action | Zone B policy unapproved/unavailable |
| Explicit approval | Yes | Yes | Not completed for a real live Zone B decision | Requires valid current decision and approved policy |
| Orion actuator adapter/K1/K2 | Yes | Yes with synthetic credentials | No real PATCH | Isolation/authorization and execution gates unresolved |
| Twin state readback | Yes | Yes | No | Requires authorized PATCH and later Twin publication |
| Snap4City visible actuator result | Outside Brain code, contract known | No end-to-end live proof | No | No dashboard account/operator verification |
| Traffic XGBoost serving | Yes | Isolated tests/parity tooling | No current artifacts | All three runtime slots are `FileNotFoundError` |
| Water LightGBM serving | Yes | Isolated tests/parity tooling | No current artifacts | All three runtime slots are `FileNotFoundError` |
| TLS 1.3/mTLS support | Yes | Handshake tests | No for local Brain/Guardian | Current services use loopback HTTP |

### Current runtime evidence

- Brain listener PID 23116, command `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`; `/health/ready` returned 200/ready.
- Guardian listener PID 47980, command `python -m guardian`; `/healthz` returned 200/ok.
- Brain process flags: Passport true, actuator execution false, auto-approval false, Zone B candidate incident/policy files selected.
- At the final dashboard observation, Orion/Twin publication was stale and the authoritative UI showed 0/2 eligible, preserving raw last values but removing trusted values. Earlier in the same repair session, while publishing was fresh, the UI was visually observed at 2/2 eligible with changing trusted smoke/temperature and 100% currently eligible. The transition demonstrates expiry rather than durable trust fabrication.

### Current automated checks

Latest complete command result observed during this investigation:

```text
345 passed, 2 failed in 276.99s
Ruff: All checks passed
```

Failures:

- `test_city_accepts_native_passport_but_never_overrides_durable_denial[rejected]`
- `test_city_accepts_native_passport_but_never_overrides_durable_denial[unknown]`

Both expected the dashboard trusted-reading metric to become zero after a mocked clock advance, but it remained one. A separately parameterized `revoked` case passed. This is current evidence that the expiration/dashboard trust-metric regression is not fully closed. It does not justify claiming unsafe actuation: execution remained disabled and Passport mode independently blocks Orion dispatch.

## 10. Jury explanations

### A. Two-minute beginner explanation

City Brain is the part of AEGISCITY that turns city data into controlled actions. The Digital Twin publishes sensor and actuator state to an Orion Context Broker. Brain reads only the sensor channels that are explicitly mapped, such as smoke and temperature from the Zone B building, converts them into strict events, and stores them.

Brain does not immediately trust those readings. Guardian independently checks the observation. Brain then verifies that Guardian assessed the exact same value and timestamp. In the live development integration, Brain can also request a short-lived signed Evidence Passport. It checks the Passport’s HMAC signature, exact evidence digest, trusted disposition, observation age, and expiry. If any check fails, the reading stays out of trusted City State.

Eligible readings are fused into City State. Configured rules can detect an incident, such as persistent high smoke. Brain generates possible responses and OR-Tools chooses the best combination under actuator, resource, zone, conflict, and capacity constraints. A separate Safety Shield rechecks the evidence and policy. Safety-critical actions require a second, explicit approval request. Only then can the outbox send an authenticated NGSI command, and a successful HTTP response is not enough: Brain waits for a later Twin-published actuator state before recording execution.

Today, real sensor ingestion and Passport-backed trusted state have been demonstrated. Real actuation has not: execution is disabled, the Zone B response policy is unapproved/unavailable, and the current Passport contract is intentionally insufficient to authorize Orion commands.

### B. Five-to-seven-minute technical presentation

City Brain is a FastAPI service built around an event database and several explicit state machines. The ingestion boundary accepts strict Pydantic events authenticated by service API keys. In the real integration, a background NGSI worker polls the hosted Orion broker for an allowlist of entity/attribute pairs. For Zone B, it maps `us-b-bldg-01.smokeLevel` to Brain sensor `us-b-bldg-01:fire_smoke`, measurement `smoke`, unit `ppm`, while preserving the original Orion timestamp and Guardian vocabulary.

The worker generates deterministic UUID5 identities and posts each observation through Brain’s own `/readings` API. The database stores the raw event, canonical SHA-256, correlation ID, and lifecycle. Duplicate identities are safe only when the canonical hash is identical.

Trust is separate from ingestion. Brain supports durable observation-level Guardian verdicts with revision, expiry, event hash, event ID, and issuer checks. It also has an audit-tail compatibility adapter. That adapter reconstructs Guardian’s exact canonical evidence body—including `ZONE-B`, Guardian’s property name and unit—and matches it to the Brain event. This confirms evidence identity but cannot authorize a reading because the audit endpoint is not an authenticated durable verdict feed.

For supervised development, Brain uses Guardian Evidence Passports. It sends the exact evidence digest to Guardian and receives a short-lived HMAC-SHA256-signed document. Brain refuses the public development key and verifies canonical signature, digest, mapping, trusted disposition, TTL, original observation age, and current Brain quarantine/rejection state. The shared random key is protected with Windows DPAPI and injected into the two processes without being printed or placed on the command line.

The City State engine reads only registered and currently eligible events. It applies freshness, unit, zone, duplicate timestamp, verdict/Passport, and quarantine checks, then calculates per-sensor statistics and zone aggregates. Raw readings remain visible separately so operators can distinguish “data arrived” from “data is authorized.”

Predictive intelligence is an optional serving layer. Traffic uses three XGBoost models for 15/30/60 minutes and requires a complete 207-sensor METR-LA grid. Water uses three LightGBM delta models for 1/3/6 hours and explicit USGS station mapping. Artifact format, feature order, checksums, preprocessing, training identities, trusted histories, and output provenance are validated. In the current runtime the model paths are not configured, so none of the six models is live.

Incident detection is rule-based rather than a model decision. A rule defines measurement, unit, direction, thresholds, persistence, evidence count, zone, gaps and recovery. The decision engine converts active eligible incidents into policy-approved candidate actions. OR-Tools CP-SAT limits action count, actuator conflicts and resource capacities, maximizes a deterministic weighted score, and must prove optimality. A separate verifier and Safety Shield recheck the selection and evidence.

Decision approval is a second request containing the exact evaluated decision ID and a reason. Brain re-hashes current inputs—incidents, evidence, policy, quarantine and availability—and cancels a stale decision. Command creation repeats safety checks and stores a deterministic command in the outbox. Delivery uses device-specific K1/K2 credentials in Orion query parameters. Broker `204` produces `DELIVERED`, not `EXECUTED`; Brain requires a later matching actuator state or trusted feedback.

Operationally, the current Brain is ready, Guardian is connected, Passport observation mode is enabled, and execution plus automatic approval are disabled. The candidate Zone B policy is unapproved and unavailable. We have demonstrated real ingestion, exact evidence matching, a real non-default HMAC signature, and trusted City State while the publisher was fresh. We have not demonstrated a real actuator command or Snap4City state change.

### C. Two-minute security pitch

Brain treats every external statement as evidence, not truth. Orion proves where data was read from, but not whether the measurement is physically trustworthy. Guardian’s device-level status is also insufficient because Brain needs authorization for one exact property, value, unit, timestamp, and persisted event.

Brain therefore recomputes canonical hashes and requires either a durable Guardian verdict bound to the Brain event or a short-lived signed Evidence Passport. It verifies HMAC with a non-default DPAPI-protected key using constant-time comparison, verifies the exact digest and trusted disposition, and enforces observation freshness and Passport expiry. Rejection, revocation and quarantine override Passport supplementation. If Guardian is unavailable, the reading is not authorized.

Trust still does not directly execute anything. Incident rules must be approved. The response policy must be approved and cryptographically tied to the incident rules. Resources and actuators must be current. OR-Tools must prove an optimal constrained selection, then an independent Safety Shield rechecks it. A human must explicitly approve safety-critical actions. Brain validates the decision again before placing a command in a durable outbox. Execution has a separate kill switch, per-device K1/K2 authentication, bounded retry rules, restart recovery, and post-delivery readback.

The most important security statement is what Brain refuses to claim: the current Passport does not prove a freshly reassessed Guardian revision, revocation, or quarantine state. Therefore Brain permits Passport-backed observation and decision inspection but explicitly blocks real Orion execution in this mode.

### D. Jury questions and answers

1. **Why use Guardian?**  
   Orion supplies values; Guardian supplies an independent trust assessment. Brain needs this separation so a plausible but compromised reading cannot directly influence decisions.

2. **Why use Orion?**  
   Orion is the shared NGSI v2 state broker. Twin publishes once, and Brain and Guardian independently read the same entity contract without a private direct Twin API.

3. **Why not trust a sensor because it came from the broker?**  
   Broker delivery does not prove sensor correctness, freshness, physical plausibility, or freedom from replay/tampering.

4. **What is HMAC?**  
   A keyed SHA-256 message authentication code. Guardian and Brain share a secret; Guardian signs canonical Passport bytes and Brain recomputes and constant-time compares the signature.

5. **How do you prevent replay?**  
   Deterministic IDs and database uniqueness stop duplicate observations; canonical hashes detect conflicting reuse; timestamps and freshness windows reject old/future events; verdict/Passport expiry prevents indefinite authorization. A Passport is invalid at its exact TTL boundary.

6. **Does `TRUSTED` for a device authorize all its readings?**  
   No. Brain requires evidence for one exact observation and attribute. A device summary can aggregate several properties and is not bound to the persisted Brain event.

7. **What happens if Guardian is offline?**  
   New Passport authorization fails closed and eligibility is cleared. Brain can still display raw observations separately, but they cannot enter trusted City State through that path.

8. **Can the AI execute decisions automatically?**  
   No in the current real runtime. Models produce forecasts, incident rules detect conditions, CP-SAT proposes responses, and safety-critical actions require explicit approval. Execution and auto-approval are both disabled.

9. **What does OR-Tools optimize?**  
   It selects policy-defined response candidates to maximize weighted benefit/urgency/severity while respecting maximum actions, capacity, conflicts, actuator uniqueness and incident constraints.

10. **What is the Safety Shield?**  
    It is independent code that rechecks incident activity, evidence eligibility, registry mapping, freshness and forecast continuity after optimization and again around approval/execution.

11. **How does Twin receive an action?**  
    Brain PATCHes plain NGSI attributes onto the actuator entity in Orion with its device-specific K1/K2. Twin polls that entity, validates the changed values, applies them, and republishes state.

12. **Does HTTP 204 mean the actuator executed?**  
    No. It means Orion accepted the PATCH. Brain records execution only after later matching Twin-published state or valid correlated feedback.

13. **What prevents unsafe actuation?**  
    Approved policy, rule hash, current trust, quarantine, current resource/actuator availability, CP-SAT constraints, independent verification, decision fingerprint, explicit approval, execution flag, outbox state machine, retry restrictions, and readback. Passport mode additionally blocks Orion execution entirely.

14. **How is this different from a normal dashboard?**  
    The dashboard is only a view. The underlying Brain persists provenance, recomputes trust, detects incidents, solves constrained responses, requires approval, and audits command lifecycle. It visibly distinguishes raw from authorized state.

15. **What happens after a verdict is revoked?**  
    Durable trust evaluation becomes untrusted, current City State excludes the evidence, dependent forecasts/decisions fail current eligibility, and stale decisions are cancelled. Passport supplementation is allowed only for missing verdicts, not a durable rejection/revocation.

16. **Is communication encrypted today?**  
    Hosted Orion is HTTPS. Brain has tested TLS 1.3/mTLS support and an nginx mTLS configuration, but local Brain and Guardian currently communicate over loopback HTTP under an explicit development-only allowance. Deployed end-to-end mTLS is not claimed.

17. **Are the AI models working live?**  
    The loaders, feature engineering, trust gates and isolated inference tests exist, but current model paths are unset and all six runtime slots report missing artifacts. Live forecasts are not available now.

18. **What is truly working today?**  
    Brain/Guardian health, real Orion ingestion when the Twin publisher is fresh, persistence, exact audit evidence matching, real non-default HMAC Passport verification, Passport-backed City State, and accurate dashboard eligible/stale transitions have been observed.

19. **What remains unfinished?**  
    A fully authenticated live durable Guardian verdict/revocation contract, current model artifacts/mappings, approval of real incident/action policy, confirmed simulation-only actuator scope, real approved PATCH plus later readback, Snap4City visualization, deployed mTLS, and two currently failing Passport/dashboard regression cases.

20. **Can you claim a complete autonomous emergency-response system?**  
    No. The implementation contains the controlled pipeline, but real execution is intentionally disabled and unverified. The accurate claim is a trust-aware decision foundation with demonstrated ingestion and authenticated City State, plus tested but gated actuation machinery.

## Source guide

- Composition/configuration: `app/main.py`, `app/core/config.py`
- API and schemas: `app/api/`, `app/schemas/`
- Persistence: `app/database/models.py`, `session.py`
- Processing/state: `app/streaming/event_processor.py`, `app/state/engine.py`
- Trust/security: `app/security/`, `app/integration/guardian_compat.py`, `guardian_passport.py`
- Twin/Orion: `app/integration/ngsi_twin.py`, `orion_adapter.py`, `config/devices.real-readonly.yaml`
- Models: `app/intelligence/artifacts.py`, `traffic_features.py`, `traffic_inference.py`, `water_features.py`, `inference.py`
- Incidents/decisions: `app/intelligence/incident_detector.py`, `incident_rules.py`, `app/decision/`
- Execution: `app/execution/actuator_manager.py`, `command_outbox.py`, `feedback_manager.py`
- Dashboard: `app/dashboard/api.py`, `app/dashboard/static/`
- Real candidate policy: `config/incidents.real-zoneb.candidate.yaml`, `policies.real-zoneb.candidate.yaml`
- Operational evidence: `docs/REAL_INTEGRATION_STATUS.md`, `scripts/verify-real-passport.ps1`
- Tests: `tests/integration/`, `tests/security/`, `tests/contract/`, `tests/unit/`

