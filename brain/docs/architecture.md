# Architecture

Step 4 adds a configuration-driven registry and CityEngine. The existing worker rebuilds city state
inside its serialized database transaction. TrustEngine remains the single trust evaluator.
Registry metadata persists in city_registry; immutable city_snapshots contains versioned zone and
sensor state with evidence references. No raw observations are copied into a separate evidence table.
Zone fusion uses only compatible, fresh, Guardian-approved readings. Historical snapshots are
as-known records, not currently eligible decision evidence.

City Brain is a modular monolith using ports and adapters.

```text
Mock Twin -> authenticated readings API -> sensor_events + event_lifecycle
Mock Guardian -> authenticated verdict/quarantine APIs -> immutable evidence history
Database queue -> async worker -> trust engine -> eligibility + ordered audit
Verified, fresh evidence -> read-only trusted operational state
```

- `api` and `streaming` are inbound adapters.
- `security` authenticates identities and evaluates evidence binding, revisions and deadlines.
- `streaming` polls a durable database queue and commits acknowledgments with state changes.
- `state` enforces lifecycle transitions and exposes only current eligible sensor evidence.
- `intelligence` defines feature, incident, model registry, and forecasting ports.
- `decision` defines policy, priority, optimization, planning, and safety ports.
- `execution` manages command delivery, feedback, and recovery boundaries.
- `integration` contains outbound HTTP adapters for Digital Twin and Guardian.
- `database` persists operational and audit records through SQLAlchemy.

SQLite supports standalone operation. PostgreSQL is selected through `DATABASE_URL`.
Writes serialize using SQLite BEGIN IMMEDIATE or a PostgreSQL transaction advisory lock.
Each event is processed within a savepoint; failures leave no partial transitions or acknowledgments.
Retries, deadlines and immutable verdict history survive restart. New verdicts and sensor quarantine
invalidate eligibility atomically before asynchronous reevaluation. Guardian is the authority for
cyberattack detection; Brain only verifies authenticated evidence and applies fail-closed trust rules.

Two additive tables hold lifecycle state and quarantine history; prior tables remain unchanged.
Startup creates missing tables and the worker recovers legacy sensor rows in bounded batches.
Polling uses thread-offloaded synchronous SQLAlchemy and bounded batches. This favors consistency
over writer throughput. Trusted-state snapshots currently scan stored readings; retention, indexing
for larger histories and horizontal throughput tuning are deferred.

NATS has an acknowledgment adapter boundary but no live broker integration. Orion is the configured
external actuator adapter; NATS is not used for command delivery. TLS/mTLS configuration and the
previously documented proxy-verification limitation remain unchanged.

# Incident detection

CityEngine rebuilds Guardian-eligible observations and evaluates configured incident rules in the
same serialized database transaction. The worker repeats this on new events and trust deadlines;
incident reads also reevaluate eligibility. Forecast warnings reuse the inference evidence checker.
No classifier training, decision optimization or actuator orchestration is performed.

One incident episode is maintained per rule and zone. IncidentRecord stores its current state;
IncidentRevision and the existing audit table preserve immutable updates. Confirmation counts
observations, not worker iterations. Configuration and evidence are persisted with every change.
Restart restores incidents from the database; SQLite transactions/PostgreSQL advisory locks prevent
competing workers from creating duplicate episodes. Invalidated evidence withdraws eligibility and
records the reason without asserting operational recovery. Synthetic example rules require explicit
configuration and cannot run in production mode.

# Decision engine

Authenticated evaluation rebuilds City State and incidents, then forms one global candidate portfolio.
Reviewed policies bind the incident-configuration hash, actuator capabilities, zone permissions and
dated resource availability. Priority scores and CP-SAT constraints select compatible actions. The
safety check independently validates selected actions and reuses existing Guardian evidence checks.
Forecast incidents are rechecked through the existing forecast-incident evaluator.

Decisions and immutable revisions share the existing database transaction/serialization mechanism.
The input fingerprint prevents duplicate evaluations; state rebuilds cancel superseded approvals.
Explicit critical-action approval is a separate brain-service request bound to the evaluated snapshot.
Actuator execution remains disabled. Availability is configuration-attested rather than a live resource
inventory, and no reservation is represented as executed consumption.

# Actuator execution

The Actuator Manager converts approved decision actions into deterministic command IDs inside the
existing database transaction boundary. A persistent outbox and command revisions survive Brain
restarts. Before each dispatch, the manager calls the existing City State, Decision Engine, Guardian
trust and Safety Shield paths again. Network I/O occurs after the DISPATCHING claim transaction.

The transport port has Orion NGSI v2 and Mock Twin adapters. Orion maps a command to an entity attribute
update over HTTPX; a broker 204 is DELIVERED, not physical execution. Feedback or verified state closes
the lifecycle. Retry policy considers declared action idempotency and never automatically repeats an
uncertain non-idempotent effect. External execution is disabled by default. The prior NATS adapter file
is retained for compatibility and is not part of actuator delivery.

# Operational mock providers and dashboard

`mocks.operational_twin.OperationalTwin` is an external development provider: it posts readings to
Brain and asks the separate Mock Guardian to submit correlated verdicts. Its pressure injections modify
the same continuous stream; they do not create a second database or bypass Brain services. The
OperationalCoordinator can auto-approve only policies that are both explicitly approved and marked
simulation-only, then delegates to the existing Actuator Manager. Mock Twin feeds execution confirmation
back through the regular feedback route.

The dashboard polls the persistent operational snapshot and streams audit timeline changes through SSE.
It labels the environment as mock data, displays provider connectivity separately from Brain processing,
and never inserts frontend-only sensor, forecast, incident, decision, or execution values.

# Regression scenario demonstrations

The dashboard is a static FastAPI-served frontend backed by authenticated snapshot, timeline, and SSE
routes. It reads existing database and engine state; persistent audit and scenario logs are the event
source. Browser sessions store only hashed tokens server-side, use HttpOnly SameSite cookies, and bind
state-changing requests to CSRF tokens and the existing service roles.

ScenarioRunner creates a fresh temporary Brain database and in-process Mock Twin and Mock Guardian for
each run, then drives the normal HTTP, trust, state, incident, decision, safety, command, and feedback
paths. Only the result and ordered evidence log are copied to the configured Brain database. This makes
resets deterministic without deleting audit evidence and keeps standalone demonstrations independent
of Orion.

