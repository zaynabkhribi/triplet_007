# AegisCity Brain

The primary dashboard is one authenticated operational view at `http://localhost:8000/dashboard`.
It reads the same persistent state written by the running Brain, Mock Twin, and Mock Guardian. The
standalone scenario runner remains for regression tests only; it is not presented as an operating mode.

For a local mock demonstration, copy `.env.demo.example` to `.env` and replace every credential
placeholder with a distinct 32+ character value. The demo registry, rules, and policies are explicitly
simulation-only. Mock Twin emits seeded measurements continuously, and pressure controls alter that
same running stream; no external actuator is enabled.

The operational mock emits one validated measurement per configured sensor each second. Every reading
travels through authenticated ingestion, Mock Guardian verdicting, durable trust processing, City State,
incident rules, decision optimization, safety validation, command delivery, and Mock Twin feedback.


```powershell
.\.venv\Scripts\python.exe scripts/run_scenario.py all
.\.venv\Scripts\python.exe scripts/run_scenario.py traffic_congestion
```

See `TEST_BOOK.md` for expected outcomes and evidence locations.

Step 8 adds a durable actuator-command outbox and FIWARE Orion NGSI v2 adapter. External execution
is disabled by default (`ACTUATOR_EXECUTION_ENABLED=false`). Set `ACTUATOR_TRANSPORT=orion` and the
reviewed Orion endpoint/authentication/mapping variables before enabling it. Local standalone testing
uses `ACTUATOR_TRANSPORT=mock_twin`; no real device is contacted. Broker acceptance is recorded as
DELIVERED and requires separate feedback or verified Orion state before EXECUTED.

Run `alembic upgrade head` for command revisions. The existing NATS placeholder remains untouched but
is not used for actuator transport. See INTERFACE.md for command safety, retry, feedback and Orion setup.

Step 7 adds `/v1/decisions/evaluate` and auditable action plans without actuator execution.
Set `DECISION_POLICY_FILE=config/policies.yaml`; its default is unapproved and returns `NO_ACTION`.
Policies must explicitly approve the incident configuration hash, resources, actuator capabilities,
zones and optimization weights. Restart to load configuration changes. Critical plans require a
separate authenticated approval request. See INTERFACE.md for the approval contract.
`config/policies.simulation.yaml` is an inactive simulation example, not an operational policy.

Step 6 adds persistent operational incidents at `/v1/incidents`.
Set `INCIDENT_RULES_FILE=config/incidents.yaml` and supply reviewed, versioned rules.
The default file has no thresholds. `config/incidents.simulation.yaml` contains synthetic
demonstrations only and is rejected in production. Restart after configuration changes.
Run `alembic upgrade head` before deployment. The worker evaluates incidents automatically;
incident reads also refresh trust eligibility. No forecast model is required for observation rules.

Step 5 model inspection is available through /v1/models. Configure TRAFFIC_MODEL_DIR and
WATER_MODEL_PATH to load native artifacts. Water inference follows the supplied USGS V3 handoff.
Traffic inference uses the verified preprocessing NPZ and best_iteration; see INTERFACE.md
for the required 207-sensor mappings, training clock and trusted history.

Modular monolith for trusted city operations. Step 4 adds versioned zone state and sensor fusion.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe scripts/setup_dev.py
```

Setup generates local credentials and certificates; see INTERFACE.md for transport configuration.

## Run (separate terminals)

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000
.\.venv\Scripts\python.exe -m uvicorn mocks.mock_twin:app --port 8001
.\.venv\Scripts\python.exe -m uvicorn mocks.mock_guardian:app --port 8002
.\.venv\Scripts\python.exe scripts/run_sample.py
```

OpenAPI: http://localhost:8000/docs. Dashboard: http://localhost:8000/dashboard.
SQLite tables initialize on startup.
Startup adds event_lifecycle and quarantine_notifications without altering existing tables.
Legacy readings are recovered in bounded batches and require valid evidence before becoming eligible.
PostgreSQL: DATABASE_URL=postgresql+psycopg://user:password@host/database.

## Verify

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\ruff.exe check .
```

Traffic reference parity: `python scripts/verify_traffic_parity.py <artifact-directory>`.
Set `TRAFFIC_TEST_ARTIFACT_DIR` to run the full-grid API test with native models.
Its generated history remains test-only; it does not validate real-world forecast accuracy.

Containers: docker compose up --build (development HTTP).
TLS proxy: docker compose -f docker-compose.secure.yml up --build.

The sample waits for a trusted event and verifies the operational-state view.
The database-backed worker runs with FastAPI; no broker or Guardian connection is needed at startup.
See INTERFACE.md for trust deadlines, revisions, quarantine and read-only status routes.

Set CITY_REGISTRY_FILE to a YAML registry (config/city.yaml is deliberately empty).
Registry changes apply on restart and persist in the database. Without a configured file,
the last persisted registry is restored. Run alembic upgrade head for the additive city tables.

Standalone verification: .venv/Scripts/python.exe scripts/check_city_flow.py.
This starts three temporary local services, registers generated sensor/zone IDs, verifies city
state and history through HTTP, then stops the processes and removes its temporary data.

