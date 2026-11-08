# AegisCity Phase 1 Test Book

All thresholds, resources, devices, and actions in this book are simulation-only. Scenario runs use
fresh isolated state with Mock Twin and Mock Guardian, then persist results in the configured Brain
database. They do not contact Orion or real devices. Each result includes a unique execution ID,
expected and actual outcomes, and an ordered timeline at `database:scenario_logs:<execution_id>`.

Run one scenario:

```powershell
.\.venv\Scripts\python.exe scripts/run_scenario.py traffic_congestion
```

Run the complete book or record a deterministic reset:

```powershell
.\.venv\Scripts\python.exe scripts/run_scenario.py all
.\.venv\Scripts\python.exe scripts/run_scenario.py --reset
```

| ID | Description | Expected result | Actual observed result | Evidence | Status |
| --- | --- | --- | --- | --- | --- |
| traffic_congestion | Trusted low compatible speeds | Congestion incident, approved plan, simulated execution | Verified by automated scenario suite | Persistent scenario timeline | PASS |
| building_fire | Trusted smoke threshold persistence | Smoke alert, explicit approval, simulated response | Verified by automated scenario suite | Persistent scenario timeline | PASS |
| rapid_water_rise | Trusted positive water-level rate | Rapid-rise incident; no flood probability claim; simulated response | Verified by automated scenario suite | Persistent scenario timeline | PASS |
| power_overload | Trusted persistent power load | Overload incident, approved plan, simulated response | Verified by automated scenario suite | Persistent scenario timeline | PASS |
| untrusted_sensor | Mock Guardian rejects readings | No trusted city value, incident, decision, or action | Verified by automated scenario suite | Verdict and scenario timeline | PASS |
| sensor_quarantine | Guardian quarantines failed sensor | Sensor unavailable and no action | Verified by automated scenario suite | Quarantine and scenario timeline | PASS |
| unauthorized_actuator | Twin role requests execution and unsupported operation | HTTP 403 and 422; no authorized command | Verified by automated scenario suite | Security and scenario timeline | PASS |
| communication_failure | Simulated connection loss after authorization | Non-idempotent command becomes UNKNOWN without retry | Verified by automated scenario suite | Command revisions and scenario timeline | PASS |
| restart_recovery | Dispatch interrupted before delivery | Idempotent command returns to PENDING | Verified by automated scenario suite | Command revisions and scenario timeline | PASS |

Dashboard trigger: open `/dashboard`, authenticate as `brain`, and select a scenario. Read-only service
roles can view state but cannot run or reset scenarios. CLI and dashboard runs share the same runner.

Known limitations: forecasts are shown only when genuine model inference records exist; scenarios do
not fabricate predictions. Mock Twin state is process-local. Live Orion, PostgreSQL, browser rendering
across multiple engines, and production thresholds remain outside this standalone Phase 1 test book.
