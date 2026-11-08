# Twin layer, Chicago

The Twin simulates three zones of a US city and publishes them to the Snap4City platform (Orion Broker Filter, NGSI v2).

* Zone A: traffic jam (roads, traffic lights, message sign)
* Zone B: fire incident (building sensors, alarm, emergency dispatch)
* Zone C: waste management (cameras, bins, cleaning task)

The Twin writes the sensors. The Brain writes the actuators, and the Twin reads them back and changes the city accordingly. The Guardian only reads. The full contract is in [INTERFACE.md](INTERFACE.md).

## Run it alone, with mocks (R1)

No platform account and no Docker are needed. Python 3.10 or later:

```
cd twin
pip install -r requirements.txt
python mocks/run_mock.py
```

This starts a fake broker, the Twin, a mock Guardian and a mock Brain, and writes its temporary files in `twin/mock_run/`. Open http://localhost:8080 and launch a scenario. Stop with Ctrl+C.

Unit tests:

```
python -m unittest discover -s tests -v
```

## Run it against the platform

1. Copy `secrets.example.json` to `secrets.json` and fill K1 and K2 for each device. Never commit this file.
2. Check `config.json`: broker URL, device ids, tick length, alert limits (`thresholds`), effect times (`effects`) and `ui.dashboard_url` (the operations dashboard link shown in the page). Scenarios are in `scenarios.json`.
3. Start:

```
python src/twin.py check       # one reading per device, prints the HTTP status
python src/twin.py serve       # Scenario Control page on http://localhost:8080
python src/twin.py run a1      # one timed scenario, writes a log in ../logs
```

With Docker, from the repository root: `docker compose up --build`.

## Configuration

Nothing is hard-coded. The Twin reads `config.json` and `secrets.json`, or the variables below, which win over the files.

| Variable | Meaning |
|---|---|
| `TWIN_CONFIG`, `TWIN_SECRETS`, `TWIN_SCENARIOS` | paths of the three files |
| `TWIN_CONFIG_JSON`, `TWIN_SECRETS_JSON` | the same content as a JSON string (for a platform that injects secrets) |
| `TWIN_LOG_DIR` | where scenario logs are written |
| `TWIN_HOST`, `PORT` | address and port of the page |
| `TWIN_UI_USER`, `TWIN_UI_PASSWORD` | optional Basic authentication on the page |

## Folders

* `src/` the simulator, one module per job: `twin.py` (command line), `engine.py` (tick loop and scenario control), `model.py` (devices and city), `schema.py` (what each device accepts), `orion_client.py` (the only code that talks to the broker), `scenarios.py` (scenario checks), `web.py` (Scenario Control page), `settings.py`
* `scenarios.json` the scenarios, as data
* `mocks/` fake broker, mock Guardian, mock Brain and the runner
* `tests/` automatic tests
* `../scenarios/` one card per scenario
* `../logs/` one log file per scenario run
