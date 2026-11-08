# triplet-07: City Brain Convergence

Three layers of one smart city on Snap4City. The city is Chicago, with three zones: A traffic jam, B fire incident, C waste management.

| Layer | Folder | Job | Owner |
|---|---|---|---|
| Twin | `twin/` | simulates the city, publishes sensors, reacts to actuator commands | Smartopia |
| Guardian | `guardian/` | reads the sensors and judges whether each reading can be trusted | AEGIS LOOP |
| Brain | `brain/` | reads the sensors and the Guardian verdicts, writes actuator commands | #NOSENSORS |


## Start

One command from this folder, with Docker:

```
docker compose up --build
```

The Twin page is then on http://localhost:8080. Before the first start, copy `twin/secrets.example.json` to `twin/secrets.json` and fill in the device keys. To protect the page, create a `.env` file with `TWIN_UI_USER` and `TWIN_UI_PASSWORD`.

Without Docker and without any platform account, the Twin runs alone with mocks:

```
cd twin
pip install -r requirements.txt
python mocks/run_mock.py
```

On Smartopia, the same image is deployed from `twin/Dockerfile`. Configuration goes in through the environment variables listed in `twin/README.md`.

## Where to read

* [INTEGRATION.md](INTEGRATION.md) how the layers connect
* [TESTBOOK.md](TESTBOOK.md) test scenarios and expected outputs
* [twin/INTERFACE.md](twin/INTERFACE.md) the Interface Card of the Twin
* [scenarios/](scenarios/) one card per scenario, with its trigger
* [logs/](logs/) one log file per scenario run

## Repository rules

Each folder is owned by its team (`.github/CODEOWNERS`). Secrets are never committed: `secrets.json`, `.env` and `*_secrets.json` are in `.gitignore`.
