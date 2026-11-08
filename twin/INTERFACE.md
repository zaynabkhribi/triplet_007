# Twin layer: Interface Card

Owner: Twin team. Version 1.2. Details, tables and every error line: [INTERFACE-DETAILS.md](INTERFACE-DETAILS.md).

The Twin simulates a US city (Chicago, three zones) and publishes it on the Snap4City Orion broker. It talks to the Guardian and the Brain only through that broker. Nobody calls the Twin.

## What the Twin sends

Every 5 s, one `PATCH` per device. Protocol: HTTPS, NGSI v2, JSON.

```
PATCH {base_url}/v2/entities/us-b-bldg-01/attrs?elementid=us-b-bldg-01&type=BuildingSensor&k1=<K1>&k2=<K2>
{"smokeLevel": {"type": "float", "value": 80}, "temperature": {"type": "float", "value": 70},
 "occupancyCount": {"type": "float", "value": 15}, "timestamp": {"type": "string", "value": "2026-11-06T22:01:26+00:00"}}
```

| Device (kind) | Example of the values sent |
|---|---|
| `us-a-traf-01` to `03` (road sensor) | `{"vehicleCount": 17, "avgSpeed": 49.2, "occupancy": 14.2, "congestionLevel": 14}` |
| `us-b-bldg-01` (building sensor) | `{"smokeLevel": 2.2, "temperature": 21.7, "occupancyCount": 15}` |
| `us-c-cam-01` (camera) | `{"dumpingDetected": false, "confidence": 0.0, "status": "active", "message": "ok"}` |
| `us-c-bin-01`, `02` (bin) | `{"fillLevel": 5}` |
| `us-a-light-01`, `03`, `us-a-sign-01`, `us-b-alarm-01`, `us-b-disp-01`, `us-c-task-01` | the current state of the actuator, for example `{"alarmState": "off"}` |
| `us-ops-center` (city summary) | `{"cityStatus": "NORMAL", "emergencyStatus": "No active emergency", "activeAlertsText": "none", "devicesNormal": 13, "devicesWarning": 0, "devicesCritical": 0, "devicesOffline": 0, "avgCongestion": 14.0, "lastEventMessage": "none"}` |

A reader gets any device with `GET {base_url}/v2/entities/<id>`. Each attribute comes back as `{"type": ..., "value": ...}`. The devices are public, so a read needs no key.

## What the Twin receives

The Brain writes a new value on an actuator, with the same kind of `PATCH` and the Brain's own keys. The Twin reads the six actuators every 5 s and applies a valid value.

```
PATCH {base_url}/v2/entities/us-b-alarm-01/attrs?elementid=us-b-alarm-01&type=FireAlarm&k1=<K1>&k2=<K2>
{"alarmState": {"type": "string", "value": "on"}}
```

| Actuator | Attribute: allowed values |
|---|---|
| traffic light | `phase`: red, yellow, green. `mode`: auto, manual. `cycleTime`: a number |
| message sign | `message`: any text. `roadClosed`: true, false |
| alarm | `alarmState`: on, off |
| emergency dispatch | `status`: idle, dispatched, onScene. `unitsDispatched`: a number. `incidentId`: any text |
| cleaning task | `taskStatus`: none, created, inProgress, done. `location`: any text |

Cause and effect: a light on green or manual relieves a jam. A fire stops only after the alarm is `on` and units are `dispatched`. Dumping and a full bin stop after a task is `created`. Without an action, nothing resolves.

## How to point it at another partner

Nothing is hard-coded. In `twin/config.json`, set `orion.base_url` (another broker), `devices` (other ids and types), `thresholds`, and `guardian.verdicts_url` (optional, shows the Guardian's verdicts on the timeline). In `twin/secrets.json`, set K1 and K2 per device. Scenarios are in `twin/scenarios.json`. Environment variables override the files (`TWIN_CONFIG`, `TWIN_SECRETS`, `TWIN_SCENARIOS`, `GUARDIAN_URL`, `TWIN_LOG_DIR`). The Twin checks these files at start and stops with a message that names the problem.

## How it authenticates

Orion Broker Filter: every call carries `elementid`, `type`, `k1` and `k2`. The Twin holds the keys of all its devices. The Brain needs only the keys of the six actuators. The Guardian needs no key to read. Keys are never in git or in the logs. The page of the Twin can be locked with `TWIN_UI_USER` and `TWIN_UI_PASSWORD`.

## When a partner sends something unexpected

The Twin refuses it, keeps the real state, and writes one line in the log that names the problem and the accepted values:

`REJECTED us-a-light-01: bad value 'blue' for phase; allowed: red, yellow, green`

An unknown attribute, a command on a sensor, text in a number field and an odd answer from the broker are handled the same way. The Twin never stops because of a partner message.

## Run it alone (R1)

```
cd twin
python mocks/run_mock.py                  # fake broker, Twin, mock Guardian, mock Brain
python -m unittest discover -s tests -v   # 17 tests
```
