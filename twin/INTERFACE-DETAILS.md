# Twin layer: interface details

This is the long version of the Interface Card. The one-page card is `INTERFACE.md`.

Owner: Twin team. Version 1.1. This card is the contract between the Twin and the two other layers (Guardian and Brain). It answers requirement R1: the Twin runs alone with mocks, nothing is hard-coded, and the way it authenticates is written down.

## 1. What the Twin does

The Twin simulates a US city (Chicago) with three zones and publishes it on the Snap4City platform:

* Zone A, a traffic jam (three traffic sensors, two traffic lights, one message sign).
* Zone B, a fire in a building (one sensor node, one alarm, one emergency dispatch).
* Zone C, waste management (one dumping camera, two bins, one cleaning task).

The Twin talks to the other layers through one shared place, the Orion broker of the platform. Nobody calls the Twin directly.

```
 TWIN --writes sensor readings--> ORION <--reads readings-- GUARDIAN
   ^                                ^ |
   | polls actuator records         | | reads
   +--------------------------------+ v
        BRAIN writes a command on an actuator record
```

## 2. Configuration

Nothing is hard-coded. Two files hold all the settings.

| File | Content | In git |
|---|---|---|
| `twin/config.json` | broker address (`orion.base_url`), API version, timeout, tick length (`tick_seconds`), the device list (id, kind, NGSI type), alert limits (`thresholds`), effect durations (`effects`), optional `guardian.verdicts_url` (see below), optional `ui.dashboard_url` | yes |
| `twin/scenarios.json` | the scenarios: steps, durations and when an incident counts as resolved | yes |
| `twin/secrets.json` | K1 and K2 of every device, or a TLS certificate and key | no (see `.gitignore`); the template is `twin/secrets.example.json` |

Environment variables override the files: `TWIN_CONFIG`, `TWIN_SECRETS`, `TWIN_LOG_DIR`, and for a hosted server `TWIN_CONFIG_JSON` and `TWIN_SECRETS_JSON` (the whole JSON text), `TWIN_HOST`, `PORT`, `TWIN_UI_PASSWORD` and `TWIN_UI_USER`.

Both files are checked when the Twin starts. A wrong file stops the Twin with a message that names the problem, for example `config.json: 'orion.base_url' is missing` or `Scenario a1, step 2: unknown mode 'explode'`.

Guardian verdicts on the timeline: if `guardian.verdicts_url` (or the variable `GUARDIAN_URL`) holds an address that answers with `{"<device id>": {"verdict": "UNTRUSTED", "reason": "..."}}`, the Twin shows each change of verdict on its live timeline. This is read only. The Twin works the same without it, and an unreachable or odd answer is logged and ignored.

Other settings come from environment variables: `GUARDIAN_URL`, `TWIN_CONFIG`, `TWIN_SECRETS`, `TWIN_SCENARIOS`, `TWIN_CONFIG_JSON`, `TWIN_SECRETS_JSON`, `TWIN_LOG_DIR`, `TWIN_HOST`, `PORT`, `TWIN_UI_USER`, `TWIN_UI_PASSWORD`.

To plug the Twin into another broker or another set of devices, change `config.json` only. The code that talks to the broker is in `src/orion_client.py`, the rules of what a device accepts are in `src/schema.py`, and the city model is in `src/model.py`. They do not depend on the web page.

## 3. Authentication

The platform uses the Orion Broker Filter with a K1 and a K2 per device. Every call carries these query parameters:

`?elementid=<device id>&type=<NGSI type>&k1=<K1>&k2=<K2>`

The base address is `https://smartopia.polytecsousse.dev/orion-filter/orion-1` (NGSI v2).

| Layer | Needs | Used for |
|---|---|---|
| Twin | K1 and K2 of every device | writing sensor values and actuator states |
| Brain | K1 and K2 of the six actuators only (`twin/mocks/brain_secrets.example.json`) | writing commands |
| Guardian | nothing, the devices are public | reading |

Keys are never printed. The Twin masks them in its logs and in its error messages.

## 4. Data out of the Twin

`GET {base}/v2/entities/<id>?type=<type>&elementid=<id>` returns `{"<attribute>": {"type": ..., "value": ...}}`. The Twin refreshes every device each `tick_seconds` (5 s by default). Every record has a `timestamp` in ISO 8601, UTC.

### Sensors

| Device id | NGSI type | Attributes and units |
|---|---|---|
| `us-a-traf-01`, `us-a-traf-02`, `us-a-traf-03` | TrafficSensor | `vehicleCount` (car/h), `avgSpeed` (km/h), `occupancy` (%), `congestionLevel` (0 to 100 %) |
| `us-b-bldg-01` | BuildingSensor | `smokeLevel` (ppm), `temperature` (C), `occupancyCount` (people) |
| `us-c-cam-01` | IPCamera | `dumpingDetected` ("true" or "false"), `confidence` (0 to 1), `status`, `message` |
| `us-c-bin-01`, `us-c-bin-02` | WasteBin | `fillLevel` (0 to 100 %) |

### Messages as sent

Every message is a `PATCH /v2/entities/<id>/attrs` with NGSI v2 attributes. Numbers are sent as `float`, text and booleans as `string`. A traffic sensor in the log:

```
{"vehicleCount": 22, "avgSpeed": 50.8, "occupancy": 14.6, "congestionLevel": 14, "timestamp": "2026-11-04T21:20:07+00:00"}
```

On the wire the same message is:

```
PATCH /orion-filter/orion-1/v2/entities/us-a-traf-01/attrs?elementid=us-a-traf-01&type=TrafficSensor&k1=<K1>&k2=<K2>
{"vehicleCount": {"type": "float", "value": 22}, "avgSpeed": {"type": "float", "value": 50.8},
 "occupancy": {"type": "float", "value": 14.6}, "congestionLevel": {"type": "float", "value": 14},
 "timestamp": {"type": "string", "value": "2026-11-04T21:20:07+00:00"}}
```

Other sensors: `us-b-bldg-01` sends `smokeLevel`, `temperature`, `occupancyCount`. `us-c-cam-01` sends `dumpingDetected`, `confidence`, `status`, `message`. `us-c-bin-01` sends `fillLevel`.

A reader gets the entity with `GET /v2/entities/<id>` and finds each attribute as `{"type": ..., "value": ...}`. The Guardian can read these without writing anything.

### Operations centre

`us-ops-center` (type OperationsCenter) summarises the whole city, so a reader gets the overall picture with one request. Attributes: `cityStatus` (NORMAL, WARNING or CRITICAL), `devicesNormal`, `devicesWarning`, `devicesCritical`, `devicesOffline`, `activeAlerts`, `activeAlertsText`, `emergencyStatus`, `avgCongestion`, `maxSmokeLevel`, `maxTemperature`, `maxFillLevel`, `lastEventTime`, `lastEventMessage`. Actuator states are available on their individual actuator entities.

`emergencyStatus` is `No active emergency`, or one line per active incident separated by `|`: `FIRE: alarm ON, 2 units dispatched`, `TRAFFIC: 2 roads jammed, light green, sign message shown`, `WASTE: cleaning task created`. A traffic jam counts once a road is critical. Waste counts when dumping is detected or a bin is critical.

Alert thresholds used by the Twin (the defaults, all set in `thresholds` of `config.json`):

| Measure | Warning | Critical |
|---|---|---|
| congestionLevel | 50 or more | 75 or more |
| smokeLevel or temperature | smoke 10 ppm or 38 C | smoke 100 ppm or 60 C |
| fillLevel | 80 or more | 95 or more |
| dumpingDetected | true | not used |
| silent device | not used | offline after 3 missed ticks |

### Actuators (the state is published too)

| Device id | NGSI type | Attributes |
|---|---|---|
| `us-a-light-01`, `us-a-light-03` | TrafficLight | `phase`, `cycleTime`, `mode` |
| `us-a-sign-01` | RoadSign | `message`, `roadClosed` |
| `us-b-alarm-01` | FireAlarm | `alarmState` |
| `us-b-disp-01` | EmergencyDispatch | `status`, `unitsDispatched`, `incidentId` |
| `us-c-task-01` | CleaningTask | `taskStatus`, `location` |

## 5. Data into the Twin: the Brain's actions

To command an actuator, write the new value on its record:

```
PATCH {base}/v2/entities/<id>/attrs?elementid=<id>&type=<type>&k1=<K1>&k2=<K2>
{"alarmState": {"type": "string", "value": "on"}}
```

The Twin reads each actuator record every tick, so a command takes up to one tick (5 s) to be applied. A value that differs from the one the Twin last published counts as a command. The Twin checks it, applies it and publishes the new state. A refused command is logged as `REJECTED` and the real state is written back on the broker.

| Actuator | Attribute | Allowed values |
|---|---|---|
| light | `phase` | red, yellow, green |
| light | `cycleTime` | any number of seconds |
| light | `mode` | auto, manual |
| sign | `message` | any text (the characters `< > " ' = ; ( )` are removed or replaced, because Orion refuses them) |
| sign | `roadClosed` | true, false |
| alarm | `alarmState` | on, off |
| dispatch | `status` | idle, dispatched, onScene |
| dispatch | `unitsDispatched` | any number |
| dispatch | `incidentId` | any text |
| task | `taskStatus` | none, created, inProgress, done |
| task | `location` | any text |

Example from Python:

```python
import requests
base = "https://smartopia.polytecsousse.dev/orion-filter/orion-1"
dev, typ = "us-b-alarm-01", "FireAlarm"
requests.patch(f"{base}/v2/entities/{dev}/attrs",
               params={"elementid": dev, "type": typ, "k1": K1, "k2": K2},
               json={"alarmState": {"type": "string", "value": "on"}}, timeout=10)
```

### What the Brain can observe after acting

* Traffic jam on roads 1 and 2: a light set to green with mode manual, or a sign message, brings the congestion back to normal in about 25 s.
* Fire: the building keeps burning, and smoke and temperature keep rising, until the alarm is `on` and units are `dispatched`. About 30 s later the fire is out.
* Waste: the dumping and the full bin stay until a task is `created`. About 15 s later the task is `done`, the dumping is cleared and the bins are emptied.

If nobody acts, nothing resolves. The incident stays and gets worse.

## 6. Scenarios and logs

`python src/twin.py run <scenario>` plays one scenario for a fixed time and writes `logs/<scenario>-<date>-<time>.log`. `python src/twin.py serve` opens the Scenario Control page on port 8080, where a scenario lasts until the incident is resolved. The scenario cards are in `scenarios/`.

| Id | Trigger | Expected |
|---|---|---|
| a1 | jam on roads 1 and 2 | warning, then critical; the Brain sets a light and the sign; recovery |
| b1 | fire in the building | warning, then critical; the Brain sets the alarm and the units; fire out |
| c1 | dumping and a full bin | warning, then critical; the Brain creates a task; cleared |
| g1 | smoke 400 ppm with a normal temperature | the Guardian marks it UNTRUSTED; the Brain must not act |
| g2 | traffic-03 stuck, traffic-02 dead | the Guardian flags both |
| g3 | constant fake jam on road 3 | the Guardian marks it UNTRUSTED |
| n1 | calm day | no alert; the Brain must not overreact |
| m1 | real fire and a fake jam at the same time | the Brain answers the fire and ignores the fake jam |

Each scenario has a trigger script in `scenarios/` (for example `python scenarios/a1.py`). Log line types: `VERDICT` (a Guardian verdict changed, if a Guardian address is set), `PUBLISH` (data sent), `MODE` (sensor behaviour changed), `ALERT` (raised, escalated or cleared), `RECEIVED` and `COMMAND` (an action from the Brain), `EFFECT` (a consequence), and lines ending in `_FAIL` (network or broker error).

## 7. Errors

When a partner sends something the Twin does not accept, the Twin keeps its real state and writes one line in the log. These lines are what a partner sees when its message is wrong:

| Log line | Cause |
|---|---|
| `REJECTED us-a-light-01: bad value 'blue' for phase; allowed: red, yellow, green` | value outside the list; the real state is written back on the broker |
| `REJECTED us-b-alarm-01: unknown attribute 'siren'; allowed: alarmState` | attribute that the device does not have |
| `REJECTED us-a-traf-01: not an actuator (kind traffic)` | a command written on a sensor |
| `REJECTED us-b-disp-01: bad value 'many' for unitsDispatched; a whole number is expected` | text where a number is expected |
| `IGNORED us-a-light-01: unknown attribute 'colour' on the entity; this device accepts phase, cycleTime, mode` | extra attribute on an actuator record, reported once. Orion metadata such as `latitude`, `longitude` and `model` is ignored. |
| `SEND_FAIL us-a-traf-01: HTTP 401 ... (wrong K1/K2, or the id or type does not match ...)` | broker answer, with the likely reason |

Broker answers:

| Answer | Meaning |
|---|---|
| 401 | wrong K1 or K2, or wrong device id or type |
| 400 "Invalid characters" | a text value contains `< > " ' = ; ( )` |
| 404 | wrong `base_url` |
| 409 TooManyResults | duplicate entity on the broker, ask the platform administrator |
| 5xx | the platform is busy; the Twin retries three times, then logs `SEND_FAIL` |

## 8. Running the Twin alone

Nothing else is needed: no platform, no Guardian, no Brain. From the `twin/` folder:

```
python mocks/run_mock.py                 # fake broker, Twin, mock Guardian, mock Brain, page on http://localhost:8080
python -m unittest discover -s tests -v  # 16 automatic tests
```

The mock Brain reads the mock Guardian's verdicts and ignores a sensor marked UNTRUSTED. On the Scenario Control page, the box "Mock Brain acts automatically" decides who commands the actuators. Switch it off when a real Brain, a mock Brain or a dashboard button does it.

## 9. Open points with the other teams

* The format of the Guardian verdicts and how the Brain receives them are not part of the Twin. The mock Guardian publishes `{device: {verdict, reason, checked}}` at `http://localhost:8090/verdicts`, as a stand-in.
* Whether a reader can list all devices of one type in a single request on the platform has not been checked. The Twin only reads one device at a time.
