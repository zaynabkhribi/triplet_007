# Integration

## Diagram

```
                 +-------------------------+
                 |  Orion Broker (Snap4City) |
                 +-------------------------+
   sensors  ^  |  actuators         |  sensors
  (PATCH)   |  |  (GET, polled)     |  (GET)
            |  v                    v
        +--------+   verdicts   +----------+
        |  Twin  |              | Guardian |
        +--------+              +----------+
            ^                        |
            | actuators (PATCH)      | verdict (format to confirm)
            |                        v
            |                    +-------+
            +--------------------| Brain |
                                 +-------+
```

The layers never call each other directly. They share state through Orion, so each layer runs on its own and can be replaced by a mock.

## Protocol

* Format: NGSI v2 entities through the Orion Broker Filter, `https://smartopia.polytecsousse.dev/orion-filter/orion-1`.
* Write: `PATCH /v2/entities/{id}/attrs?elementid={id}&type={type}&k1={K1}&k2={K2}`.
* Read: `GET /v2/entities/{id}`. Public devices need no key.
* Text values may not contain `< > " ' = ; ( )`. The broker answers HTTP 400 otherwise.
* Time step: one tick, 5 seconds by default (`config.json`).

Who writes what:

| Layer | Writes | Reads |
|---|---|---|
| Twin | sensors (traffic, building, camera, bin) and the operations centre status | actuators (light, sign, alarm, dispatch, cleaning task), every tick |
| Guardian | its verdicts (format to confirm, see below) | sensors |
| Brain | actuators | sensors and Guardian verdicts |

Device ids, attributes and allowed values are in [twin/INTERFACE.md](twin/INTERFACE.md).

## One scenario end to end: fire (b1)

Times are measured in the mock run, see `logs/b1-*.log`.

1. +5 s. The Twin sets `us-b-bldg-01` to fire. Smoke and temperature rise on every tick and are published to Orion.
2. +5 s. The operations centre `us-ops-center` shows a WARNING for FIRE.
3. The Guardian reads smoke and temperature. Both rise together, so it marks the building TRUSTED.
4. The Brain reads the sensors and the verdict, and sees a confirmed fire. It writes `alarmState=on` on `us-b-alarm-01` and `status=dispatched` on `us-b-disp-01`.
5. +20 s. The Twin reads both actuators at its next tick. The alert is already CRITICAL (smoke 80 ppm, 70 C).
6. The Twin sees the alarm on and the units dispatched, and starts to put the fire out.
7. +45 s. Smoke and temperature are back to normal, the alert clears and the emergency status is released.

If the Brain does nothing, step 6 never happens and the fire stays.

Spoofed case (g1): smoke is 400 ppm but the temperature is normal. The Guardian marks it UNTRUSTED and the Brain must not write the alarm. The test is that no COMMAND line appears in the log.

## Live timeline (R3)

The Twin page has a live timeline with a time stamp on each line. It shows, in one list, the reading that turns into an alert (ALERT), the Guardian verdict (VERDICT), the Brain's command (BRAIN) and the effect in the city (EFFECT). To see the verdicts, set the Guardian's address in `twin/config.json` (`guardian.verdicts_url`). The Brain's commands and the effects are read from the broker, so they appear without any setting.


