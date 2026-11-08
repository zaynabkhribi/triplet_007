# Testbook

Nine scenarios for the Twin and its interactions with the Guardian and the Brain. Every scenario starts with one trigger and writes one log file in `logs/`. A trigger is one command at the root of the repository (`python scenarios/<id>.py`) or one click on the Scenario Control page of the Twin. The scenario cards, with more detail, are in `scenarios/`.

The "Mock run" line is what was measured with the Twin against a mock broker, with the Twin playing the Brain's answer. The "Platform run" line stays empty until the run on Smartopia with the real Guardian and Brain.

## What the scenarios cover

| Interaction | What it shows | Scenarios |
|---|---|---|
| Twin and Brain | the city runs normally, and the Brain reacts correctly to real events | n1, a1, b1, c1 |
| Twin and Guardian | healthy and unhealthy data are told apart | g1, g2, g3 |
| Brain and Guardian | a trust verdict changes the Brain's decision | g1, g3, m1 |
| All three | the whole city works as one system, including when something goes wrong | m1, d1 |

## n1. Calm day

| Field | Content |
|---|---|
| ID | n1 |
| Name | Calm day |
| Layers involved | Twin, Guardian, Brain |
| Description | Normal traffic, a quiet building and empty bins for 60 s. Nothing should happen. The Brain must not overreact. |
| Trigger | `python scenarios/n1.py`, or the card "Calm day" on the Twin page |
| Expected: Twin | Publishes normal values on every tick. Traffic stays under 50%, the building at about 22 C, bins fill slowly and empty at 70%. City status NORMAL. |
| Expected: Guardian | Marks every sensor TRUSTED. |
| Expected: Brain | Writes no command on any actuator. |
| How to verify | `logs/n1-*.log` has no ALERT line and no COMMAND line. |
| Mock run | no alert and no command in 60 s |
| Platform run | |

## a1. Traffic jam on roads 1 and 2

| Field | Content |
|---|---|
| ID | a1 |
| Name | Traffic jam on roads 1 and 2 |
| Layers involved | Twin, Brain |
| Description | Roads 1 and 2 jam. The Brain must relieve the traffic with the light and the sign. |
| Trigger | `python scenarios/a1.py`, or the card "Traffic jam" |
| Expected: Twin | +5 s: roads 1 and 2 start to jam. +10 s: WARNING (about 50%). +25 s and +30 s: CRITICAL (75% and more). The jam stays until a light is set to green or manual. Alerts clear about 10 s after the command. |
| Expected: Guardian | Marks the three road sensors TRUSTED (their values are consistent). |
| Expected: Brain | Writes `phase=green` and `mode=manual` on `us-a-light-01` and a message on `us-a-sign-01`. |
| How to verify | Timeline page, and `logs/a1-*.log`: ALERT RAISED, ALERT ESCALATED, two COMMAND lines, ALERT CLEARED. |
| Mock run | warning +10 s, critical +25 s and +30 s, commands +35 s, cleared +45 s |
| Platform run | |

## b1. Fire in building 1

| Field | Content |
|---|---|
| ID | b1 |
| Name | Fire in building 1 |
| Layers involved | Twin, Guardian, Brain |
| Description | The building burns. The Brain must sound the alarm and send units. |
| Trigger | `python scenarios/b1.py`, or the card "Fire incident" |
| Expected: Twin | +5 s: smoke and temperature rise on every tick. WARNING at +5 s, CRITICAL at +20 s. The fire stays until the alarm is on and units are dispatched, then goes out about 25 s later. |
| Expected: Guardian | Marks smoke and temperature TRUSTED, because both rise together. |
| Expected: Brain | Writes `alarmState=on` on `us-b-alarm-01` and `status=dispatched` on `us-b-disp-01`. |
| How to verify | Timeline page, and `logs/b1-*.log`: two COMMAND lines, then EFFECT fire extinguished, then ALERT CLEARED. |
| Mock run | warning +5 s, critical +20 s, commands +20 s, fire out +45 s |
| Platform run | |

## c1. Illegal dumping and full bin

| Field | Content |
|---|---|
| ID | c1 |
| Name | Illegal dumping and full bin |
| Layers involved | Twin, Brain |
| Description | The camera sees dumping and a bin fills up. The Brain must create a cleaning task. |
| Trigger | `python scenarios/c1.py`, or the card "Waste / illegal dumping" |
| Expected: Twin | +5 s: dumping alert at once, and the bin fills fast. Bin WARNING at 80%, CRITICAL at 95%. Both stay until a task is created. About 10 s after the task, the dumping is cleared and the bins are emptied. |
| Expected: Guardian | Marks the camera and the bin TRUSTED. |
| Expected: Brain | Writes `taskStatus=created` and a `location` on `us-c-task-01`. |
| How to verify | Timeline page, and `logs/c1-*.log`: COMMAND for the task, EFFECT cleaning done, both alerts CLEARED. |
| Mock run | dumping +5 s, bin warning +26 s, critical +31 s, task +41 s, cleared +50 s |
| Platform run | |

## g1. Spoofed smoke reading

| Field | Content |
|---|---|
| ID | g1 |
| Name | Spoofed smoke reading |
| Layers involved | Twin, Guardian, Brain |
| Description | The building sensor reports 400 ppm of smoke while the temperature stays normal. Nothing burns. |
| Trigger | `python scenarios/g1.py`, or the card "Spoofed smoke reading" |
| Expected: Twin | +5 s: the sensor reports 400 ppm and 22 C. The operations centre only shows raw values, so it raises a FIRE alert. Judging the reading is the Guardian's job. |
| Expected: Guardian | Marks the sensor UNTRUSTED (smoke without heat) within a few ticks. |
| Expected: Brain | Does not sound the alarm and does not dispatch units, and records why. |
| How to verify | Timeline page, and `logs/g1-*.log`: MODE spoof_smoke, and no COMMAND line for the alarm or the dispatch. |
| Mock run | MODE +5 s, alert raised +5 s, no command line |
| Platform run | |

## g2. Stuck and dead sensors

| Field | Content |
|---|---|
| ID | g2 |
| Name | Stuck and dead sensors |
| Layers involved | Twin, Guardian |
| Description | One road sensor repeats the same values and another stops publishing. |
| Trigger | `python scenarios/g2.py`, or the card "Sensor faults" |
| Expected: Twin | +5 s: `us-a-traf-03` repeats the same values and `us-a-traf-02` stops. +15 s: COMM_LOSS alert for `us-a-traf-02`. |
| Expected: Guardian | Flags the stuck sensor and the silent one as not TRUSTED. |
| Expected: Brain | Does not act on either sensor. |
| How to verify | Timeline page, and `logs/g2-*.log`: MODE stuck, MODE dead, ALERT COMM_LOSS, no COMMAND line. |
| Mock run | modes +5 s, COMM_LOSS +15 s, no command line |
| Platform run | |

## g3. Fake traffic jam

| Field | Content |
|---|---|
| ID | g3 |
| Name | Fake traffic jam |
| Layers involved | Twin, Guardian, Brain |
| Description | One road sensor reports a constant jam while the road is free. |
| Trigger | `python scenarios/g3.py`, or the card "Fake traffic jam" |
| Expected: Twin | +5 s: `us-a-traf-03` reports the same high congestion on every tick. The operations centre raises a TRAFFIC_JAM alert from the raw values. |
| Expected: Guardian | Marks `us-a-traf-03` UNTRUSTED (constant values). |
| Expected: Brain | Does not change a light or a sign because of it. |
| How to verify | Timeline page, and `logs/g3-*.log`: MODE fake_jam, and no COMMAND line. |
| Mock run | mode +5 s, alert raised +5 s, no command line |
| Platform run | |

## m1. Real fire and a fake jam at the same time

| Field | Content |
|---|---|
| ID | m1 |
| Name | Real fire and a fake jam at the same time |
| Layers involved | Twin, Guardian, Brain |
| Description | A real fire starts while a sensor reports a fake jam on road 3. The Brain must answer the fire and ignore the fake jam. |
| Trigger | `python scenarios/m1.py`, or the card "Real fire and a fake jam at the same time" |
| Expected: Twin | +5 s: the fire starts and `us-a-traf-03` reports a fake jam. The fire ends about 25 s after the alarm and the dispatch. The fake jam stays until Reset all. |
| Expected: Guardian | Marks the building TRUSTED and `us-a-traf-03` UNTRUSTED. |
| Expected: Brain | Writes the alarm and the dispatch. Writes nothing on the lights or the sign. |
| How to verify | Timeline page, and `logs/m1-*.log`: two COMMAND lines for the fire, none for the lights or the sign. |
| Mock run | fire commands +20 s, fire out +45 s, no light or sign command |
| Platform run | |

## d1. Brain down, the fire keeps burning

| Field | Content |
|---|---|
| ID | d1 |
| Name | Brain down, the fire keeps burning |
| Layers involved | Twin |
| Description | A real fire starts and no Brain answers, as if the Brain layer were down. One missing layer must not stop the city. |
| Trigger | `python scenarios/d1.py`, or the card "Brain down" (with the mock Brain unticked) |
| Expected: Twin | +5 s: the fire starts. The alert goes CRITICAL and stays. The Twin keeps publishing every device on every tick. |
| Expected: Guardian | Marks the building TRUSTED. |
| Expected: Brain | Absent. It writes nothing. |
| How to verify | `logs/d1-*.log`: no COMMAND line, the fire alert stays CRITICAL, PUBLISH lines until the last tick. |
| Mock run | warning +5 s, critical +20 s, no command line, 140 PUBLISH lines in 60 s |
| Platform run | |

## Interface tests (R1)

Run with `python -m unittest discover -s tests -v` in `twin/`. They need no platform and no partner.

| Test | Expected |
|---|---|
| publish | every sensor is written to the broker |
| wrong keys | the Twin does not publish with wrong keys (broker answers 401) |
| text cleaning | forbidden characters are removed before sending |
| invalid command | a value outside the allowed list is rejected |
| command applied | a command read from the broker changes the city |
| fire out | fire ends after alarm on and units dispatched |
| fire persists | fire stays when no action is taken |
| valid command | a correct command is accepted |
| bad value | a rejected value says what is allowed |
| unknown attribute | a rejected attribute is named, with the accepted list |
| sensor commanded | a command on a sensor is refused |
| number field | text in a number field is refused |
| shipped scenarios | `scenarios.json` matches `config.json` |
| scenario with unknown device | the Twin stops and names the device |
| thresholds from config | alert limits change with `config.json` |
| odd broker answers | a list, text or empty attribute from the broker is ignored with a log line, the Twin keeps running |
| emergency status | a critical traffic jam shows in the emergency status |

## How to read a log

Each line is `date time TYPE text`. Look for MODE (the incident starts), ALERT RAISED, ALERT ESCALATED, COMMAND (the Brain acted), EFFECT (the city reacted) and ALERT CLEARED. A scenario passes when these lines appear in this order and within the times above, give or take one tick (5 s).
