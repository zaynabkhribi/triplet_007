# Logs

One file per scenario run, named `<scenario>-<date>-<time>.log`. Each line has a timestamp and a type: SCENARIO, MODE (a sensor changes behaviour), ALERT, COMMAND (an actuator is written), EFFECT (the city reacts) or NOTE.

The files in this folder were produced by running `python src/twin.py run <scenario>` against the mock broker, with the Twin playing the Brain response itself. They show the format and the timings. Replace them with runs against the platform before the final submission.
