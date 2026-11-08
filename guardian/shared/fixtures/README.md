Fixture set for the Phase 1 Test Book. Every file here is used by one committed
log in `logs/`, so nothing is speculative.

| Fixture | Scenario | What it plants |
|---|---|---|
| `calm_day_t1.json` | T1 | healthy river gauge, dry rain, calm junction camera |
| `rush_hour_t2.json` | T2 | saturated camera, heavy grid, corroborating call volume |
| `real_flood_t3.json` | T3 | genuine rise 1.40 -> 1.55 m with heavy rain corroborating |
| `muted_gauge_t4.json` | T4 | gauge collapses 0.82 -> 0.00 m while rain keeps pouring |
| `fake_flood_t5.json` | T5 | port gauge reports 1.80 m, true level 0.40 m, dry rain |
| `spoof_gps_t6.json` | T6 | fleet GPS jumps -179 -> +179 degrees in one tick |
| `combined_t7.json` | T7 | real heat, fabricated port surge, real hospital calls, one tick |
| `drift_attack.json` | S1 | slow authenticated drift of +6 cm/tick, signature valid |
| `golden_clean.json` | golden | all-clear baseline, asserted to stay all-TRUSTED |

`ground_truth` is the judge-only channel. It holds what the Twin knows and never
publishes (true water level, whether the actuator really moved). The Guardian and
the Brain never read it; the scenario runner reads it only to report the observed
effect honestly in the witness step.

The actuator-fault path lives in the adversarial suite rather than in a fixture:
`guardian/tests/test_adversarial.py::test_three_mismatches_quarantine_and_downgrade`
drives three consecutive MISMATCH witnesses and asserts quarantine. Keeping it in
tests rather than in a fixture is deliberate — a staged false witness would be an
invented result, and T5's actuator genuinely does move.
