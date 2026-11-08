"""
Tests of the Twin layer, run alone against the fake broker (no platform, no other layer).

    python -m unittest discover -s tests -v        (from the twin/ folder)
"""
import os
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, os.path.join(HERE, "..", "mocks"))

import fake_orion   # noqa: E402
import twin         # noqa: E402
import schema       # noqa: E402
import scenarios    # noqa: E402
import model        # noqa: E402

DEVICES = {
    "us-a-traf-01": {"kind": "traffic", "type": "TrafficSensor"},
    "us-a-light-01": {"kind": "light", "type": "TrafficLight"},
    "us-b-bldg-01": {"kind": "building", "type": "BuildingSensor"},
    "us-b-alarm-01": {"kind": "alarm", "type": "FireAlarm"},
    "us-b-disp-01": {"kind": "dispatch", "type": "EmergencyDispatch"},
}
SECRETS = {d: {"k1": f"k1-{d}", "k2": f"k2-{d}"} for d in DEVICES}


class TwinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fake_orion.KEYS.update({d: (s["k1"], s["k2"]) for d, s in SECRETS.items()})
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), fake_orion.Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}/orion-filter/orion-1"
        twin.log.setLevel(50)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def city(self, secrets=SECRETS):
        conf = {"orion": {"base_url": self.base, "api": "v2", "timeout": 3}, "devices": DEVICES}
        return twin.build_city(conf, secrets)

    # ---- data out of the Twin ------------------------------------------------
    def test_sensor_reading_is_published(self):
        c = self.city()
        dev = c.devices["us-a-traf-01"]
        self.assertTrue(dev.send(dev.reading()))
        self.assertIn("congestionLevel", fake_orion.STORE["us-a-traf-01"])

    def test_wrong_keys_are_refused(self):
        bad = {d: {"k1": "x", "k2": "y"} for d in DEVICES}
        dev = self.city(bad).devices["us-a-traf-01"]
        self.assertFalse(dev.send({"avgSpeed": 50}))

    def test_text_with_forbidden_characters_is_cleaned(self):
        self.assertEqual(twin.to_attr("a;b (c) =d <e>")["value"], "a,b [c] :d e")

    # ---- commands into the Twin ---------------------------------------------
    def test_invalid_command_is_rejected(self):
        c = self.city()
        self.assertFalse(c.devices["us-b-alarm-01"].apply_command({"alarmState": "maybe"}))
        self.assertFalse(c.devices["us-b-alarm-01"].apply_command({"unknown": 1}))
        self.assertFalse(c.devices["us-a-traf-01"].apply_command({"phase": "green"}))   # a sensor

    def test_command_written_on_the_broker_is_applied(self):
        c = self.city()
        alarm = c.devices["us-b-alarm-01"]
        alarm.publish_state()
        alarm.poll_commands()                                   # first look = baseline
        self.assertEqual(alarm.state["alarmState"], "off")
        fake_orion.STORE["us-b-alarm-01"]["alarmState"] = {"type": "string", "value": "on"}   # the Brain writes
        alarm.poll_commands()
        self.assertEqual(alarm.state["alarmState"], "on")

    def test_platform_metadata_on_actuator_does_not_warn_or_become_a_command(self):
        alarm = self.city().devices["us-b-alarm-01"]
        response = {
            "id": alarm.id,
            "latitude": {"type": "float", "value": 41.88},
            "longitude": {"type": "float", "value": -87.63},
            "model": {"type": "string", "value": "FireAlarm"},
            "alarmState": {"type": "string", "value": "off"},
        }
        with patch.object(alarm, "fetch", return_value=response):
            with self.assertNoLogs("twin", level="WARNING"):
                alarm.poll_commands()
        self.assertEqual(alarm.state["alarmState"], "off")

    # ---- the whole loop: incident -> action -> effect --------------------------
    def test_fire_goes_out_after_alarm_and_dispatch(self):
        c = self.city()
        c.devices["us-b-bldg-01"].set_mode("fire")
        for _ in range(3):
            c.step()
            for d in c.devices.values():
                d.reading()
        c.devices["us-b-alarm-01"].apply_command({"alarmState": "on"}, source="test-brain")
        c.devices["us-b-disp-01"].apply_command({"status": "dispatched", "unitsDispatched": 2}, source="test-brain")
        for _ in range(8):
            c.step()
        self.assertEqual(c.devices["us-b-bldg-01"].mode, "normal")

    def test_fire_keeps_burning_without_action(self):
        c = self.city()
        c.devices["us-b-bldg-01"].set_mode("fire")
        for _ in range(12):
            c.step()
        self.assertEqual(c.devices["us-b-bldg-01"].mode, "fire")


class ContractTests(unittest.TestCase):
    """The data contract of the Interface Card, checked without any broker."""

    def test_valid_command_is_accepted(self):
        self.assertIsNone(schema.validate_command("light", {"phase": "green", "mode": "manual"}))

    def test_bad_value_says_what_is_allowed(self):
        msg = schema.validate_command("light", {"phase": "blue"})
        self.assertIn("bad value", msg)
        self.assertIn("red, yellow, green", msg)

    def test_unknown_attribute_is_named(self):
        msg = schema.validate_command("alarm", {"siren": "on"})
        self.assertIn("unknown attribute", msg)
        self.assertIn("alarmState", msg)

    def test_sensor_cannot_be_commanded(self):
        self.assertIn("not an actuator", schema.validate_command("traffic", {"phase": "green"}))

    def test_number_field_must_be_a_number(self):
        self.assertIn("whole number", schema.validate_command("dispatch", {"unitsDispatched": "many"}))

    def test_shipped_scenarios_match_the_shipped_config(self):
        import json
        conf = json.load(open(os.path.join(HERE, "..", "config.json")))
        scenarios.validate_scenarios(scenarios.load_scenarios(), conf)   # exits on a problem

    def test_n1_is_a_60_second_calm_day_scenario(self):
        self.assertIn("n1", scenarios.SCENARIOS)
        self.assertEqual(scenarios.SCENARIOS["n1"]["duration"], 60)

    def test_ops_summary_only_contains_city_summary_attributes(self):
        summary = model.City().ops_summary()
        self.assertEqual(
            set(summary),
            {
                "cityStatus", "devicesNormal", "devicesWarning", "devicesCritical",
                "devicesOffline", "activeAlerts", "activeAlertsText", "emergencyStatus",
                "avgCongestion", "maxSmokeLevel", "maxTemperature", "maxFillLevel",
                "lastEventTime", "lastEventMessage",
            },
        )

    def test_scenario_with_unknown_device_is_refused(self):
        conf = {"devices": {"us-a-traf-01": {"kind": "traffic", "type": "TrafficSensor"}}}
        bad = {"x": {"duration": 10, "steps": [[1, "mode", "us-z-nothing", "jam"]]}}
        with self.assertRaises(SystemExit) as cm:
            scenarios.validate_scenarios(bad, conf)
        self.assertIn("us-z-nothing", str(cm.exception))

    def test_thresholds_come_from_the_configuration(self):
        city = model.City({"traffic_warning": 10, "traffic_critical": 20})
        dev = model.Device("t", {"kind": "traffic", "type": "TrafficSensor"}, {},
                           {"orion": {"base_url": "http://x"}}, city)
        dev.last = {"congestionLevel": 25}
        level, alerts = city._alerts_for(dev)
        self.assertEqual(level, "critical")


if __name__ == "__main__":
    unittest.main()
