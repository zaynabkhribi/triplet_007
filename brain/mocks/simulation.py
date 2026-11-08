import random


class TwinTimeSeries:
    def __init__(self, scenario_id: str, seed: int) -> None:
        self.scenario_id = scenario_id
        self.random = random.Random(f"{seed}:{scenario_id}")
        self.tick = 0

    def primary_values(self, maximum: int) -> list[float]:
        profiles = {
            "traffic_congestion": [55, 53, 49, 44, 37, 30, 23, 18, 14, 10],
            "building_fire": [0.2, 0.3, 0.5, 1, 3, 7, 12, 18, 25, 30],
            "rapid_water_rise": [1, 1.02, 1.08, 1.2, 1.5, 2, 2.8, 3.8, 5, 6.2],
            "power_overload": [4, 5, 6, 7, 9, 12, 16, 20, 24, 28],
            "untrusted_sensor": [5, 8, 12, 18, 25, 30, 35, 40],
            "sensor_quarantine": [5, 8, 12, 18, 25, 30, 35, 40],
        }
        if self.scenario_id == "normal_city":
            return [0.25 + self.random.uniform(-0.08, 0.08) for _ in range(maximum)]
        if self.scenario_id == "city_under_pressure":
            count = min(maximum, 90)
            return [
                0.25
                if tick < 25
                else min(30.0, 0.25 + (tick - 24) * 0.7)
                for tick in range(count)
            ]
        return profiles.get(self.scenario_id, [0.2, 0.4, 1, 3, 8, 14, 20, 25, 30, 32])

    def measurements(self, primary_measurement: str, primary: float) -> dict[str, float]:
        values = {
            "traffic": 52 + self.random.uniform(-2, 2),
            "smoke": max(0, 0.25 + self.random.uniform(-0.08, 0.08)),
            "temperature": 22 + self.random.uniform(-0.5, 0.5),
            "water_level": 1 + self.random.uniform(-0.03, 0.03),
            "power_load": 5 + self.random.uniform(-0.3, 0.3),
            "air_quality": 18 + self.random.uniform(-2, 2),
        }
        values[primary_measurement] = primary
        if self.scenario_id == "city_under_pressure":
            progress = max(0.0, min(1.0, (self.tick - 24) / 35))
            values.update(
                {
                    "traffic": 54 - 44 * progress + self.random.uniform(-0.8, 0.8),
                    "smoke": max(0.0, 0.25 + 24 * progress),
                    "temperature": 22 + 38 * progress,
                    "water_level": 1 + 3.5 * progress,
                    "power_load": 5 + 23 * progress,
                    "air_quality": 18 + 62 * progress,
                }
            )
            values[primary_measurement] = primary
            self.tick += 1
        if primary_measurement == "smoke":
            values["temperature"] = 22 + primary * 1.6
        return values
