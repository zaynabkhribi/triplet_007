from mocks.simulation import TwinTimeSeries


def test_twin_time_series_is_seeded_changing_and_bounded() -> None:
    first = TwinTimeSeries("normal_city", 42)
    second = TwinTimeSeries("normal_city", 42)
    values = first.primary_values(20)
    assert values == second.primary_values(20)
    assert len(set(values)) > 1
    assert all(0 <= value <= 1 for value in values)

    measurements = first.measurements("smoke", 25)
    assert measurements["smoke"] == 25
    assert measurements["temperature"] == 62
    assert 0 <= measurements["air_quality"] <= 100


def test_city_under_pressure_is_reproducible_and_progressive() -> None:
    first = TwinTimeSeries("city_under_pressure", 2026)
    second = TwinTimeSeries("city_under_pressure", 2026)
    assert first.primary_values(180) == second.primary_values(180)
    baseline = first.measurements("smoke", 0.25)
    for _ in range(120):
        pressured = first.measurements("smoke", 20)
    assert pressured["traffic"] < baseline["traffic"]
    assert pressured["power_load"] > baseline["power_load"]
    assert pressured["water_level"] > baseline["water_level"]
    assert 0 <= pressured["smoke"] <= 30
