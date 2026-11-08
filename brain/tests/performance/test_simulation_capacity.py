import pytest

from scripts.run_simulation_load import measure


@pytest.mark.parametrize("sensor_count", [10, 50, 100])
async def test_progressive_simulation_capacity(sensor_count: int) -> None:
    result = await measure(sensor_count, 1)
    assert result["events"] == sensor_count
    assert result["guardian_accepted"] == sensor_count
    assert result["guardian_rejected"] == 0
    assert result["throughput_events_per_second"] > 0
    assert result["latency_p95_ms"] >= result["latency_p50_ms"] > 0
    assert result["backlog_max"] == 0
    assert result["errors"] == 0
