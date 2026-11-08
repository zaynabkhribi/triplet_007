from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.schemas.sensor import SensorReading


def valid_reading() -> dict[str, object]:
    return {
        "event_id": uuid4(),
        "correlation_id": uuid4(),
        "occurred_at": datetime.now(UTC),
        "sensor_id": "traffic-001",
        "sensor_type": "traffic_flow",
        "value": 12.5,
        "unit": "vehicles_per_minute",
    }


def test_sensor_reading_accepts_valid_data() -> None:
    reading = SensorReading.model_validate(valid_reading())
    assert reading.schema_version == "1.0.0"


def test_sensor_reading_rejects_unknown_fields() -> None:
    data = valid_reading()
    data["unexpected"] = True
    with pytest.raises(ValidationError):
        SensorReading.model_validate(data)


def test_sensor_reading_rejects_naive_timestamp() -> None:
    data = valid_reading()
    data["occurred_at"] = datetime.now()
    with pytest.raises(ValidationError):
        SensorReading.model_validate(data)
