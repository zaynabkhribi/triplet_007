from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from pydantic import Field, field_validator

from app.schemas.base import WireEvent


class SensorReading(WireEvent):
    event_id: UUID
    correlation_id: UUID
    occurred_at: datetime
    sensor_id: Annotated[str, Field(min_length=1, max_length=128)]
    sensor_type: Annotated[str, Field(min_length=1, max_length=64)]
    value: float
    unit: Annotated[str, Field(min_length=1, max_length=32)]
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("occurred_at")
    @classmethod
    def timestamp_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        return value
