from datetime import datetime
from enum import StrEnum
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class IncidentSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CityIncident(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: UUID
    correlation_id: UUID
    schema_version: Annotated[str, Field(pattern=r"^1\.\d+\.\d+$")] = "1.0.0"
    detected_at: datetime
    incident_type: Annotated[str, Field(min_length=1, max_length=64)]
    severity: IncidentSeverity
    summary: Annotated[str, Field(min_length=1, max_length=512)]
    source_event_ids: list[UUID] = Field(min_length=1)
