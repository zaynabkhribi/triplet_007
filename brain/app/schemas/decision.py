from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class DecisionStatus(StrEnum):
    PROPOSED = "proposed"
    AUTHORIZED = "authorized"
    REJECTED = "rejected"


class BrainDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_id: UUID
    correlation_id: UUID
    schema_version: Annotated[str, Field(pattern=r"^1\.\d+\.\d+$")] = "1.0.0"
    created_at: datetime
    incident_id: UUID | None = None
    status: DecisionStatus
    action_type: Annotated[str, Field(min_length=1, max_length=64)]
    rationale: Annotated[str, Field(min_length=1, max_length=1024)]
    parameters: dict[str, Any] = Field(default_factory=dict)
