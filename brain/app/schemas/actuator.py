from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any
from uuid import UUID

from pydantic import Field, model_validator

from app.schemas.base import WireEvent


class ActuatorCommand(WireEvent):
    command_id: UUID
    decision_id: UUID
    correlation_id: UUID
    issued_at: datetime
    actuator_id: Annotated[str, Field(min_length=1, max_length=128)]
    action: Annotated[str, Field(min_length=1, max_length=64)]
    parameters: dict[str, Any] = Field(default_factory=dict)
    expires_at: datetime

    @model_validator(mode="after")
    def validate_expiry(self) -> "ActuatorCommand":
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must follow issued_at")
        return self


class FeedbackStatus(StrEnum):
    ACCEPTED = "accepted"
    EXECUTED = "executed"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ActuatorFeedback(WireEvent):
    feedback_id: UUID
    command_id: UUID
    correlation_id: UUID
    occurred_at: datetime
    status: FeedbackStatus
    detail: Annotated[str, Field(max_length=512)] = ""
