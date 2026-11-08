from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, model_validator

from app.schemas.base import WireEvent


class TrustStatus(StrEnum):
    TRUSTED = "trusted"
    REJECTED = "rejected"
    UNKNOWN = "unknown"
    REVOKED = "revoked"


class GuardianVerdict(WireEvent):
    verdict_id: UUID
    event_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    event_id: UUID
    correlation_id: UUID
    issued_at: datetime
    status: TrustStatus
    reason_code: Annotated[str, Field(min_length=1, max_length=64)]
    guardian_id: Annotated[str, Field(min_length=1, max_length=128)]
    revision: Annotated[int, Field(ge=0)] = 0
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def validate_expiry(self) -> "GuardianVerdict":
        if self.expires_at is not None and self.expires_at <= self.issued_at:
            raise ValueError("expires_at must follow issued_at")
        return self


class QuarantineNotification(WireEvent):
    notification_id: UUID
    correlation_id: UUID
    guardian_id: Annotated[str, Field(min_length=1, max_length=128)]
    issued_at: datetime
    target_type: Literal["sensor", "actuator"]
    target_id: Annotated[str, Field(min_length=1, max_length=128)]
    action: Literal["quarantine", "release"]
    revision: Annotated[int, Field(ge=0)]
    reason_code: Annotated[str, Field(min_length=1, max_length=64)]
