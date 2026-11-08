import json
from datetime import UTC, datetime
from enum import Enum
from typing import Literal, get_args
from uuid import UUID

from pydantic import BaseModel, ConfigDict, ValidationInfo, field_validator, model_validator


class WireEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)
    schema_version: Literal["1.0.0"] = "1.0.0"

    @model_validator(mode="after")
    def validate_json(self) -> "WireEvent":
        json.dumps(self.model_dump(mode="json"), allow_nan=False)
        return self

    @field_validator("*", mode="before")
    @classmethod
    def parse_wire_types(cls, value: object, info: ValidationInfo) -> object:
        annotation = cls.model_fields[info.field_name].annotation
        if isinstance(value, str):
            if annotation is UUID:
                return UUID(value)
            if annotation is datetime or datetime in get_args(annotation):
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            if isinstance(annotation, type) and issubclass(annotation, Enum):
                return annotation(value)
        return value

    @field_validator("*")
    @classmethod
    def normalize_timestamp(cls, value: object) -> object:
        if isinstance(value, datetime):
            if value.utcoffset() is None:
                raise ValueError("timestamp must include a timezone")
            return value.astimezone(UTC)
        return value
