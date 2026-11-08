import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Annotated

import yaml
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from app.intelligence.incident_rules import SEVERITIES

Amount = Annotated[int, Field(ge=0, le=1_000_000, strict=True)]
Demand = Annotated[int, Field(gt=0, le=1_000_000, strict=True)]


def digest(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class ParameterRange(StrictModel):
    minimum: float
    maximum: float

    @model_validator(mode="after")
    def ordered(self) -> "ParameterRange":
        if self.minimum > self.maximum:
            raise ValueError("invalid capability range")
        return self


class Availability(StrictModel):
    observed_at: AwareDatetime
    valid_until: AwareDatetime
    available: bool = False

    def current(self, now: datetime) -> bool:
        return self.available and self.observed_at <= now < self.valid_until

    @model_validator(mode="after")
    def ordered(self) -> "Availability":
        if self.observed_at >= self.valid_until:
            raise ValueError("invalid availability interval")
        return self


class Resource(Availability):
    capacity: Amount
    zones: list[str] = Field(min_length=1)


class Actuator(Availability):
    zone: str = Field(min_length=1)
    capabilities: dict[str, dict[str, ParameterRange]] = Field(min_length=1)


class ActionPolicy(StrictModel):
    id: str = Field(min_length=1, max_length=128)
    incident_types: list[str] = Field(min_length=1)
    zones: list[str] = Field(min_length=1)
    minimum_severity: str
    action_type: str = Field(min_length=1, max_length=64)
    actuator_id: str = Field(min_length=1, max_length=128)
    parameters: dict[str, float] = Field(default_factory=dict)
    resources: dict[str, Demand] = Field(default_factory=dict)
    conflicts: list[str] = Field(default_factory=list)
    cost: Amount
    benefit: Demand
    safety_critical: bool = True
    requires_approval: bool = True
    allow_forecast_warning: bool = False
    idempotent: bool = False

    @model_validator(mode="after")
    def safe(self) -> "ActionPolicy":
        if self.minimum_severity not in SEVERITIES:
            raise ValueError("unknown minimum severity")
        if self.safety_critical and not self.requires_approval:
            raise ValueError("safety-critical actions require explicit approval")
        return self


class Optimization(StrictModel):
    max_actions: int = Field(default=0, ge=0, le=256)
    max_candidates: int = Field(default=128, ge=1, le=256)
    timeout_seconds: float = Field(default=1, gt=0, le=10)
    severity_weights: dict[str, Amount] = Field(default_factory=dict)
    urgency_weights: dict[str, Amount] = Field(default_factory=dict)
    zone_weights: dict[str, Amount] = Field(default_factory=dict)
    cost_weight: Amount = 1


class DecisionPolicies(StrictModel):
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    simulation_only: bool = True
    approved: bool = False
    approval_reference: str = ""
    approved_incident_config_sha256: str = ""
    resources: dict[str, Resource] = Field(default_factory=dict)
    actuators: dict[str, Actuator] = Field(default_factory=dict)
    actions: list[ActionPolicy] = Field(default_factory=list)
    optimization: Optimization = Field(default_factory=Optimization)

    @model_validator(mode="after")
    def consistent(self) -> "DecisionPolicies":
        ids = {action.id for action in self.actions}
        if len(ids) != len(self.actions):
            raise ValueError("duplicate policy IDs")
        for action in self.actions:
            if action.actuator_id not in self.actuators:
                raise ValueError("unknown actuator")
            if not set(action.resources) <= self.resources.keys():
                raise ValueError("unknown resource")
            if not set(action.conflicts) <= ids:
                raise ValueError("unknown conflicting policy")
        return self


def load_policy(path: str | None) -> tuple[DecisionPolicies | None, str | None]:
    if not path:
        return None, "policy_not_configured"
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return DecisionPolicies.model_validate(data), None
    except (OSError, ValueError, yaml.YAMLError):
        return None, "policy_invalid_or_missing"
