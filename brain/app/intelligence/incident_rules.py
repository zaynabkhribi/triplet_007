from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.state.registry import SensorDefinition

Severity = Literal["low", "medium", "high", "critical"]
SEVERITIES = ("low", "medium", "high", "critical")


class IncidentRule(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    id: str = Field(min_length=1, max_length=128)
    incident_type: Literal[
        "traffic_congestion",
        "traffic_speed_drop",
        "rapid_water_rise",
        "high_water",
        "abnormal_power_load",
        "power_overload",
        "air_pollution",
        "abnormal_temperature",
        "smoke_alert",
    ]
    measurement: str
    unit: str
    source: Literal["observations", "forecast"] = "observations"
    mode: Literal["above", "below", "rise", "fall"] = "above"
    thresholds: dict[Severity, float] = Field(min_length=1)
    zones: list[str] = Field(default_factory=list)
    window_seconds: int = Field(default=300, ge=1)
    persistence_seconds: int = Field(default=30, ge=0)
    min_samples: int = Field(default=2, ge=1)
    min_sensors: int = Field(default=1, ge=1)
    correlation_seconds: int = Field(default=30, ge=0)
    max_gap_seconds: int = Field(default=60, ge=1)
    recovery_seconds: int = Field(default=30, ge=0)
    recovery_samples: int = Field(default=2, ge=1)
    cooldown_seconds: int = Field(default=60, ge=0)
    forecast_max_age_seconds: int = Field(default=300, ge=1)
    forecast_max_horizon_minutes: int = Field(default=360, ge=1)

    @model_validator(mode="after")
    def compatible(self) -> "IncidentRule":
        SensorDefinition(
            sensor_id="validation",
            zone_id="validation",
            measurement=self.measurement,
            unit=self.unit,
        )
        expected = {
            "traffic_congestion": "traffic",
            "traffic_speed_drop": "traffic",
            "rapid_water_rise": "water_level",
            "high_water": "water_level",
            "abnormal_power_load": "power_load",
            "power_overload": "power_load",
            "air_pollution": "air_quality",
            "abnormal_temperature": "temperature",
            "smoke_alert": "smoke",
        }
        if self.measurement != expected[self.incident_type]:
            raise ValueError("incident type and measurement mismatch")
        if self.measurement == "traffic" and self.unit != "METR-LA_native_speed":
            raise ValueError("traffic detection requires compatible speed measurements")
        if self.source == "forecast" and (
            self.measurement not in {"traffic", "water_level"}
            or self.mode not in {"above", "below"}
        ):
            raise ValueError("forecast rules support traffic/water absolute thresholds only")
        if max(self.persistence_seconds, self.recovery_seconds) > self.window_seconds:
            raise ValueError("persistence or recovery exceeds history window")
        required_modes = {
            "traffic_congestion": "below",
            "traffic_speed_drop": "fall",
            "rapid_water_rise": "rise",
            "high_water": "above",
            "power_overload": "above",
            "air_pollution": "above",
            "smoke_alert": "above",
        }
        if self.incident_type in required_modes and self.mode != required_modes[self.incident_type]:
            raise ValueError("incident classification does not match rule direction")
        if self.source == "forecast" and (self.min_samples != 1 or self.persistence_seconds != 0):
            raise ValueError(
                "forecast warnings require one validated forecast, not observation persistence"
            )
        values = [self.thresholds[s] for s in SEVERITIES if s in self.thresholds]
        reverse = self.mode == "below"
        if values != sorted(set(values), reverse=reverse):
            raise ValueError("severity thresholds must increase in anomaly magnitude")
        if self.mode in {"rise", "fall"} and any(value < 0 for value in values):
            raise ValueError("rate thresholds must be nonnegative magnitudes per second")
        return self

    def severity(self, value: float) -> str | None:
        matches = [
            s
            for s in SEVERITIES
            if s in self.thresholds
            and (
                value <= self.thresholds[s] if self.mode == "below" else value >= self.thresholds[s]
            )
        ]
        return matches[-1] if matches else None


class IncidentRules(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    simulation_only: bool = True
    rules: list[IncidentRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_ids(self) -> "IncidentRules":
        if len({rule.id for rule in self.rules}) != len(self.rules):
            raise ValueError("duplicate incident rule IDs")
        return self


def load_rules(path: str | None, environment: str) -> IncidentRules:
    rules = IncidentRules.model_validate(
        yaml.safe_load(Path(path).read_text(encoding="utf-8")) if path else {"version": "1.0.0"}
    )
    if environment.lower() == "production" and rules.simulation_only and rules.rules:
        raise ValueError("simulation incident rules cannot run in production")
    return rules
