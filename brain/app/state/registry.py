from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.database.models import CityRegistryRecord
from app.database.session import Database


class SensorDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sensor_id: str = Field(min_length=1, max_length=128)
    zone_id: str = Field(min_length=1, max_length=128)
    measurement: Literal[
        "traffic", "water_level", "water_flow", "power_load", "air_quality", "temperature", "smoke"
    ]
    unit: str
    weight: float = Field(default=1, gt=0, allow_inf_nan=False)
    freshness_seconds: int = Field(default=60, ge=1)
    training_source: Literal["USGS", "METR-LA"] | None = None
    training_id: str | None = None
    training_compatible: bool = False
    training_timezone: str | None = None

    @model_validator(mode="after")
    def compatible_unit(self) -> "SensorDefinition":
        units = {
            "traffic": {"vehicles/min", "vehicles/hour", "METR-LA_native_speed"},
            "water_level": {"m", "cm", "ft"},
            "water_flow": {"cfs"},
            "power_load": {"kW", "MW"},
            "air_quality": {"ug/m3", "ppm"},
            "temperature": {"degC", "degF"},
            "smoke": {"ppm", "mg/m3"},
        }
        if self.unit not in units[self.measurement]:
            raise ValueError("incompatible measurement unit")
        return self


class Registry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    zones: list[str] = Field(default_factory=list)
    sensors: list[SensorDefinition] = Field(default_factory=list)
    window_seconds: int = Field(default=300, ge=1)
    ema_alpha: float = Field(default=0.3, gt=0, le=1)

    @model_validator(mode="after")
    def validate_assignments(self) -> "Registry":
        if len(set(self.zones)) != len(self.zones) or any(not zone for zone in self.zones):
            raise ValueError("zone IDs must be unique and nonempty")
        ids = [sensor.sensor_id for sensor in self.sensors]
        if len(set(ids)) != len(ids):
            raise ValueError("sensor IDs must be unique")
        if any(sensor.zone_id not in self.zones for sensor in self.sensors):
            raise ValueError("sensor references unknown zone")
        return self


def load_registry(database: Database, path: str | None) -> None:
    with database.transaction() as session:
        existing = session.get(CityRegistryRecord, 1)
        if path is not None:
            config = Registry.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
            session.merge(CityRegistryRecord(id=1, payload=config.model_dump()))
        elif existing is None:
            session.add(CityRegistryRecord(id=1, payload=Registry().model_dump()))
