from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class CityState:
    updated_at: datetime
    values: dict[str, Any] = field(default_factory=dict)
