from typing import Any, Protocol


class FeatureEngineer(Protocol):
    def transform(self, state: dict[str, Any]) -> dict[str, float]: ...
