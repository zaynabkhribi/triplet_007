from typing import Protocol


class ForecastModel(Protocol):
    def predict(self, features: dict[str, float]) -> list[float]: ...
