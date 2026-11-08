from app.intelligence.forecasting import ForecastModel


class ModelRegistry:
    def __init__(self) -> None:
        self._models: dict[str, ForecastModel] = {}

    def register(self, name: str, model: ForecastModel) -> None:
        self._models[name] = model

    def get(self, name: str) -> ForecastModel:
        try:
            return self._models[name]
        except KeyError as exc:
            raise LookupError(f"model not registered: {name}") from exc
