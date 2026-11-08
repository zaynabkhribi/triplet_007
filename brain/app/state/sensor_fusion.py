from app.schemas.sensor import SensorReading


class SensorFusion:
    def fuse(self, readings: list[SensorReading]) -> dict[str, float]:
        return {reading.sensor_id: reading.value for reading in readings}
