from collections.abc import Sequence
from typing import Protocol

from app.schemas.actuator import ActuatorCommand, ActuatorFeedback
from app.schemas.guardian import GuardianVerdict
from app.schemas.sensor import SensorReading


class SensorIngestionProvider(Protocol):
    async def readings(self) -> Sequence[SensorReading]: ...


class GuardianVerificationProvider(Protocol):
    async def evaluate(self, readings: Sequence[SensorReading]) -> Sequence[GuardianVerdict]: ...


class ActuatorExecutionProvider(Protocol):
    async def deliver(self, command: ActuatorCommand) -> ActuatorFeedback: ...
