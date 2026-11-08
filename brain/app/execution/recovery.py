from typing import Protocol

from app.schemas.actuator import ActuatorFeedback


class RecoveryStrategy(Protocol):
    async def recover(self, feedback: ActuatorFeedback) -> None: ...
