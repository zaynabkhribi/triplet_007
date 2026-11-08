from typing import Protocol

from app.integration.orion_adapter import Delivery
from app.schemas.actuator import ActuatorCommand, ActuatorFeedback


class CommandGateway(Protocol):
    async def deliver(self, command: ActuatorCommand) -> Delivery | ActuatorFeedback: ...
