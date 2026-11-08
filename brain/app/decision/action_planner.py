from typing import Protocol

from app.schemas.actuator import ActuatorCommand
from app.schemas.decision import BrainDecision


class ActionPlanner(Protocol):
    def plan(self, decision: BrainDecision) -> list[ActuatorCommand]: ...
