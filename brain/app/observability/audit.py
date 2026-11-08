from typing import Any, Protocol


class AuditSink(Protocol):
    async def record(self, action: str, context: dict[str, Any]) -> None: ...
