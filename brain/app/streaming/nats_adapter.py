from collections.abc import Awaitable, Callable
from typing import Protocol


class JetStreamMessage(Protocol):
    data: bytes

    async def ack(self) -> None: ...
    async def nak(self) -> None: ...


class NatsAdapter:
    def __init__(self, durable_ingest: Callable[[bytes], Awaitable[None]]) -> None:
        self.durable_ingest = durable_ingest

    async def handle(self, message: JetStreamMessage) -> None:
        try:
            await self.durable_ingest(message.data)
        except Exception:
            await message.nak()
            raise
        await message.ack()
