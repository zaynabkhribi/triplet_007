import asyncio


class EventBuffer:
    def __init__(self, capacity: int = 1000) -> None:
        self._queue: asyncio.Queue[object] = asyncio.Queue(maxsize=capacity)

    async def put(self, event: object) -> None:
        await self._queue.put(event)

    async def get(self) -> object:
        return await self._queue.get()
