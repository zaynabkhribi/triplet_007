import asyncio
from collections.abc import Hashable


class InMemoryReplayProtector:
    def __init__(self, capacity: int = 10_000) -> None:
        self._capacity = capacity
        self._seen: set[Hashable] = set()
        self._lock = asyncio.Lock()

    async def accept(self, event_id: Hashable) -> bool:
        async with self._lock:
            if event_id in self._seen:
                return False
            if len(self._seen) >= self._capacity:
                self._seen.clear()
            self._seen.add(event_id)
            return True
