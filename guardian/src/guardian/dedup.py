"""In-memory anti-replay / dedup window (plan §6.1 Stage A, §7.4 idempotency).

Keys are reading_id (or a digest-derived id). The window is cleared only at an
explicit run boundary (`Pipeline.reset_run`), which is what makes a scenario
replayable on a long-running server without a mid-run replay ever being accepted.
"""
from __future__ import annotations

import time
from typing import Dict


class SeenSet:
    def __init__(self, window_s: int = 60) -> None:
        self.window_s = window_s
        self._seen: Dict[str, float] = {}

    # Hard cap so a flood of unique ids cannot grow the map without bound. The
    # time window below is what normally evicts; this is only a safety valve.
    _MAX_ENTRIES = 8192

    def _evict(self, now: float) -> None:
        if len(self._seen) > self._MAX_ENTRIES:
            self._seen.clear()
        stale = [k for k, t in self._seen.items() if now - t > self.window_s]
        for k in stale:
            self._seen.pop(k, None)

    def seen_before(self, key: str) -> bool:
        now = time.time()
        self._evict(now)
        return key in self._seen

    def add(self, key: str) -> None:
        now = time.time()
        self._seen[key] = now
        self._evict(now)

    def clear(self) -> None:
        """Drop every key. Used at a run boundary only — never mid-run."""
        self._seen.clear()

    def __len__(self) -> int:
        return len(self._seen)
