from collections import Counter


class Metrics:
    def __init__(self) -> None:
        self._counters: Counter[str] = Counter()

    def increment(self, name: str) -> None:
        self._counters[name] += 1

    def value(self, name: str) -> int:
        return self._counters[name]
