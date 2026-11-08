"""Dedup / anti-replay window semantics (plan §6.1 Stage A, §7.4 idempotency).

REGRESSION: eviction was gated behind `len(_seen) < 1024`, so below that size nothing
ever expired — the documented `window_s` window was inert and the map grew unbounded.
"""
import time

from guardian.dedup import SeenSet


def test_entry_expires_after_the_window():
    ss = SeenSet(window_s=1)
    ss.add("k")
    assert ss.seen_before("k") is True
    time.sleep(1.2)
    assert ss.seen_before("k") is False, "entry outlived its window"


def test_window_is_short_circuited_only_at_capacity():
    ss = SeenSet(window_s=60)
    for i in range(2000):
        ss.add(f"k{i}")
    assert len(ss) == 2000
    assert ss.seen_before("k0") is True
    assert ss.seen_before("never-added") is False


def test_hard_cap_bounds_memory():
    ss = SeenSet(window_s=3600)
    for i in range(SeenSet._MAX_ENTRIES + 500):
        ss.add(f"k{i}")
    assert len(ss) <= SeenSet._MAX_ENTRIES, "map must stay bounded under a flood of ids"


def test_duplicates_within_window_are_blocked():
    ss = SeenSet(window_s=60)
    ss.add("dup")
    assert ss.seen_before("dup") is True
    assert ss.seen_before("dup") is True