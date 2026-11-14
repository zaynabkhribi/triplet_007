"""Task 7.3G-7B: async-safe passport pipeline — fully offline regression.

Chain under test:

  signed Guardian passport → awaitable eligibility refresh → immutable
  snapshot → trusted decision input → dispatch gate.

Every external boundary is mocked (Guardian passport endpoint). No real
services, database, or network. Refresh is genuinely awaited (pytest-asyncio
asyncio_mode=auto); no run_until_complete/run_coroutine_threadsafe anywhere.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest

from app.integration.guardian_passport import (
    GuardianPassportAuthorizer,
    PassportError,
)
from app.integration.ngsi_twin import SensorMapping
from app.security.event_hash import event_hash
from app.security.passport_trust import PassportEligibilityIndex
from tests.integration.test_guardian_passport import (
    TEST_PASSPORT_KEY,
    _expected_digest,
    _mapping,
    _passport_body,
    _reading,
    _settings,
    _sign,
    _signed_passport,
    _transport,
)


def _index(
    passport: dict | None,
    status: int = 200,
    mappings: list[SensorMapping] | None = None,
    **settings_overrides,
) -> PassportEligibilityIndex:
    settings = _settings(**settings_overrides)
    settings.guardian_base_url = "https://guardian.invalid"
    index = PassportEligibilityIndex(
        settings, mappings if mappings is not None else [_mapping()]
    )
    index.authorizer.transport = _transport(passport, status)
    return index


def _disabled_index() -> PassportEligibilityIndex:
    return PassportEligibilityIndex(_settings(guardian_passport_enabled=False), [])


def _candidate(event_id: int, value: float = 12.0) -> tuple[SimpleNamespace, None]:
    """A hash-valid persisted-observation double, matching the real schema."""
    reading = _reading(value)
    payload = {"event": reading.model_dump(mode="json"), "sha256": event_hash(reading)}
    return (SimpleNamespace(id=event_id, payload=payload), None)


@pytest.fixture
def entry() -> SensorMapping:
    return _mapping()


@pytest.fixture
def event_id() -> int:
    return 4242


# --------------------------------------------------------------------------
# 1. Disabled-by-default invariant: the index NEVER grants eligibility.
# --------------------------------------------------------------------------


async def test_disabled_index_never_eligible(event_id) -> None:
    index = _disabled_index()
    stats = await index.refresh([_candidate(event_id)], datetime.now(UTC))
    assert stats["evaluated"] == 0
    assert stats["eligible"] == 0
    assert index.eligible_at(event_id, datetime.now(UTC)) is False


# --------------------------------------------------------------------------
# 2. Decision-eligibility gating: valid → eligible, failures → denied.
# --------------------------------------------------------------------------


async def test_valid_passport_grants_momentary_eligibility(entry, event_id) -> None:
    index = _index(_signed_passport(_expected_digest(entry), datetime.now(UTC)))
    stats = await index.refresh([_candidate(event_id)], datetime.now(UTC))
    assert stats["eligible"] == 1, stats
    assert index.eligible_at(event_id, datetime.now(UTC)) is True


async def test_expired_passport_denies_decisions(entry, event_id) -> None:
    stale = datetime.now(UTC) - timedelta(seconds=3600)
    index = _index(_signed_passport(_expected_digest(entry), stale))
    stats = await index.refresh([_candidate(event_id)], datetime.now(UTC))
    assert stats["eligible"] == 0
    assert index.eligible_at(event_id, datetime.now(UTC)) is False


async def test_invalid_signature_denies_decisions(event_id) -> None:
    passport = _signed_passport(_expected_digest(_mapping()), datetime.now(UTC))
    passport["signature"] = "hmac-sha256:" + "1" * 64
    index = _index(passport)
    stats = await index.refresh([_candidate(event_id)], datetime.now(UTC))
    assert stats["evaluated"] == 1, "candidate must actually be evaluated"
    assert stats["eligible"] == 0 and stats["denied"] == 1
    assert index.eligible_at(event_id, datetime.now(UTC)) is False


async def test_wrong_digest_denies_decisions(event_id) -> None:
    passport = _signed_passport("sha256:" + "b" * 64, datetime.now(UTC))
    index = _index(passport)
    stats = await index.refresh([_candidate(event_id)], datetime.now(UTC))
    assert stats["eligible"] == 0 and stats["denied"] == 1
    assert index.eligible_at(event_id, datetime.now(UTC)) is False


async def test_wrong_disposition_denies_decisions(entry, event_id) -> None:
    digest = _expected_digest(_mapping())
    body = _passport_body(digest, datetime.now(UTC))
    body["disposition"] = "REJECTED"
    body["signature"] = _sign(body, TEST_PASSPORT_KEY)
    index = _index(body)
    stats = await index.refresh([_candidate(event_id)], datetime.now(UTC))
    assert stats["eligible"] == 0 and stats["denied"] == 1


async def test_guardian_unavailable_denies_decisions(event_id) -> None:
    index = _index(None)

    def handler(request):
        raise httpx.ConnectError("down")

    index.authorizer.transport = httpx.MockTransport(handler)
    stats = await index.refresh([_candidate(event_id)], datetime.now(UTC))
    assert stats["eligible"] == 0 and stats["denied"] == 1
    assert index.eligible_at(event_id, datetime.now(UTC)) is False


async def test_guardian_missing_verdict_fails_closed(event_id) -> None:
    index = _index(None, status=404)
    stats = await index.refresh([_candidate(event_id)], datetime.now(UTC))
    assert stats["eligible"] == 0
    assert index.eligible_at(event_id, datetime.now(UTC)) is False


# --------------------------------------------------------------------------
# 3. Momentary eligibility: TTL, expiry, snapshot age — nothing durable.
# --------------------------------------------------------------------------


async def test_eligibility_is_momentary_not_durable(entry, event_id) -> None:
    """Eligibility exists only while the REAL Guardian-issued TTL is valid,
    and disappears when Guardian stops cooperating."""
    index = _index(_signed_passport(_expected_digest(entry), datetime.now(UTC)))
    now = datetime.now(UTC)
    await index.refresh([_candidate(event_id)], now)
    assert index.eligible_at(event_id, now) is True
    # Beyond the passport window (ttl=6s in fixture):
    later = now + timedelta(seconds=30)
    assert index.eligible_at(event_id, later) is False
    # A later refresh requires Guardian cooperation; 404 fails closed.
    index.authorizer.transport = _transport(None, status=404)
    stats = await index.refresh([_candidate(event_id)], later)
    assert stats["eligible"] == 0
    assert index.eligible_at(event_id, later) is False


async def test_snapshot_too_old_fails_closed(entry, event_id) -> None:
    """Even an unexpired ENTRY is unusable when the snapshot itself is stale:
    eligibility must be re-derived at the consumer's instant."""
    index = _index(_signed_passport(_expected_digest(entry), datetime.now(UTC)))
    now = datetime.now(UTC)
    await index.refresh([_candidate(event_id)], now)
    stale_consumer = now + timedelta(seconds=index.max_snapshot_age_seconds + 5)
    assert index.eligible_at(event_id, stale_consumer) is False


@pytest.mark.parametrize("delay,eligible", [(3, True), (7, False)])
async def test_network_time_does_not_preexpire_reuse_or_extend_signed_ttl(
    entry, event_id, monkeypatch, delay, eligible,
):
    from app.security import passport_trust

    candidate = _candidate(event_id)
    started = datetime.now(UTC)
    receipt = started + timedelta(seconds=delay)
    clock = [started]

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock[0]

    passport = _signed_passport(_expected_digest(entry), started)
    index = _index(passport)
    index.authorizer._clock = lambda: clock[0]

    def handler(request):
        clock[0] = receipt
        return httpx.Response(200, json=passport)

    index.authorizer.transport = httpx.MockTransport(handler)
    monkeypatch.setattr(passport_trust, "datetime", Clock)
    await index.refresh([candidate], started)
    assert index.eligible_at(event_id, receipt) is eligible
    assert not index.eligible_at(event_id, receipt + timedelta(seconds=2))


async def test_failed_refresh_preserves_previous_snapshot_fail_closed(
    entry, event_id,
) -> None:
    """A Guardian outage during re-refresh must not silently grant trust:
    eligibility at the NEW instant is denied (empty/stale snapshot rules)."""
    index = _index(_signed_passport(_expected_digest(entry), datetime.now(UTC)))
    now = datetime.now(UTC)
    await index.refresh([_candidate(event_id)], now)
    assert index.eligible_at(event_id, now) is True

    def handler(request):
        raise httpx.ConnectError("down")

    index.authorizer.transport = httpx.MockTransport(handler)
    later = now + timedelta(seconds=2)
    await index.refresh([_candidate(event_id)], later)
    assert index.eligible_at(event_id, later) is False


# --------------------------------------------------------------------------
# 4. Dispatch-gate invariant: expired evidence blocks the command path.
# --------------------------------------------------------------------------


async def test_dispatch_gate_blocks_when_evidence_not_current(event_id) -> None:
    """Mirrors ActuatorManager._passport_evidence_current: an approved
    decision must be blocked from dispatch once eligibility lapses."""
    index = _index(_signed_passport(_expected_digest(_mapping()), datetime.now(UTC)))
    now = datetime.now(UTC)
    await index.refresh([_candidate(event_id)], now)
    snapshot = index.snapshot(now)

    def gate(now_arg, candidate_ids):
        return any(snapshot.eligible_at(cid, now_arg) for cid in candidate_ids)

    assert gate(now, [event_id]) is True  # dispatch would proceed
    later = now + timedelta(seconds=60)
    assert gate(later, [event_id]) is False  # dispatch MUST be blocked


async def test_no_dispatch_without_any_eligibility(event_id) -> None:
    """Universal negative: absent/invalid Guardian state → no eligibility →
    no external command path can open."""
    for index in (_index(None, status=404), _index(None, status=500)):
        await index.refresh([_candidate(event_id)], datetime.now(UTC))
        assert index.eligible_at(event_id, datetime.now(UTC)) is False


# --------------------------------------------------------------------------
# 5. Structural gates: hash binding and unknown sensors stay denied.
# --------------------------------------------------------------------------


async def test_hash_mismatch_skipped(event_id) -> None:
    index = _index(None)
    reading = _reading()
    payload = {"event": reading.model_dump(mode="json"), "sha256": "deadbeef"}
    stats = await index.refresh(
        [(SimpleNamespace(id=event_id, payload=payload), None)], datetime.now(UTC)
    )
    assert stats["skipped"] == 1
    assert index.eligible_at(event_id, datetime.now(UTC)) is False


async def test_unmapped_sensor_skipped(entry, event_id) -> None:
    index = _index(_signed_passport(_expected_digest(entry), datetime.now(UTC)))
    reading = _reading().model_copy(
        update={"attributes": {**_reading().attributes, "attribute": "unknownAttr"}}
    )
    payload = {"event": reading.model_dump(mode="json"), "sha256": event_hash(reading)}
    stats = await index.refresh(
        [(SimpleNamespace(id=event_id, payload=payload), None)], datetime.now(UTC)
    )
    assert stats["skipped"] == 1
    assert index.eligible_at(event_id, datetime.now(UTC)) is False


async def test_stale_observation_skipped(entry, event_id) -> None:
    index = _index(_signed_passport(_expected_digest(entry), datetime.now(UTC)))
    stale_event = _candidate(event_id)
    stale_event[0].payload["event"]["occurred_at"] = (
        datetime.now(UTC) - timedelta(seconds=3600)
    ).isoformat()
    stats = await index.refresh([stale_event], datetime.now(UTC))
    assert stats["skipped"] == 1


# --------------------------------------------------------------------------
# 6. Authorizer sanity at the integration boundary.
# --------------------------------------------------------------------------


async def test_authorizer_requires_enabled_flag(entry) -> None:
    authorizer = GuardianPassportAuthorizer(
        _settings(guardian_passport_enabled=False)
    )
    with pytest.raises(PassportError):
        await authorizer.authorize(_reading(), entry)
