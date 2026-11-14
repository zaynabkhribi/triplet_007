"""Task 7.3G-7B: async-safe passport eligibility bridge (corrected design).

The 7.3G-7 draft attempted ``loop.run_until_complete()`` inside the
synchronous ``CityEngine.rebuild()`` path — fundamentally broken under a
running asyncio loop (FastAPI/uvicorn or pytest-asyncio): you cannot block on
a loop that is already executing. That defect is fixed here, not patched in
tests.

Corrected architecture (async evidence collection / sync state rebuilding):

* ``PassportEligibilityIndex.refresh()`` is a coroutine (``await`` on Guardian
  HTTP). It clears old eligibility before collecting evidence, then swaps in
  a fully derived replacement. Errors/cancellation cannot retain old grants.
* Synchronous consumers (``CityEngine.rebuild``, dispatch gate,
  ``currently_eligible``) read ONLY the immutable snapshot via
  ``eligible_at(event_id, now)`` — no blocking calls anywhere.
* Production orchestration: async call sites that own an event loop refresh
  eligibility BEFORE entering the synchronous rebuild:
    - ``app/api/decisions.py::evaluate`` awaits
      ``refresh_for_decision(session, city, now)`` then runs the sync
      rebuild+decision in a worker thread;
    - ``ActuatorManager.tick`` (already async) awaits ``refresh_for_dispatch``
      before ``_claim``.
  Snapshot currency is enforced by binding each snapshot to the instant it
  was derived; ``eligible_at`` compares against ``now`` and rejects stale
  snapshots outright (``max_snapshot_age_seconds``).

Security semantics preserved from 7.3G-6/7:

* NEVER creates GuardianVerdict records; NO fabricated revisions or
  revocations; quarantine never bypassed (structural gates run first and the
  caller's quarantine checks remain authoritative).
* Signature verification against a provisioned non-default HMAC key; digest
  recomputed FROM the persisted observation; TRUSTED disposition only;
  Guardian's TTL enforced exactly, never extended.
* Disabled by default; dev/test environments only.

Explicit Guardian security limitations (verified from source, unchanged):

1. A passport is signed from Guardian's IN-MEMORY ``_verdicts`` cache — the
   trust assessment may be OLDER than the signature TTL. Brain therefore
   treats the TTL as an authorization-freshness bound ONLY, never as
   evidence recency.
2. Reissuance (POST /v1/passport) extends eligibility without a new Guardian
   evaluation while the cached verdict lives. Bounded here by mandatory
   re-fetch per decision/dispatch instant and the snapshot age limit, but
   this is NOT equivalent to re-evaluation.
3. Quarantine state is not queryable per-request; Brain's own quarantine
   gates remain authoritative, but Guardian-side quarantine changes are only
   observed indirectly.
If these guarantees are insufficient for a deployment, the feature stays
disabled and observations remain untrusted — fail closed.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx

from app.integration.guardian_passport import GuardianPassportAuthorizer
from app.integration.ngsi_twin import SensorMapping
from app.schemas.sensor import SensorReading
from app.security.event_hash import event_hash


def supplements_missing_verdict(result) -> bool:
    """Native passports never override a rejection, revocation or quarantine."""
    return result.reason in {"awaiting_guardian", "verdict_missing"}


@dataclass(frozen=True)
class EligibilitySnapshot:
    """Immutable eligibility state for ONE refresh instant.

    ``derived_at`` bounds snapshot reuse: consumers reject snapshots older
    than ``max_snapshot_age_seconds`` even if individual entries have not
    expired, so eligibility can never silently outlive its evidence cycle.
    """

    derived_at: datetime
    expiry_by_event: dict[object, datetime] = field(default_factory=dict)
    completed_at: datetime | None = None

    def eligible_at(self, event_id: object, now: datetime) -> bool:
        expiry = self.expiry_by_event.get(event_id)
        return expiry is not None and now < expiry


class PassportEligibilityIndex:
    """Async-refreshed, snapshot-consumed eligibility (no blocking anywhere)."""

    def __init__(
        self,
        settings: object,
        mappings: list[SensorMapping],
        max_snapshot_age_seconds: float = 2.0,
    ) -> None:
        self.enabled = bool(getattr(settings, "guardian_passport_enabled", False))
        self.authorizer = GuardianPassportAuthorizer(settings)
        self.by_sensor_attribute: dict[tuple[str, str], SensorMapping] = {
            (m.sensor_id, m.attribute): m for m in mappings
        }
        self.max_snapshot_age_seconds = max_snapshot_age_seconds
        self._refresh_lock = asyncio.Lock()
        self._snapshot = EligibilitySnapshot(
            derived_at=datetime(1970, 1, 1, tzinfo=UTC)
        )

    # -- consumption (SYNC, non-blocking) ------------------------------------

    def snapshot(self, now: datetime) -> EligibilitySnapshot:
        """Current snapshot, or an EMPTY one if it is too old (fail closed)."""
        age = (now - (self._snapshot.completed_at or self._snapshot.derived_at)).total_seconds()
        if now < self._snapshot.derived_at or age > self.max_snapshot_age_seconds:
            return EligibilitySnapshot(derived_at=self._snapshot.derived_at)
        return self._snapshot

    def eligible_at(self, event_id: object, now: datetime) -> bool:
        """True only if THIS event was passport-authorized at THIS instant.

        When disabled this is always False — the feature cannot grant
        anything it never evaluated.
        """
        if not self.enabled:
            return False
        return self.snapshot(now).eligible_at(event_id, now)

    def now(self) -> datetime:
        """Return the authorization clock used for Passport freshness checks."""
        return self.authorizer._clock()

    # -- refresh (ASYNC) ------------------------------------------------------

    async def refresh(
        self,
        candidates: list[tuple[object, object]],
        now: datetime,
    ) -> dict[str, int]:
        async with self._refresh_lock:
            return await self._refresh(candidates, now)

    async def _refresh(
        self,
        candidates: list[tuple[object, object]],
        now: datetime,
    ) -> dict[str, int]:
        """Re-derive eligibility for the given (SensorEvent, lifecycle) rows.

        Awaits real Guardian passport fetches. The resulting snapshot is
        swapped in atomically at the END of a fully successful pass. Old
        eligibility is cleared at entry; an interrupted pass stays closed.

        Statistics (returned, not swallowed):
          evaluated  – candidates that passed structural gates
          eligible   – passport-authorized
          denied     – authorization refused (signature/digest/expiry/404…)
          skipped    – malformed hash binding, unmapped sensor, stale event
        """
        stats = {"evaluated": 0, "eligible": 0, "denied": 0, "skipped": 0}
        self.clear()
        if not self.enabled:
            return stats

        authorizations = []
        semaphore = asyncio.Semaphore(8)

        async def authorize(reading, mapping):
            async with semaphore:
                result = await self.authorizer.authorize(reading, mapping, now, client=client)
                # Start local reuse at validation receipt, not before HTTP latency.
                # Each entry still expires at its own TTL/evidence/reuse deadline.
                checked_at = result.authorized_at
                return min(
                    result.expires_at,
                    checked_at + timedelta(seconds=self.max_snapshot_age_seconds),
                )
        identities: list[object] = []
        for event, _candidate_lifecycle in candidates:
            payload = getattr(event, "payload", None) or {}
            try:
                reading = SensorReading.model_validate(payload["event"])
            except Exception:  # noqa: BLE001 - malformed rows stay untrusted
                stats["skipped"] += 1
                continue
            # Structural gates mirroring TrustEngine/city-engine semantics.
            if event_hash(reading) != payload.get("sha256"):
                stats["skipped"] += 1
                continue
            age = (now - reading.occurred_at).total_seconds()
            if age < 0:
                stats["skipped"] += 1
                continue
            mapping = self.by_sensor_attribute.get(
                (reading.sensor_id, reading.attributes.get("attribute", ""))
            )
            if mapping is None:
                stats["skipped"] += 1
                continue
            stats["evaluated"] += 1
            authorizations.append(authorize(reading, mapping))
            identities.append(event.id)

        expiry_by_event: dict[object, datetime] = {}
        if authorizations:
            async with httpx.AsyncClient(
                transport=self.authorizer.transport, trust_env=False, timeout=5.0
            ) as client:
                outcomes = await asyncio.gather(*authorizations, return_exceptions=True)
            for event_id, outcome in zip(identities, outcomes, strict=False):
                if isinstance(outcome, BaseException):
                    # Fail closed: PassportError paths (signature, digest,
                    # expiry, 404, unavailability) deny that candidate.
                    stats["denied"] += 1
                    continue
                expiry_by_event[event_id] = outcome
                stats["eligible"] += 1

        # Atomic swap: fully-derived snapshot replaces the old one.
        self._snapshot = EligibilitySnapshot(
            derived_at=now, expiry_by_event=expiry_by_event,
            completed_at=max(now, self.now()),
        )
        return stats

    def clear(self) -> None:
        self._snapshot = EligibilitySnapshot(
            derived_at=datetime(1970, 1, 1, tzinfo=UTC)
        )


async def refresh_for_rebuild(
    index: PassportEligibilityIndex,
    candidates: list[tuple[object, object]],
    now: datetime,
) -> None:
    """Refresh eligibility inside an ASYNC caller before a sync rebuild."""
    await index.refresh(candidates, now)


async def refresh_for_decision(
    index: PassportEligibilityIndex,
    candidates: list[tuple[object, object]],
    now: datetime,
) -> None:
    """Decision-evaluation refresh (same contract as rebuild refresh)."""
    await index.refresh(candidates, now)
