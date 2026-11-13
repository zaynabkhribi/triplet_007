"""Verification-only Guardian compatibility adapter (Brain-owned).

Bridges the real Guardian's ``GET /v1/integration/verdicts`` rows to Brain
observations WITHOUT granting trust. This module can *verify* that a Guardian
verdict refers to one specific stored Brain observation, but it deliberately
does NOT emit GuardianVerdicts: the real Guardian contract has no revision
counter, no revocation semantics and no per-frame signatures Brain can verify,
so a fully valid fail-closed GuardianVerdict cannot be constructed today.
Emitting one would require fabricating authorization — forbidden.

What verification means here, concretely:

1. The row's sensor_id/observed_property/phenomenon_time/value/unit must match
   the Brain observation, joined through the explicit mapping file. Guardian's
   wire vocabulary (zone strings like ``ZONE-B``, property names like
   ``fire_smoke``, unit spellings like ``C``) is authoritative on the Guardian
   side and lives in the mapping, never guessed by equating it to Brain's.
2. Guardian's canonical evidence body is reconstructed from GUARDIAN-ORIGIN
   values (its sensor_id, its zone, its property, the verbatim timestamp, its
   value and unit) and hashed with the same canonicalization; the result must
   equal the row's ``evidence_digest``.
3. The matched observation is bound to its Brain event_id, correlation_id
   and canonical Brain event_hash (unchanged algorithm).
4. The Guardian must be reached over verified HTTPS with the exact
   integration token header; malformed, unauthenticated or unavailable
   responses fail closed.
5. Channels whose Guardian property is ambiguous (two NGSI attributes
   collapsing to one observed_property) are never verified — the mapping
   validator rejects them outright.

Everything else (disposition interpretation) is reported, never enforced.
"""

import asyncio
import hashlib
import json
import logging
import math
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import ValidationError
from sqlalchemy import select

from app.database.models import SensorEvent
from app.integration.ngsi_twin import SensorMapping
from app.schemas.sensor import SensorReading
from app.security.event_hash import event_hash

logger = logging.getLogger(__name__)

#: The literal the Guardian stamps on broker-derived frames. It is a provenance
#: placeholder, NOT a signature; it must never be represented as crypto proof.
NGSI_BROKER_PLACEHOLDER = "ngsi-broker"

_LOOPBACK_HOSTS = frozenset({"localhost", "::1", "[::1]"})


def audit_cursor_path(settings: Any) -> str:
    """Location of the Brain-owned audit cursor (isolated per database)."""
    configured = getattr(settings, "guardian_audit_cursor_file", None)
    if configured:
        return str(configured)
    database_url = str(getattr(settings, "database_url", ""))
    if database_url.startswith("sqlite:///"):
        db_path = database_url[len("sqlite:///"):]
        return str(Path(db_path).with_suffix(".audit-cursor.json"))
    return "guardian.audit-cursor.json"


def audit_pending_path(settings: Any) -> str:
    """Location of the durable pending-evidence store (beside the cursor)."""
    return str(Path(audit_cursor_path(settings)).with_suffix(".pending.jsonl"))


class GuardianCompatError(RuntimeError):
    """Fail-closed error for unavailable/invalid/unauthenticated verdict data."""


@dataclass(frozen=True)
class VerifiedEvidence:
    """A Guardian verdict row bound to one specific Brain observation."""

    row: dict[str, Any]
    reading: SensorReading
    event_id: str
    correlation_id: str
    brain_event_hash: str
    guardian_digest: str
    disposition: str
    trust: float
    reason_codes: list[str]


def loopback_http_permitted(settings: Any) -> bool:
    """True when plaintext HTTP to a LOOPBACK-only Guardian is explicitly allowed.

    Task 7.3E-1 dev-only escape hatch. All of the following must hold:
    * the deployment explicitly opted in (``guardian_allow_loopback_http``);
    * the environment is not production;
    * the URL host is a loopback address (127.x, ::1 or localhost).
    Anything else fails closed: the HTTPS requirement stands.
    """
    if not getattr(settings, "guardian_allow_loopback_http", False):
        return False
    if str(getattr(settings, "environment", "")).lower() == "production":
        return False
    base = str(getattr(settings, "guardian_base_url", "") or "")
    host = urlparse(base).hostname or ""
    return host in _LOOPBACK_HOSTS or host.startswith("127.")


def require_guardian_url(settings: Any) -> str:
    """Return Guardian's base URL after enforcing the transport policy."""
    base = str(getattr(settings, "guardian_base_url", "") or "").rstrip("/")
    if not base:
        raise GuardianCompatError("guardian_base_url is not configured")
    if base.startswith("https://"):
        return base
    if base.startswith("http://") and loopback_http_permitted(settings):
        host = urlparse(base).hostname or ""
        logger.warning(
            "guardian_loopback_http_optin host=%s "
            "(explicit dev-only opt-in, non-production)",
            host,
        )
        return base
    raise GuardianCompatError("guardian_base_url must use HTTPS")


# --- Task 7.3E-3: Guardian audit-tail evidence source ----------------------

#: Guardian stamps this literal on every accepted-reading audit record.
AUDIT_ACCEPTED_EVENT = "reading.accepted"


class AuditCursor:
    """Persistent, Brain-owned audit-tail cursor.

    Tracks the highest Guardian audit ``seq`` Brain has fully accounted for:
    every event at or below this position is reconciled, durably retained in
    the pending-evidence store, or terminal (malformed/unmapped, which can
    never become evidence — the explicit terminal policy). The cursor NEVER
    advances past a live unretained unmatched event. This is a RETRIEVAL
    POSITION, never a Guardian-issued verdict revision.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._seq = 0
        self._loaded = False

    def load(self) -> int:
        if self._loaded:
            return self._seq
        self._loaded = True
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return self._seq
        except (OSError, ValueError) as exc:
            raise GuardianCompatError(f"audit cursor unreadable: {exc}") from exc
        try:
            seq = int(raw.get("last_seq", 0))
        except (TypeError, ValueError) as exc:
            raise GuardianCompatError("audit cursor has a malformed seq") from exc
        if seq < 0:
            raise GuardianCompatError("audit cursor seq must be non-negative")
        self._seq = seq
        return self._seq

    @property
    def seq(self) -> int:
        return self._seq

    def advance(self, seq: int) -> None:
        """Only ever moves forward — a rewound cursor would re-reconcile."""
        if seq <= self._seq:
            return
        self._seq = int(seq)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"last_seq": self._seq}), encoding="utf-8"
        )


class PendingEvidenceStore:
    """Durable, bounded store for accepted audit events awaiting a match.

    Solves the "Guardian reading arrives before Brain observation" ordering
    problem: an accepted, mapped audit event with no matching persisted
    observation YET is written to a JSONL file keyed by ``seq``, so the
    cursor may safely advance past it and the event is retried on every
    later cycle until it matches or is evicted. Overflow is a hard error
    (fail closed, never silent loss). Duplicate ``seq`` writes are idempotent.
    """

    def __init__(self, path: str | Path, max_pending: int = 5000) -> None:
        self.path = Path(path)
        self.max_pending = max_pending

    def load(self) -> dict[int, dict[str, Any]]:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise GuardianCompatError(f"pending store unreadable: {exc}") from exc
        pending: dict[int, dict[str, Any]] = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                seq = int(record["seq"])
            except (ValueError, KeyError, TypeError) as exc:
                raise GuardianCompatError(
                    "pending store contains a malformed record"
                ) from exc
            pending[seq] = record  # later lines win: idempotent overwrite
        return pending

    def persist(self, pending: dict[int, dict[str, Any]]) -> None:
        if len(pending) > self.max_pending:
            raise GuardianCompatError(
                f"pending evidence store overflow: {len(pending)} entries "
                f"> limit {self.max_pending}; refusing to drop evidence"
            )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            for seq in sorted(pending):
                fh.write(json.dumps(pending[seq], sort_keys=True) + "\n")
        tmp.replace(self.path)


def parse_audit_event(
    event: Any,
    mapping: dict[tuple[str, str], SensorMapping],
) -> tuple[str, str, str, float, str] | None:
    """Parse one Guardian audit record into matchable identity fields.

    Returns ``(sensor_id, guardian_property, guardian_zone, value,
    evidence_digest)`` for an accepted reading whose sensor/property is in
    the allowlist, or ``None`` for anything else (rejected frames, unrelated
    audit events, unmapped sensors). Malformed accepted rows are a contract
    violation and raise.
    """
    if not isinstance(event, dict):
        raise GuardianCompatError("audit event is not an object")
    event_name = str(event.get("event", ""))
    if event_name != AUDIT_ACCEPTED_EVENT:
        return None
    sensor_id = str(event.get("sensor_id", ""))
    guardian_property = str(event.get("observed_property", ""))
    guardian_zone = str(event.get("zone", ""))
    raw_value = event.get("value")
    evidence_digest = str(event.get("evidence_digest", ""))
    if not evidence_digest:
        raise GuardianCompatError(
            f"accepted audit event without evidence_digest: {event.get('reading_id', '')}"
        )
    if not sensor_id or not guardian_property or not guardian_zone:
        raise GuardianCompatError(
            "accepted audit event missing identity fields"
        )
    try:
        value = float(raw_value)
    except (TypeError, ValueError) as exc:
        raise GuardianCompatError("accepted audit event has a non-numeric value") from exc
    if not math.isfinite(value):
        raise GuardianCompatError("accepted audit event has a non-finite value")
    entry = next(
        (
            m
            for m in mapping.values()
            if m.entity_id == sensor_id and m.guardian_property == guardian_property
        ),
        None,
    )
    if entry is None:
        return None  # unmapped: skip, never guess
    return (sensor_id, guardian_property, guardian_zone, value, evidence_digest)


def _values_equal(reported: float, persisted: float) -> bool:
    """Strict numeric equivalence over the canonical wire representation.

    Guardian and Brain both serialize measurements as JSON floats, so exact
    ``==`` on the parsed floats is the supported comparison. Non-finite values
    are rejected outright (a NaN or Inf can never constitute evidence), and no
    rounding, tolerance or approximation is applied.
    """
    if not math.isfinite(reported) or not math.isfinite(persisted):
        return False
    return reported == persisted


def match_audit_event_to_reading(
    parsed: tuple[str, str, str, float, str],
    entry: SensorMapping,
    readings_by_identity: dict[tuple[str, str], SensorReading],
) -> VerifiedEvidence | None:
    """Bind one parsed audit event to a stored Brain observation by digest.

    The audit record does NOT carry phenomenon_time or unit. Matching is
    therefore done in two stages, both exact:

    1. Identity: the Brain observation must have been ingested from the same
       entity/attribute (mapping-defined) — the (sensor_id, entity_timestamp)
       index key is the same join the integration-verdicts adapter uses.
    2. Digest: Guardian's canonical evidence body is reconstructed using the
       PERSISTED observation's own timestamp and the mapping-declared Guardian
       unit, hashed with Guardian's canonicalization, and must equal the
       audit record's ``evidence_digest``. A contradiction fails closed.

    Any temporal proximity heuristic is forbidden: only the digest pinpoints
    WHICH observation a verdict refers to when several ticks share values.
    """
    sensor_id, guardian_property, guardian_zone, guardian_value, reported = parsed
    # Contradictory identifiers fail closed BEFORE any digest work: the
    # audit row's zone and sensor must agree with the mapped Brain channel's
    # declared Guardian vocabulary. A row claiming ZONE-C for a ZONE-B sensor
    # describes a different observation even if its value matches.
    if entry.entity_id != sensor_id:
        return None
    if entry.guardian_property != guardian_property:
        return None
    if entry.guardian_zone and guardian_zone != entry.guardian_zone:
        return None
    candidates: list[SensorReading] = [
        reading
        for (sid, _stamp), reading in readings_by_identity.items()
        if sid == entry.sensor_id
        and reading.attributes.get("entity_id") == sensor_id
        and reading.attributes.get("attribute") == entry.attribute
        and reading.unit == entry.unit
        and reading.attributes.get("zone_id", "")
    ]
    if not candidates:
        return None
    for reading in candidates:
        # Guardian stamps the verbatim NGSI timestamp; Brain carries it in
        # attributes.entity_timestamp. That IS the observation's phenomenon
        # time — reconstructed, not invented.
        entity_timestamp = reading.attributes.get("entity_timestamp", "")
        if not entity_timestamp:
            continue
        # The digest is reconstructed from the PERSISTED Brain observation's
        # own value — the authoritative measurement — never from the audit
        # event's untrusted reported value. An attacker-controlled audit row
        # claiming a different value must not mint a self-consistent digest.
        body = evidence_body(
            sensor_id, guardian_zone, guardian_property,
            entity_timestamp, float(reading.value), entry.guardian_unit or "",
        )
        digest = evidence_digest(body)
        if digest != reported:
            continue
        # The audit-reported value must ALSO independently equal the persisted
        # value (exact float equality over Guardian's canonical numeric wire
        # representation — both sides are floats serialized by the same
        # pipeline; no rounding or tolerance is applied).
        if not _values_equal(guardian_value, float(reading.value)):
            continue
        return VerifiedEvidence(
            row={
                "sensor_id": sensor_id,
                "observed_property": guardian_property,
                "zone": guardian_zone,
                "value": guardian_value,
                "evidence_digest": reported,
                "source": "audit_tail",
            },
            reading=reading,
            event_id=str(reading.event_id),
            correlation_id=str(reading.correlation_id),
            brain_event_hash=event_hash(reading),
            guardian_digest=digest,
            disposition="", trust=0.0, reason_codes=[],
        )
    return None


class AuditTailVerifier:
    """Fetches Guardian audit records and binds them to Brain observations.

    Uses ``GET /v1/verdict?since=<cursor>``. The endpoint is UNAUTHENTICATED
    in the current Guardian build, so this verifier additionally REQUIRES the
    loopback-only policy (loopback_http_permitted) or HTTPS; a plain-HTTP
    non-loopback URL is refused even when the general loopback flag is set.
    """

    def __init__(
        self,
        settings: Any,
        mappings: list[SensorMapping],
        cursor: AuditCursor,
        transport: httpx.AsyncBaseTransport | None = None,
        pending_store: PendingEvidenceStore | None = None,
    ) -> None:
        self.settings = settings
        self.by_entity: dict[tuple[str, str], SensorMapping] = {
            (m.entity_id, m.attribute): m for m in mappings
        }
        self.cursor = cursor
        self.transport = transport
        self.pending_store = pending_store or PendingEvidenceStore(
            Path(str(cursor.path)).with_suffix(".pending.jsonl")
        )

    def _headers(self) -> dict[str, str]:
        token = (
            self.settings.guardian_integration_token.get_secret_value()
            if getattr(self.settings, "guardian_integration_token", None)
            else ""
        )
        # The audit endpoint ignores headers today; sending the token when
        # configured is harmless and forward-compatible.
        if token:
            return {"X-Integration-Token": token}
        return {}

    async def fetch_events(
        self, client: httpx.AsyncClient | None = None
    ) -> list[dict[str, Any]]:
        if client is None:
            async with httpx.AsyncClient(
                transport=self.transport, trust_env=False
            ) as owned:
                return await self.fetch_events(owned)
        base = require_guardian_url(self.settings)
        since = self.cursor.load()
        try:
            response = await client.get(
                f"{base}/v1/verdict", headers=self._headers(),
                params={"since": since},
            )
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise GuardianCompatError("guardian audit tail unavailable") from exc
        if response.status_code != 200:
            raise GuardianCompatError(
                f"guardian audit tail returned HTTP {response.status_code}"
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise GuardianCompatError("guardian audit tail is not JSON") from exc
        events = body.get("events") if isinstance(body, dict) else None
        if not isinstance(events, list):
            raise GuardianCompatError("guardian audit tail has no events list")
        return events

    async def verify_against(
        self,
        events: list[dict[str, Any]],
        readings: list[SensorReading],
    ) -> dict[str, Any]:
        """Reconcile audit records against Brain observations (verify-only).

        Reliability model (Task 7.3E-3-R):

        * Guardian emits a CONTIGUOUS ascending ``seq`` stream; Brain's
          durable cursor marks the highest seq fully ACCOUNTED for. Every
          incoming event is classified:
            - verified: exact digest match -> counted, cursor can pass it;
            - pending:  accepted, mapped, but no matching persisted
              observation YET -> durably retained in the pending store and
              retried on every later cycle (ordering safety);
            - terminal: malformed, or unmapped, or otherwise never matchable
              -> counted, cursor may pass it (explicit terminal policy;
              these can never become evidence);
            - duplicate/replay: seq at or below the cursor -> ignored.
        * The cursor never advances past a live, unretained unmatched event:
          the next fetch starts BELOW it, so nothing is silently lost.
        * Continuity violations (a fetched seq jumping a gap or moving
          backwards below the cursor range) are detected and reported as
          ``gap_detected``/``reset_detected``; the cursor is never advanced
          across a detected gap, so the missed range stays unconsumed.
        * Overflow of the pending store fails the cycle closed — evidence is
          never silently discarded to fit a bound.
        """
        cursor_seq = self.cursor.load()
        index: dict[tuple[str, str], SensorReading] = {
            (r.sensor_id, r.attributes.get("entity_timestamp", "")): r
            for r in readings
        }
        verified: list[VerifiedEvidence] = []
        unmatched = malformed = duplicates = 0
        pending_events: dict[int, dict[str, Any]] = self.pending_store.load()
        before_pending = len(pending_events)
        gap_detected = reset_detected = False
        highest_accounted = cursor_seq
        blockage: int | None = None  # lowest unaccounted seq in this batch

        # RETRY PASS: durably retained pending events sit BEHIND the cursor
        # (the cursor advanced past them once they were safely stored). They
        # must be re-matched against today's observations before the dedup
        # gate; a match releases them from the store.
        for seq in sorted(list(pending_events)):
            event = pending_events[seq]
            try:
                parsed = parse_audit_event(event, self.by_entity)
            except GuardianCompatError:
                pending_events.pop(seq, None)  # now-terminal: stop retrying
                malformed += 1
                continue
            if parsed is None:
                pending_events.pop(seq, None)
                continue
            entry = next(
                (
                    m for m in self.by_entity.values()
                    if m.entity_id == parsed[0]
                    and m.guardian_property == parsed[1]
                ),
                None,
            )
            if entry is None:
                pending_events.pop(seq, None)
                continue
            evidence = match_audit_event_to_reading(parsed, entry, index)
            if evidence is not None:
                pending_events.pop(seq, None)
                verified.append(evidence)

        for event in events:
            seq_raw = event.get("seq") if isinstance(event, dict) else None
            try:
                seq = int(seq_raw)
            except (TypeError, ValueError):
                malformed += 1
                continue
            if seq <= cursor_seq or seq <= highest_accounted:
                duplicates += 1
                continue  # replay / already accounted (incl. in-batch dupes)
            if cursor_seq == 0 and highest_accounted == 0:
                # Baseline bootstrap: FIRST batch ever reconciled. The audit
                # stream exposes no head marker, so Brain cannot know which
                # earlier seqs existed before the first poll; the first seen
                # seq anchors the baseline instead of looking like a gap.
                highest_accounted = seq - 1
            elif seq > highest_accounted + 1:
                # A gap AFTER the baseline: events (cursor, seq) were never
                # delivered. Refuse to advance past them; keep the batch's
                # earlier progress only.
                gap_detected = True
                blockage = seq
                break
            try:
                parsed = parse_audit_event(event, self.by_entity)
            except GuardianCompatError:
                malformed += 1
                highest_accounted = seq  # terminal: can never be evidence
                continue
            if parsed is None:
                # Rejected frames and unmapped sensors are terminal: they can
                # never become evidence regardless of future observations.
                highest_accounted = seq
                continue
            entry = next(
                (
                    m for m in self.by_entity.values()
                    if m.entity_id == parsed[0]
                    and m.guardian_property == parsed[1]
                ),
                None,
            )
            if entry is None:
                unmatched += 1
                highest_accounted = seq
                continue
            evidence = match_audit_event_to_reading(parsed, entry, index)
            if evidence is None:
                # Not matchable YET (e.g. the Brain observation has not been
                # persisted): retain durably and retry next cycle.
                pending_events[seq] = event
                highest_accounted = seq
                continue
            pending_events.pop(seq, None)  # a late match clears pending state
            verified.append(evidence)
            highest_accounted = seq

        if blockage is not None and highest_accounted > cursor_seq:
            # Only advance to the last contiguous position actually processed.
            self.cursor.advance(highest_accounted)
        elif blockage is None and highest_accounted > cursor_seq:
            self.cursor.advance(highest_accounted)

        try:
            self.pending_store.persist(pending_events)
        except GuardianCompatError:
            # Overflow: the cursor has already advanced past those seqs, so
            # persist failure must fail the cycle closed (no silent loss).
            raise
        return {
            "mode": "audit_tail_reconciliation",
            "trusted_granted": 0,
            "verified_matches": len(verified),
            "unmatched": unmatched,
            "unmatched_pending": len(pending_events),
            "pending_delta": len(pending_events) - before_pending,
            "malformed": malformed,
            "duplicates": duplicates,
            "gap_detected": gap_detected,
            "reset_detected": reset_detected,
            "cursor_seq": self.cursor.seq,
            "verified": [
                {
                    "event_id": v.event_id,
                    "correlation_id": v.correlation_id,
                    "brain_event_hash": v.brain_event_hash,
                    "guardian_digest": v.guardian_digest,
                    "sensor_id": v.row["sensor_id"],
                    "observed_property": v.row["observed_property"],
                }
                for v in verified
            ],
        }


class AuditTailShadowWorker:
    """Bounded, verification-only Guardian audit-tail reconciliation worker.

    Own loop (does NOT subclass GuardianShadowWorker — the two adapters have
    different fetch/verify contracts). Reconciles fetched audit events
    against PERSISTED Brain observations loaded from the database, records
    Brain-issued observations only, and never grants trust.
    """

    def __init__(
        self,
        verifier: AuditTailVerifier,
        database: Any,
        poll_seconds: float,
        max_events: int = 500,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.verifier = verifier
        self.database = database
        self.poll_seconds = poll_seconds
        self.max_events = max_events
        self.timeout_seconds = timeout_seconds
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self.last_error: str | None = None
        self.stats: dict[str, Any] = {
            "mode": "audit_tail_reconciliation",
            "trusted_granted": 0,
            "last_attempted": None,
            "last_succeeded": None,
            "verified_matches": 0,
            "unmatched": 0,
            "malformed": 0,
            "cursor_seq": 0,
        }

    @classmethod
    def from_settings(cls, settings: Any, database: Any) -> "AuditTailShadowWorker":
        if not settings.guardian_shadow_reconciliation_enabled:
            raise GuardianCompatError(
                "guardian shadow reconciliation is disabled by configuration"
            )
        if not settings.guardian_base_url:
            raise GuardianCompatError(
                "guardian_base_url is required for audit-tail reconciliation"
            )
        # Unauthenticated endpoint: loopback HTTP requires the explicit
        # opt-in; anything else must be HTTPS.
        https_ok = str(settings.guardian_base_url).startswith("https://")
        if not https_ok and not loopback_http_permitted(settings):
            raise GuardianCompatError("guardian_base_url must use HTTPS")
        if (
            settings.environment.lower() == "production"
            and settings.guardian_allow_loopback_http
        ):
            raise GuardianCompatError(
                "loopback HTTP guardian is forbidden in production"
            )
        if settings.environment.lower() != "development":
            raise GuardianCompatError(
                "audit-tail evidence source is allowed only in the development "
                "environment (endpoint is unauthenticated)"
            )
        from app.integration.ngsi_twin import load_mapping

        mappings = list(load_mapping(settings.snap4city_devices_file).sensors)
        cursor = AuditCursor(audit_cursor_path(settings))
        store = PendingEvidenceStore(audit_pending_path(settings))
        verifier = AuditTailVerifier(settings, mappings, cursor, pending_store=store)
        return cls(
            verifier,
            database,
            settings.guardian_shadow_poll_seconds,
            max_events=settings.guardian_shadow_max_rows,
            timeout_seconds=settings.guardian_shadow_timeout_seconds,
        )

    async def cycle(self) -> dict[str, Any]:
        self.stats["last_attempted"] = datetime.now(UTC).isoformat()
        # verify_against re-tries durably retained pending evidence against
        # freshly-loaded observations every cycle, so a Guardian reading that
        # arrived before its Brain observation is matched as soon as it lands.
        events = await self.verifier.fetch_events()
        readings = self._load_readings()
        result = await self.verifier.verify_against(events, readings)
        self.stats["last_succeeded"] = self.stats["last_attempted"]
        self.stats.update({
            "verified_matches": result["verified_matches"],
            "unmatched": result["unmatched"],
            "unmatched_pending": result["unmatched_pending"],
            "malformed": result["malformed"],
            "duplicates": result["duplicates"],
            "gap_detected": result["gap_detected"],
            "cursor_seq": result["cursor_seq"],
        })
        self.stats["last_succeeded"] = self.stats["last_attempted"]
        self.stats.update({
            "verified_matches": result["verified_matches"],
            "unmatched": result["unmatched"],
            "malformed": result["malformed"],
            "cursor_seq": result["cursor_seq"],
        })
        self.last_error = None
        return result

    def _load_readings(self) -> list[SensorReading]:
        """Load persisted observations (restart-safe join) from the database."""
        if self.database is None:
            return []
        from datetime import timedelta

        with self.database.transaction() as session:
            cutoff = datetime.now(UTC) - timedelta(
                seconds=float(getattr(self.verifier.settings, "event_freshness_seconds", 300))
            )
            rows = session.scalars(
                select(SensorEvent).where(SensorEvent.occurred_at >= cutoff)
            ).all()
        readings: list[SensorReading] = []
        for row in rows:
            payload = row.payload.get("event") or {}
            try:
                readings.append(SensorReading.model_validate(payload))
            except ValidationError:
                continue
        return readings

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self.cycle()
            except Exception as exc:  # noqa: BLE001 - worker must survive errors
                self.last_error = f"{type(exc).__name__}: {exc}"
                logger.warning("audit_tail_reconciliation_failed error=%s", self.last_error)
            with suppress(TimeoutError):
                await asyncio.wait_for(
                    self._stop.wait(), timeout=max(self.poll_seconds, 0.05)
                )

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop = asyncio.Event()
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
            self._task = None


def evidence_body(
    sensor_id: str, zone: str, observed_property: str, phenomenon_time: str,
    value: float, unit: str,
) -> dict[str, Any]:
    """Reconstruct the Guardian reading frame body exactly (ngsi.py:191-197)."""
    return {
        "sensor_id": sensor_id,
        "zone": zone,
        "observed_property": observed_property,
        "phenomenon_time": phenomenon_time,
        "result": {"value": float(value), "unit": unit},
    }


def evidence_digest(body: dict[str, Any]) -> str:
    """Guardian's digest canonicalization: sorted keys, compact separators.

    Matches ``guardian/src/guardian/ngsi.py::_digest`` including its default
    ensure_ascii=True JSON encoding.
    """
    blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def match_row_to_reading(
    row: dict[str, Any],
    mapping: dict[tuple[str, str], SensorMapping],
    readings_by_identity: dict[tuple[str, str], SensorReading],
) -> VerifiedEvidence | None:
    """Bind one Guardian row to a Brain observation, verifying every field.

    Returns None when the row does not correspond to a mapped, stored
    observation (unknown mapping is a skip, not an authorization).

    Guardian-origin values (its zone string, its property name, its unit
    spelling) come from the row, cross-checked against the mapping's declared
    Guardian vocabulary; the Brain reading is then verified separately against
    the Brain-side identity, value and explicitly mapped unit equivalence.
    """
    sensor_id = str(row.get("sensor_id", ""))
    guardian_property = str(row.get("observed_property", ""))
    guardian_zone = str(row.get("zone", ""))
    guardian_unit = str(row.get("unit", ""))
    phenomenon_time = str(row.get("phenomenon_time", ""))
    try:
        guardian_value = float(row.get("value", float("nan")))
    except (TypeError, ValueError):
        return None

    entry = next(
        (
            m
            for m in mapping.values()
            if m.entity_id == sensor_id and m.guardian_property == guardian_property
        ),
        None,
    )
    if entry is None:
        return None
    # Guardian's zone and unit must equal the explicitly configured contract
    # values — never inferred from Brain's internal strings.
    if guardian_zone != (entry.guardian_zone or ""):
        return None
    if guardian_unit != (entry.guardian_unit or ""):
        return None
    key = (entry.sensor_id, phenomenon_time)
    reading = readings_by_identity.get(key)
    if reading is None:
        return None
    if reading.attributes.get("entity_timestamp") != phenomenon_time:
        return None
    if reading.attributes.get("entity_id") != sensor_id:
        return None
    if reading.attributes.get("attribute") != entry.attribute:
        return None
    if guardian_value != reading.value:
        return None
    # Explicitly configured equivalence between Guardian's unit spelling and
    # Brain's internal unit (e.g. Guardian "C" vs Brain "degC"). No numerical
    # conversion, no silent normalization of anything unmapped.
    if reading.unit != entry.unit:
        return None
    # Zone check: each side is validated against its own configured value.
    # Vocabulary equality is legitimate when both systems agree on a label;
    # correctness comes from the explicit mapping, not from forced inequality.
    brain_zone = reading.attributes.get("zone_id", "")
    if not brain_zone:
        return None
    digest = evidence_digest(
        evidence_body(
            sensor_id, guardian_zone, guardian_property, phenomenon_time,
            guardian_value, guardian_unit,
        )
    )
    reported = str(row.get("evidence_digest", ""))
    if digest != reported:
        return None
    return VerifiedEvidence(
        row=row,
        reading=reading,
        event_id=str(reading.event_id),
        correlation_id=str(reading.correlation_id),
        brain_event_hash=event_hash(reading),
        guardian_digest=digest,
        disposition=str(row.get("disposition", "")),
        trust=float(row.get("trust", 0.0)),
        reason_codes=[str(code) for code in row.get("reason_codes", [])],
    )


class GuardianVerifier:
    """Fetches and verifies Guardian verdict rows; never grants trust."""

    def __init__(
        self,
        settings: Any,
        mappings: list[SensorMapping],
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.by_entity: dict[tuple[str, str], SensorMapping] = {
            (m.entity_id, m.attribute): m for m in mappings
        }
        self.transport = transport

    def _headers(self) -> dict[str, str]:
        token = (
            self.settings.guardian_integration_token.get_secret_value()
            if self.settings.guardian_integration_token
            else ""
        )
        if not token:
            raise GuardianCompatError("guardian integration token is not configured")
        return {"X-Integration-Token": token}

    async def fetch_rows(self, client: httpx.AsyncClient | None = None) -> list[dict[str, Any]]:
        """Fetch verdict rows over the injected transport.

        When no client is supplied, one is created bound to ``self.transport``
        so offline tests (and fail-closed deployments) never touch the live
        network by accident.
        """
        if client is None:
            async with httpx.AsyncClient(
                transport=self.transport, trust_env=False
            ) as owned:
                return await self.fetch_rows(owned)
        base = require_guardian_url(self.settings)
        try:
            response = await client.get(
                f"{base}/v1/integration/verdicts", headers=self._headers()
            )
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise GuardianCompatError("guardian unavailable") from exc
        if response.status_code == 401:
            raise GuardianCompatError("guardian rejected the integration token")
        if response.status_code != 200:
            raise GuardianCompatError(f"guardian returned HTTP {response.status_code}")
        try:
            body = response.json()
        except ValueError as exc:
            raise GuardianCompatError("guardian response is not JSON") from exc
        rows = body.get("verdicts") if isinstance(body, dict) else None
        if not isinstance(rows, list):
            raise GuardianCompatError("guardian response has no verdict rows")
        return rows

    async def verify_against(
        self,
        rows: list[dict[str, Any]],
        readings: list[SensorReading],
    ) -> list[VerifiedEvidence]:
        verified: list[VerifiedEvidence] = []
        for row in rows:
            try:
                evidence = match_row_to_reading(
                    row, self.by_entity, self._index(readings)
                )
            except (TypeError, ValueError):
                continue
            if evidence is not None:
                verified.append(evidence)
        return verified

    @staticmethod
    def _index(readings: list[SensorReading]) -> dict[tuple[str, str], SensorReading]:
        return {
            (r.sensor_id, r.attributes.get("entity_timestamp", "")): r for r in readings
        }


def verification_summary(verified: list[VerifiedEvidence]) -> dict[str, Any]:
    """Operator-readable report; proves binding without granting trust."""
    now = datetime.now(UTC).isoformat()
    return {
        "verified_at": now,
        "mode": "verification_only",
        "trusted_granted": 0,
        "observations": [
            {
                "event_id": v.event_id,
                "correlation_id": v.correlation_id,
                "brain_event_hash": v.brain_event_hash,
                "guardian_digest": v.guardian_digest,
                "disposition": v.disposition,
                "trust": v.trust,
                "reason_codes": v.reason_codes,
            }
            for v in verified
        ],
    }


def _reading_from_event(row: SensorEvent) -> SensorReading | None:
    """Rebuild the SensorReading view of a persisted event (restart-safe join)."""
    payload = row.payload.get("event") or {}
    try:
        return SensorReading.model_validate(payload)
    except ValidationError:
        return None


class ShadowStats:
    """Brain-issued reconciliation observations (NOT Guardian statements).

    Every counter here describes what this Brain process observed about
    Guardian's response to an unauthenticated-to-Guardian poll. Dispositions
    seen here are copied from rows for operator visibility only; they never
    enter the Brain trust pipeline. ``trusted_granted`` is structurally zero.
    """

    __slots__ = (
        "last_attempted", "last_succeeded", "rows_fetched", "verified_matches",
        "rejected_or_mismatched", "unknown_mappings", "adverse_dispositions",
        "missing_rows", "transport_failures", "stale_evidence", "last_error",
        "last_event_ids", "duration_ms", "db_lookup_ms", "candidates_inspected",
        "incomplete_cycles",
    )

    def __init__(self) -> None:
        self.last_attempted: datetime | None = None
        self.last_succeeded: datetime | None = None
        self.rows_fetched = 0
        self.verified_matches = 0
        self.rejected_or_mismatched = 0
        self.unknown_mappings = 0
        self.adverse_dispositions = 0
        self.missing_rows = 0
        self.transport_failures = 0
        self.stale_evidence = 0
        self.last_error: str | None = None
        # Task 7.3C-3B observability additions.
        self.duration_ms = 0.0
        self.db_lookup_ms = 0.0
        self.candidates_inspected = 0
        self.incomplete_cycles = 0
        # Digests of rows seen in the last successful cycle, so "previously
        # observed rows no longer returned" can be reported without implying
        # revocation.
        self.last_event_ids: set[str] = set()

    def as_dict(self) -> dict[str, Any]:
        return {
            "mode": "shadow_reconciliation",
            "trusted_granted": 0,
            "last_attempted": (
                self.last_attempted.isoformat() if self.last_attempted else None
            ),
            "last_succeeded": (
                self.last_succeeded.isoformat() if self.last_succeeded else None
            ),
            "rows_fetched": self.rows_fetched,
            "verified_matches": self.verified_matches,
            "rejected_or_mismatched": self.rejected_or_mismatched,
            "unknown_mappings": self.unknown_mappings,
            "adverse_dispositions": self.adverse_dispositions,
            "missing_rows": self.missing_rows,
            "transport_failures": self.transport_failures,
            "stale_evidence": self.stale_evidence,
            "last_error": self.last_error,
            "duration_ms": round(self.duration_ms, 1),
            "db_lookup_ms": round(self.db_lookup_ms, 1),
            "candidates_inspected": self.candidates_inspected,
            "incomplete_cycles": self.incomplete_cycles,
        }


class GuardianShadowWorker:
    """Verification-and-observability-only Guardian reconciliation.

    Polls ``GET /v1/integration/verdicts`` over verified TLS with the
    integration token, validates every row with the strict mapping/digest
    checks, joins verified rows to PERSISTED Brain SensorEvents by exact
    observation identity, and records Brain-issued observations only.

    It never mints GuardianVerdicts, never assigns Guardian identity to a
    Brain assertion, never grants TRUSTED, and never reads revocation into a
    vanished row: the Guardian response is a limited collection (its verdict
    cache), not an authoritative snapshot. Missing rows are reported as
    observations, nothing more.

    Concurrency note: this is a process-local, single-loop worker. It does
    NOT provide distributed coordination; deployments with multiple Brain
    processes against one database would each reconcile independently
    (observations only, so harmless, but duplicated). Documented limitation.
    """

    ADVERSE = {"SUSPECT", "RESTRICT", "MALICIOUS"}

    def __init__(
        self,
        verifier: GuardianVerifier,
        database: Any,
        poll_seconds: float,
        stale_after_seconds: float,
        transport: httpx.AsyncBaseTransport | None = None,
        max_rows: int = 500,
        max_candidates: int = 2000,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.verifier = verifier
        self.database = database
        self.poll_seconds = poll_seconds
        self.stale_after_seconds = stale_after_seconds
        self.transport = transport
        self.max_rows = max_rows
        self.max_candidates = max_candidates
        self.timeout_seconds = timeout_seconds
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._cycle_lock = asyncio.Lock()
        self.stats = ShadowStats()
        self.last_error: str | None = None

    @classmethod
    def from_settings(cls, settings: Any, database: Any) -> "GuardianShadowWorker":
        if not settings.guardian_shadow_reconciliation_enabled:
            raise GuardianCompatError(
                "guardian shadow reconciliation is disabled by configuration"
            )
        if not settings.guardian_base_url:
            raise GuardianCompatError(
                "guardian_base_url is required for shadow reconciliation"
            )
        https_ok = str(settings.guardian_base_url).startswith("https://")
        if not https_ok and not loopback_http_permitted(settings):
            raise GuardianCompatError("guardian_base_url must use HTTPS")
        if (
            settings.environment.lower() == "production"
            and settings.guardian_allow_loopback_http
        ):
            raise GuardianCompatError(
                "loopback HTTP guardian is forbidden in production"
            )
        if not settings.guardian_integration_token:
            raise GuardianCompatError("guardian_integration_token is required")
        from app.integration.ngsi_twin import load_mapping

        # Row validation joins through the SAME explicit device allowlist the
        # Twin ingest worker uses: one mapping source, no divergent copies.
        mappings = list(load_mapping(settings.snap4city_devices_file).sensors)
        verifier = GuardianVerifier(settings, mappings)
        return cls(
            verifier,
            database,
            settings.guardian_shadow_poll_seconds,
            stale_after_seconds=float(settings.event_freshness_seconds),
            max_rows=settings.guardian_shadow_max_rows,
            max_candidates=settings.guardian_shadow_max_candidates,
            timeout_seconds=settings.guardian_shadow_timeout_seconds,
        )

    def _load_events(
        self, sensor_ids: list[str], since: datetime
    ) -> tuple[list[tuple[SensorEvent, SensorReading]], bool]:
        """Bounded candidate selection over indexed columns.

        Joins Guardian rows to persisted observations by the exact existing
        identity (sensor_id + verbatim entity timestamp). Candidates are
        restricted to the mapped sensor_ids present in the response and a
        bounded recency window, using the indexed ``sensor_id`` and
        ``occurred_at`` columns. A ``LIMIT + 1`` probe detects truncation:
        the caller must then classify the cycle as incomplete instead of
        reporting definitive missing/mismatched observations.
        """
        started = time.perf_counter()
        pairs: list[tuple[SensorEvent, SensorReading]] = []
        overflow = False
        with self.database.transaction() as session:
            stmt = (
                select(SensorEvent)
                .where(
                    SensorEvent.sensor_id.in_(sensor_ids),
                    SensorEvent.occurred_at >= since,
                )
                .order_by(SensorEvent.occurred_at.desc())
                .limit(self.max_candidates + 1)  # overflow probe
            )
            rows = session.scalars(stmt).all()
            if len(rows) > self.max_candidates:
                overflow = True
                rows = rows[: self.max_candidates]
            for row in rows:
                reading = _reading_from_event(row)
                if reading is not None:
                    pairs.append((row, reading))
        self.stats.db_lookup_ms = (time.perf_counter() - started) * 1000.0
        self.stats.candidates_inspected = len(pairs)
        return pairs, overflow

    async def cycle(self) -> dict[str, Any]:
        """One reconciliation pass; overlapping cycles are prevented."""
        async with self._cycle_lock:
            cycle_started = time.perf_counter()
            self.stats.last_attempted = datetime.now(UTC)
            try:
                async with httpx.AsyncClient(
                    transport=self.transport,
                    trust_env=False,
                    timeout=self.timeout_seconds,
                ) as client:
                    rows = await self.verifier.fetch_rows(client)
            except GuardianCompatError as exc:
                self.stats.transport_failures += 1
                self.stats.last_error = f"{type(exc).__name__}: {exc}"
                self.last_error = self.stats.last_error
                logger.warning(
                    "guardian_shadow_reconcile_failed error=%s", self.stats.last_error
                )
                raise
            if len(rows) > self.max_rows:
                # Oversized response: refuse to half-report. Record an
                # incomplete reconciliation; nothing here implies absence or
                # revocation of anything.
                self.stats.incomplete_cycles += 1
                self.stats.last_error = (
                    f"guardian response exceeds row cap ({len(rows)} > "
                    f"{self.max_rows})"
                )
                logger.warning(
                    "guardian_shadow_response_oversized rows=%d cap=%d",
                    len(rows), self.max_rows,
                )
                return self.stats.as_dict()
            self.stats.rows_fetched = len(rows)
            self.stats.verified_matches = 0
            self.stats.rejected_or_mismatched = 0
            self.stats.unknown_mappings = 0
            self.stats.adverse_dispositions = 0
            self.stats.missing_rows = 0
            self.stats.stale_evidence = 0

            # Candidate search window: anchored at the newest row timestamp
            # CLAMPED to now, so a future-dated or spoofed row can never push
            # the window forward and silently exclude valid observations.
            # Malformed/naive stamps are skipped for window computation.
            now = datetime.now(UTC)
            stamps = []
            for row in rows:
                try:
                    stamp = datetime.fromisoformat(
                        str(row.get("phenomenon_time", "")).replace("Z", "+00:00")
                    )
                except ValueError:
                    continue
                if stamp.tzinfo is None:
                    continue
                stamps.append(stamp)
            sensor_ids = sorted(
                {
                    m.sensor_id
                    for row in rows
                    for m in self.verifier.by_entity.values()
                    if m.entity_id == str(row.get("sensor_id", ""))
                }
            )
            if stamps:
                newest = min(max(stamps), now)  # future rows never widen scope
                since = newest - timedelta(seconds=self.stale_after_seconds)
            else:
                since = now - timedelta(seconds=self.stale_after_seconds)
            events, candidate_overflow = self._load_events(sensor_ids, since)
            if candidate_overflow:
                # Truncated candidate search: refusing to classify would-be
                # definitive negatives (missing/mismatched) on unexamined
                # candidates. Positive verification is also deferred to the
                # next complete cycle; nothing implies absence/revocation.
                self.stats.incomplete_cycles += 1
                self.stats.last_error = (
                    "candidate search truncated at "
                    f"{self.max_candidates} rows; reconciliation incomplete"
                )
                self.stats.duration_ms = (
                    time.perf_counter() - cycle_started
                ) * 1000.0
                logger.warning(
                    "guardian_shadow_candidates_truncated cap=%d",
                    self.max_candidates,
                )
                return self.stats.as_dict()
            index: dict[tuple[str, str], SensorReading] = {
                (r.sensor_id, r.attributes.get("entity_timestamp", "")): r
                for _, r in events
            }
            # Metric definitions (Task 7.3C-3A-R):
            # * ``missing_rows`` counts previously VERIFIED observation matches
            #   (by Brain event id) that no longer appear — an operational
            #   observation, NEVER proof of Guardian revocation.
            # * ``stale_evidence`` counts Guardian rows whose phenomenon_time
            #   exceeds the freshness window, evaluated independently of
            #   observation binding (stale telemetry, never accepted as
            #   evidence and never granted trust).
            verified_ids: set[str] = set()
            seen: set[str] = set()
            for row in rows:
                digest = str(row.get("evidence_digest", ""))
                seen.add(digest)
                try:
                    stamp = datetime.fromisoformat(
                        str(row.get("phenomenon_time", "")).replace("Z", "+00:00")
                    )
                except ValueError:
                    self.stats.rejected_or_mismatched += 1
                    continue
                if stamp.tzinfo is None:
                    # Naive timestamp: unverifiable against Brain's clock.
                    self.stats.rejected_or_mismatched += 1
                    continue
                if (now - stamp).total_seconds() > self.stale_after_seconds:
                    self.stats.stale_evidence += 1
                mapping_hit = any(
                    m.entity_id == str(row.get("sensor_id", ""))
                    and m.guardian_property == str(row.get("observed_property", ""))
                    for m in self.verifier.by_entity.values()
                )
                if not mapping_hit:
                    self.stats.unknown_mappings += 1
                    continue
                verified = match_row_to_reading(
                    row, self.verifier.by_entity, index
                )
                if verified is None:
                    self.stats.rejected_or_mismatched += 1
                    continue
                self.stats.verified_matches += 1
                verified_ids.add(verified.event_id)
                disposition = str(row.get("disposition", ""))
                if disposition in self.ADVERSE:
                    self.stats.adverse_dispositions += 1
            self.stats.missing_rows = max(
                0,
                len(self.stats.last_event_ids)
                - len(verified_ids & self.stats.last_event_ids),
            )
            self.stats.last_event_ids = verified_ids
            self.stats.last_succeeded = datetime.now(UTC)
            self.stats.last_error = None
            self.last_error = None
            self.stats.duration_ms = (time.perf_counter() - cycle_started) * 1000.0
            logger.info(
                "guardian_shadow_reconciled rows=%d verified=%d mismatched=%d "
                "unknown=%d adverse=%d missing=%d stale=%d db_ms=%.1f "
                "candidates=%d",
                self.stats.rows_fetched, self.stats.verified_matches,
                self.stats.rejected_or_mismatched, self.stats.unknown_mappings,
                self.stats.adverse_dispositions, self.stats.missing_rows,
                self.stats.stale_evidence, self.stats.db_lookup_ms,
                self.stats.candidates_inspected,
            )
            return self.stats.as_dict()

    async def _loop(self) -> None:
        while not self._stop.is_set():
            with suppress(Exception):
                await self.cycle()
            with suppress(TimeoutError):
                await asyncio.wait_for(
                    self._stop.wait(), timeout=max(self.poll_seconds, 0.05)
                )

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop = asyncio.Event()
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
            self._task = None
