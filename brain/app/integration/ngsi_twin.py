"""Read-only NGSI-v2 sensor ingestion adapter for the Snap4City Orion broker.

This adapter implements the read half of docs/integration-contract-map.md: it
polls explicitly allowlisted Twin sensor entities and translates them into
Brain ``SensorReading`` objects that flow through the existing authenticated
ingestion and trust pipeline. It never writes to the broker, never fabricates
Guardian verdicts, and never invents sensor events for unmapped or malformed
entities. Observations stay untrusted until a matching Guardian verdict is
ingested by the normal trust path.

Design notes (mirroring Guardian's own ngsi.py principles, Brain-owned):

* Allowlist only: an entity/attribute pair not present in the mapping file is
  skipped, never guessed. A wrong property would be scored against the wrong
  physics profile downstream.
* Deterministic observation identity: event_id and correlation_id are UUID5
  over (sensor_id, attribute, entity timestamp). Unchanged entities therefore
  produce identical IDs across polls, and the Brain ingestion API rejects the
  duplicate with 409 instead of storing a second event.
* Provenance preservation: the entity ``timestamp`` string is carried verbatim
  in ``occurred_at`` (parsed) and echoed in ``attributes`` so a Guardian
  evidence digest can later be recomputed byte-for-byte.
* Fail-closed: network failures raise PollError; HTTP-level rejections are
  logged and skipped. There is no fallback to mock transport.
"""

import asyncio
import logging
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

import httpx
import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.config import Settings
from app.database.models import SensorEvent
from app.schemas.sensor import SensorReading
from app.security.event_hash import event_hash

logger = logging.getLogger(__name__)

_OBSERVATION_NS = "aegicity-brain:observation"
_CORRELATION_NS = "aegicity-brain:correlation"


class SensorMapping(BaseModel):
    """One allowlisted (entity, attribute) -> Brain observation translation.

    ``guardian_*`` fields record the REAL Guardian's wire vocabulary for this
    channel (guardian/ngsi.yaml + zone_for()); they exist so evidence
    verification can reconstruct Guardian's canonical digest exactly. They are
    descriptive contract data, never used to authorize anything.
    """

    model_config = ConfigDict(extra="forbid")

    entity_id: str = Field(min_length=1, max_length=128)
    ngsi_type: str = Field(min_length=1, max_length=128)
    attribute: str = Field(min_length=1, max_length=128)
    sensor_id: str = Field(min_length=1, max_length=128)
    measurement: str = Field(min_length=1, max_length=64)
    unit: str = Field(min_length=1, max_length=32)
    # Exact Guardian-side vocabulary (authority: guardian/ngsi.yaml).
    guardian_zone: str | None = Field(default=None, max_length=32)
    guardian_property: str | None = Field(default=None, max_length=64)
    guardian_unit: str | None = Field(default=None, max_length=32)


class TwinDeviceMap(BaseModel):
    """The parsed allowlist file (data, not code)."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    sensors: list[SensorMapping] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_unique(self) -> "TwinDeviceMap":
        pairs = [(m.entity_id, m.attribute) for m in self.sensors]
        if len(set(pairs)) != len(pairs):
            raise ValueError("duplicate entity/attribute mapping")
        ids = [m.sensor_id for m in self.sensors]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate sensor_id mapping")
        # Ambiguity gate: two allowlisted channels sharing one Guardian
        # property on the same entity cannot be told apart in verdict rows
        # (Guardian only echoes observed_property), so neither may be used
        # for evidence verification.
        guardian_pairs = [
            (m.entity_id, m.guardian_property) for m in self.sensors
            if m.guardian_property
        ]
        if len(set(guardian_pairs)) != len(guardian_pairs):
            raise ValueError("ambiguous guardian_property mapping")
        return self


def load_mapping(path: str | None) -> TwinDeviceMap:
    if not path:
        raise ValueError("no Snap4City device mapping file configured")
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return TwinDeviceMap.model_validate(raw)


class PollError(RuntimeError):
    """Raised when the broker is unreachable; never swallowed into silence."""


@dataclass
class PollStats:
    fetched: int = 0
    emitted: int = 0
    skipped_unmapped: int = 0
    skipped_invalid: int = 0
    duplicates: int = 0
    errors: list[str] = field(default_factory=list)


def _flatten(entity: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, raw in (entity or {}).items():
        if key in ("id", "type"):
            continue
        out[key] = raw.get("value") if isinstance(raw, dict) and "value" in raw else raw
    return out


def _parse_stamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        stamp = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        return None
    return stamp.astimezone(UTC)


class NgsiTwinPoller:
    """Polls allowlisted Orion entities and yields SensorReading objects."""

    def __init__(
        self,
        settings: Settings,
        mapping: TwinDeviceMap,
        transport: httpx.AsyncBaseTransport | None = None,
        now: datetime | None = None,
    ) -> None:
        self.settings = settings
        self.mapping = mapping
        self.transport = transport
        self._now = now
        # In-run dedupe: (sensor_id, attribute) -> (timestamp, value).
        # Keyed per attribute: sibling attributes of one entity tick are
        # distinct observations, not duplicates of each other.
        self._last_seen: dict[tuple[str, str], tuple[datetime, float]] = {}

    def _observation_ids(
        self, entity_id: str, attribute: str, stamp: datetime
    ) -> tuple[UUID, UUID]:
        """Deterministic per-observation identity.

        The attribute (and its mapped sensor_id namespace) is part of the key:
        one entity publishes several measured properties per tick, and each is
        an independent observation with its own event identity. Omitting it
        collapsed sibling attributes onto one ID and made ingestion reject the
        second one as a duplicate event.
        """
        key = f"{_OBSERVATION_NS}:{entity_id}:{attribute}:{stamp.isoformat()}"
        event_id = uuid5(NAMESPACE_URL, key)
        stamp_key = f"{_CORRELATION_NS}:{entity_id}:{attribute}:{stamp.isoformat()}"
        correlation_id = uuid5(NAMESPACE_URL, stamp_key)
        return event_id, correlation_id

    def _fresh(self, stamp: datetime, now: datetime) -> bool:
        age = (now - stamp).total_seconds()
        return 0 <= age <= self.settings.event_freshness_seconds

    def _to_reading(
        self, entry: SensorMapping, values: dict[str, Any], entity_type: str | None, now: datetime
    ) -> SensorReading | None:
        if entity_type is not None and entity_type != entry.ngsi_type:
            logger.warning(
                "ngsi_twin_type_mismatch entity=%s type=%s", entry.entity_id, entity_type
            )
            return None
        raw = values.get(entry.attribute)
        if raw is None or isinstance(raw, bool):
            return None
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        stamp = _parse_stamp(values.get("timestamp"))
        if stamp is None or not self._fresh(stamp, now):
            return None
        event_id, correlation_id = self._observation_ids(
            entry.entity_id, entry.attribute, stamp
        )
        return SensorReading(
            event_id=event_id,
            # correlation_id binds one poll batch to one entity observation.
            correlation_id=correlation_id,
            occurred_at=stamp,
            sensor_id=entry.sensor_id,
            sensor_type=entry.measurement,
            value=value,
            unit=entry.unit,
            attributes={
                "zone_id": entry.entity_id.split("-")[1].upper() if "-" in entry.entity_id else "",
                "source": "snap4city",
                "entity_id": entry.entity_id,
                "attribute": entry.attribute,
                "entity_timestamp": values.get("timestamp"),
            },
        )

    async def poll(self) -> tuple[list[SensorReading], PollStats]:
        stats = PollStats()
        now = self._now or datetime.now(UTC)
        base = ""
        if self.settings.orion_base_url:
            base = str(self.settings.orion_base_url).rstrip("/")
        if not base:
            raise PollError("orion_base_url is not configured")
        entities: dict[str, SensorMapping] = {}
        for entry in self.mapping.sensors:
            entities.setdefault(entry.entity_id, entry)
        readings: list[SensorReading] = []
        async with httpx.AsyncClient(
            transport=self.transport,
            timeout=self.settings.command_timeout_seconds,
            trust_env=False,
        ) as client:
            for entity_id, first in entities.items():
                url = f"{base}/v2/entities/{entity_id}"
                try:
                    response = await client.get(
                        url,
                        params={"type": first.ngsi_type, "elementid": entity_id},
                    )
                except (httpx.TimeoutException, httpx.NetworkError) as exc:
                    stats.errors.append(f"{entity_id}: {type(exc).__name__}")
                    raise PollError(f"broker unavailable for {entity_id}") from exc
                stats.fetched += 1
                if response.status_code != 200:
                    stats.errors.append(f"{entity_id}: HTTP {response.status_code}")
                    continue
                try:
                    entity = response.json()
                except ValueError:
                    stats.errors.append(f"{entity_id}: response is not JSON")
                    continue
                if not isinstance(entity, dict):
                    stats.errors.append(f"{entity_id}: unexpected payload shape")
                    continue
                values = _flatten(entity)
                for entry in (m for m in self.mapping.sensors if m.entity_id == entity_id):
                    if values.get(entry.attribute) is None:
                        stats.skipped_unmapped += 1
                        continue
                    reading = self._to_reading(entry, values, entity.get("type"), now)
                    if reading is None:
                        stats.skipped_invalid += 1
                        continue
                    prior = self._last_seen.get((entry.sensor_id, entry.attribute))
                    if prior is not None and prior[0] == reading.occurred_at:
                        # Identical timestamp replay: deterministic identity
                        # keeps it idempotent — but a conflicting value under
                        # the same identity is a contract violation, never a
                        # silent duplicate.
                        if prior[1] != reading.value:
                            raise PollError(
                                "conflicting value for observation "
                                f"{entry.sensor_id}/{entry.attribute} at "
                                f"{reading.occurred_at.isoformat()}"
                            )
                        stats.duplicates += 1
                        continue
                    stats.emitted += 1
                    self._last_seen[(entry.sensor_id, entry.attribute)] = (
                        reading.occurred_at,
                        reading.value,
                    )
                    readings.append(reading)
        return readings, stats


def event_matches_session(session: Any, reading: SensorReading) -> bool:
    """Verify a stored SensorEvent really is this observation.

    A 409 may mean an idempotent replay (same deterministic ID, same
    canonical content) OR a conflicting event that reused the ID. Only a
    byte-identical canonical hash makes it a replay.
    """
    row = session.get(SensorEvent, reading.event_id)
    return row is not None and row.payload.get("sha256") == event_hash(reading)


async def poll_and_post(
    poller: NgsiTwinPoller,
    client: httpx.AsyncClient,
    twin_api_key: str,
    database: Any | None = None,
) -> dict[str, int]:
    """Poll the broker and push readings through the Brain's own ingestion API.

    A 409 is accepted as an idempotent replay only after verifying the stored
    event's canonical content hash matches the submitted observation; anything
    else fails closed. Any non-202/non-409 response aborts the batch.
    """
    readings, stats = await poller.poll()
    posted = duplicates = conflicts = 0
    headers = {"X-API-Key": twin_api_key}
    for reading in readings:
        response = await client.post(
            "/readings", json=reading.model_dump(mode="json"), headers=headers
        )
        if response.status_code == 202:
            posted += 1
        elif response.status_code == 409:
            if database is None:
                # No way to verify stored content: fail closed.
                conflicts += 1
                continue
            with database.transaction() as session:
                if event_matches_session(session, reading):
                    duplicates += 1
                else:
                    conflicts += 1
        else:
            response.raise_for_status()
    return {
        "posted": posted,
        "duplicates": duplicates + stats.duplicates,
        "conflicts": conflicts,
        "skipped": stats.skipped_unmapped + stats.skipped_invalid,
        "fetched": stats.fetched,
    }


class NgsiTwinIngestWorker:
    """Opt-in background worker that polls the real Twin and posts readings.

    Started only by explicit configuration; one instance per configured
    application (constructing two workers against the same deterministic
    identity space is safe — duplicates are suppressed, and a conflicting
    value under one identity fails closed). Clean startup/shutdown; the HTTP
    client is created per cycle and never leaked. No fallback to mocks.
    """

    def __init__(
        self,
        poller: NgsiTwinPoller,
        brain_base_url: str,
        twin_api_key: str,
        database: Any,
        poll_seconds: float,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.poller = poller
        self.brain_base_url = brain_base_url.rstrip("/")
        self.twin_api_key = twin_api_key
        self.database = database
        self.poll_seconds = poll_seconds
        self.transport = transport
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self.last_error: str | None = None

    @classmethod
    def from_settings(cls, settings: Settings, database: Any) -> "NgsiTwinIngestWorker":
        if not settings.snap4city_ingest_enabled:
            raise PollError("snap4city ingestion is disabled by configuration")
        poller = NgsiTwinPoller(settings, load_mapping(settings.snap4city_devices_file))
        return cls(
            poller,
            str(settings.brain_base_url),
            settings.twin_api_key.get_secret_value(),
            database,
            settings.snap4city_poll_seconds,
        )

    async def cycle(self) -> dict[str, int]:
        async with httpx.AsyncClient(
            base_url=self.brain_base_url, transport=self.transport, trust_env=False
        ) as client:
            return await poll_and_post(
                self.poller, client, self.twin_api_key, database=self.database
            )

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self.cycle()
                self.last_error = None
            except Exception as exc:  # noqa: BLE001 - worker must survive errors
                self.last_error = f"{type(exc).__name__}: {exc}"
                logger.warning("snap4city_poll_failed error=%s", self.last_error)
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


def poller_from_settings(settings: Settings) -> NgsiTwinPoller:
    """Build a poller from configuration; fail-closed when real mode is on."""
    if not settings.snap4city_ingest_enabled:
        raise PollError("snap4city ingestion is disabled by configuration")
    return NgsiTwinPoller(settings, load_mapping(settings.snap4city_devices_file))
