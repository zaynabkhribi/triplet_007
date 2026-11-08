"""Isolated, read-only Snap4City NGSI-v2 sensor ingestion adapter.

Purpose
-------
Convert NGSI-v2 sensor entity documents (as published by the real Twin through
the Snap4City Orion Broker Filter) into validated Brain ``SensorReading``
candidates. This module is deliberately isolated:

* It is NOT wired into the event worker, coordinator, or application startup.
* It performs read-only ``GET /v2/entities/{id}`` calls only; it never writes.
* It never creates GuardianVerdict objects, event hashes for verdicts,
  guardian identities, or verdict revisions. Candidates carry no trust state;
  they become trusted only through the existing TrustEngine once compatible,
  authenticated Guardian verdicts arrive (future task).
* Every accepted observation keeps the exact sensor identity and observation
  timestamp provided by the broker. Nothing is re-stamped or inferred.

Grounding (audited repository sources, not invented)
----------------------------------------------------
* Device ids and NGSI entity types: ``twin/config.json`` (kind + type).
* Attribute -> measured property -> unit mapping: ``guardian/ngsi.yaml``
  (the Guardian team's published contract) cross-checked against
  ``twin/INTERFACE-DETAILS.md`` section 4.
* Wire attribute shape ``{"type": ..., "value": ...}``:
  ``twin/src/schema.py:to_attr`` and ``guardian/ngsi.py:flatten_entity``.
* Broker per-publish ``timestamp`` attribute (ISO 8601 UTC string):
  ``twin/INTERFACE.md`` "Data out of the Twin" and ``twin/src/model.py``.

Known limitations (documented, not hidden)
------------------------------------------
* Orion v2 GET responses carry no per-attribute modification metadata that the
  Twin populates (the Twin sends its own ``timestamp`` attribute each tick).
  Observation identity is therefore derived from the observable content:
  (entity id, attribute, timestamp, value). If the Twin ever publishes the
  same observation without a timestamp, the entity is rejected rather than
  receiving a fabricated time. This is a reported limitation, not solved by
  invented assumptions about broker-side versioning.
* Deduplication is exact-observation based: an observation is skipped only
  when the broker shows the identical observation again (same entity,
  attribute, timestamp AND value). A new timestamp with an unchanged value is
  a genuine new measurement (for example a stuck sensor that still reports)
  and is emitted with its own deterministic event_id.
* Dedup state is in-memory and lost on restart. After a restart the same
  observations are re-emitted with the SAME deterministic event_id (uuid5 of
  observable content), and Brain ingestion durably rejects duplicate event
  ids after restart (brain/INTERFACE.md: "Duplicate IDs remain rejected after
  restart"). Durable idempotency therefore comes from the Brain's own
  duplicate rejection, not from adapter memory.
* Contract conflict (documented, unresolved): guardian/ngsi.yaml maps BOTH
  ``vehicleCount`` (unit car/h) and ``occupancy`` (unit %) to the observed
  property ``traffic_camera``. One property cannot carry two units. These two
  attributes are reported as ``ambiguous_mapping`` rejections instead of
  guessing a unit. This needs Guardian-team confirmation (Twin publishes
  vehicleCount as car/h and occupancy as % per twin/INTERFACE-DETAILS.md §4).
* Attributes the Twin publishes that appear in no agreed mapping (for example
  ``occupancyCount`` on us-b-bldg-01) are reported as ``unsupported_attribute``
  rejections, never silently ignored and never guessed.
* Composite Brain ``sensor_id`` values (``<entity_id>:<property>``) are a
  Brain-side convention chosen so one NGSI entity can carry several measured
  properties. Guardian verdict correlation (future task) must bind verdicts to
  the same composite identity; this requires Guardian-team confirmation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
from pydantic import ValidationError

from app.schemas.sensor import SensorReading

# Deterministic namespace for derived event ids. The id is a pure function of
# observable source content (entity, attribute, timestamp, value); it is not a
# random identity and carries no trust semantics.
_EVENT_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "urn:aegiscity:ngsi-sensor-reading")

# Brain-side schema version used for every candidate (matches brain contracts).
_SCHEMA_VERSION = "1.0.0"

# Source label recorded on each candidate for provenance.
_SOURCE_LABEL = "snap4city_orion"

# ---------------------------------------------------------------------------
# Strict allowlist. Derived from twin/config.json (ids + NGSI types) and
# guardian/ngsi.yaml (attributes -> observed property -> unit). Only these
# sensors and attributes are ever parsed; anything else is rejected.
# ---------------------------------------------------------------------------

AttributeSpec = dict[str, str]  # {"sensor_type": property, "unit": unit}

# NGSI/platform metadata present on broker entities. Mirrors BROKER_ATTRS in
# twin/src/schema.py (plus id/type): never treated as measurements.
_METADATA_KEYS = frozenset(
    {"id", "type", "timestamp", "TimeInstant", "dateModified", "dateCreated",
     "latitude", "longitude", "model"}
)


def _device(
    entity_id: str,
    ngsi_type: str,
    kind: str,
    attributes: dict[str, AttributeSpec],
    excluded: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "entity_id": entity_id,
        "ngsi_type": ngsi_type,
        "kind": kind,
        "attributes": attributes,
        # attribute -> rejection detail (e.g. ambiguous Guardian mapping)
        "excluded": excluded or {},
    }


# kind values come from twin/config.json; attribute keys are the exact NGSI
# attribute names the Twin publishes; property/unit values come from
# guardian/ngsi.yaml.
SENSOR_REGISTRY: dict[str, dict[str, Any]] = {
    device["entity_id"]: device
    for device in (
        _device(
            "us-a-traf-01",
            "TrafficSensor",
            "traffic",
            {
                "congestionLevel": {"sensor_type": "congestion", "unit": "%"},
                "avgSpeed": {"sensor_type": "flow", "unit": "km/h"},
            },
            # guardian/ngsi.yaml maps vehicleCount AND occupancy to the same
            # property (traffic_camera) with conflicting units (car/h vs %).
            # One property cannot carry two units: fail closed until the
            # Guardian team resolves its mapping. Units per twin docs:
            # vehicleCount is car/h, occupancy is % (INTERFACE-DETAILS.md §4).
            excluded={
                "vehicleCount": (
                    "guardian/ngsi.yaml maps vehicleCount and occupancy to the "
                    "same property 'traffic_camera' with conflicting units "
                    "(car/h vs %); unit cannot be chosen without team confirmation"
                ),
                "occupancy": (
                    "guardian/ngsi.yaml maps vehicleCount and occupancy to the "
                    "same property 'traffic_camera' with conflicting units "
                    "(car/h vs %); unit cannot be chosen without team confirmation"
                ),
            },
        ),
        _device(
            "us-a-traf-02",
            "TrafficSensor",
            "traffic",
            {
                "congestionLevel": {"sensor_type": "congestion", "unit": "%"},
                "avgSpeed": {"sensor_type": "flow", "unit": "km/h"},
            },
            # guardian/ngsi.yaml maps vehicleCount AND occupancy to the same
            # property (traffic_camera) with conflicting units (car/h vs %).
            # One property cannot carry two units: fail closed until the
            # Guardian team resolves its mapping. Units per twin docs:
            # vehicleCount is car/h, occupancy is % (INTERFACE-DETAILS.md §4).
            excluded={
                "vehicleCount": (
                    "guardian/ngsi.yaml maps vehicleCount and occupancy to the "
                    "same property 'traffic_camera' with conflicting units "
                    "(car/h vs %); unit cannot be chosen without team confirmation"
                ),
                "occupancy": (
                    "guardian/ngsi.yaml maps vehicleCount and occupancy to the "
                    "same property 'traffic_camera' with conflicting units "
                    "(car/h vs %); unit cannot be chosen without team confirmation"
                ),
            },
        ),
        _device(
            "us-a-traf-03",
            "TrafficSensor",
            "traffic",
            {
                "congestionLevel": {"sensor_type": "congestion", "unit": "%"},
                "avgSpeed": {"sensor_type": "flow", "unit": "km/h"},
            },
            # guardian/ngsi.yaml maps vehicleCount AND occupancy to the same
            # property (traffic_camera) with conflicting units (car/h vs %).
            # One property cannot carry two units: fail closed until the
            # Guardian team resolves its mapping. Units per twin docs:
            # vehicleCount is car/h, occupancy is % (INTERFACE-DETAILS.md §4).
            excluded={
                "vehicleCount": (
                    "guardian/ngsi.yaml maps vehicleCount and occupancy to the "
                    "same property 'traffic_camera' with conflicting units "
                    "(car/h vs %); unit cannot be chosen without team confirmation"
                ),
                "occupancy": (
                    "guardian/ngsi.yaml maps vehicleCount and occupancy to the "
                    "same property 'traffic_camera' with conflicting units "
                    "(car/h vs %); unit cannot be chosen without team confirmation"
                ),
            },
        ),
        _device(
            "us-b-bldg-01",
            "BuildingSensor",
            "building",
            {
                "smokeLevel": {"sensor_type": "fire_smoke", "unit": "ppm"},
                "temperature": {"sensor_type": "temperature", "unit": "C"},
            },
        ),
        _device(
            "us-c-cam-01",
            "IPCamera",
            "camera",
            {
                "confidence": {"sensor_type": "air_quality", "unit": "0-1"},
            },
        ),
        _device(
            "us-c-bin-01",
            "WasteBin",
            "bin",
            {
                "fillLevel": {"sensor_type": "fill_level", "unit": "%"},
            },
        ),
        _device(
            "us-c-bin-02",
            "WasteBin",
            "bin",
            {
                "fillLevel": {"sensor_type": "fill_level", "unit": "%"},
            },
        ),
    )
}


class NgsiIngestError(Exception):
    """A broker payload cannot be converted into trustworthy candidates."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


def _timestamp_value(entity: dict[str, Any]) -> str:
    """Extract the observation timestamp with explicit failure classification.

    Distinct codes: missing_timestamp (attribute absent or empty),
    malformed_timestamp (present but not a usable NGSI attr object or not a
    string). Nothing is ever inferred or defaulted.
    """
    raw = entity.get("timestamp")
    if raw is None:
        raise NgsiIngestError("missing_timestamp", "entity has no timestamp attribute")
    if not isinstance(raw, dict) or "value" not in raw:
        raise NgsiIngestError("malformed_timestamp", "timestamp attribute is not an NGSI attr object")
    value = raw["value"]
    if value is None or (isinstance(value, str) and not value.strip()):
        raise NgsiIngestError("missing_timestamp", "timestamp attribute is empty")
    if not isinstance(value, str):
        raise NgsiIngestError("malformed_timestamp", f"timestamp value {value!r} is not a string")
    return value


def _parse_timestamp(raw: str) -> datetime:
    """Parse the Twin's per-publish ``timestamp`` string. Never inferred."""
    try:
        parsed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise NgsiIngestError("invalid_timestamp", f"unparseable timestamp {raw!r}") from exc
    if parsed.utcoffset() is None:
        raise NgsiIngestError("naive_timestamp", "timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _numeric(value: Any) -> float:
    """Accept finite numbers only. Booleans, strings and non-finites are rejected."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise NgsiIngestError("non_numeric_value", f"value {value!r} is not a number")
    number = float(value)
    if number != number or number in (float("inf"), float("-inf")):
        raise NgsiIngestError("non_finite_value", "value is NaN or infinite")
    return number


def _attribute_value(entity: dict[str, Any], attribute: str) -> Any:
    raw = entity.get(attribute)
    if raw is None:
        raise NgsiIngestError("missing_attribute", f"attribute {attribute!r} absent")
    if not isinstance(raw, dict) or "value" not in raw:
        raise NgsiIngestError("malformed_attribute", f"attribute {attribute!r} is not an NGSI attr object")
    return raw["value"]


def _event_id(entity_id: str, attribute: str, timestamp: datetime, value: float) -> uuid.UUID:
    stamp = timestamp.isoformat()
    key = f"{entity_id}|{attribute}|{stamp}|{value!r}"
    return uuid.uuid5(_EVENT_NAMESPACE, key)


def _candidate(entity_id: str, attribute: str, spec: AttributeSpec, ngsi_type: str, timestamp: datetime, value: float) -> SensorReading:
    return SensorReading(
        event_id=_event_id(entity_id, attribute, timestamp, value),
        correlation_id=uuid.uuid5(_EVENT_NAMESPACE, f"corr|{entity_id}|{attribute}|{timestamp.isoformat()}"),
        occurred_at=timestamp,
        sensor_id=f"{entity_id}:{spec['sensor_type']}",
        sensor_type=spec["sensor_type"],
        value=value,
        unit=spec["unit"],
        attributes={
            "source": _SOURCE_LABEL,
            "ngsi_entity_id": entity_id,
            "ngsi_entity_type": ngsi_type,
            "ngsi_attribute": attribute,
            "ngsi_kind": SENSOR_REGISTRY[entity_id]["kind"],
        },
    )


@dataclass
class EntityParseResult:
    """Outcome of parsing one NGSI entity document."""

    entity_id: str
    readings: list[SensorReading] = field(default_factory=list)
    rejected: list[dict[str, str]] = field(default_factory=list)  # {attribute, code, detail}
    duplicates: list[str] = field(default_factory=list)  # attribute keys skipped as unchanged


def parse_entity(
    entity_id: str,
    entity: Any,
    last_emitted: dict[tuple[str, str], tuple[datetime, float]] | None = None,
    suppress_unchanged: bool = True,
) -> EntityParseResult:
    """Parse one NGSI-v2 entity document into SensorReading candidates.

    ``last_emitted`` maps (entity_id, attribute) -> (timestamp, value) of the
    last observation actually emitted by this adapter instance. When
    ``suppress_unchanged`` is true and the new value equals the stored value,
    the observation is reported as a duplicate instead of a new candidate.
    The caller owns the dedup state; the function itself stays stateless.
    """
    result = EntityParseResult(entity_id=entity_id)
    spec_device = SENSOR_REGISTRY.get(entity_id)
    if spec_device is None:
        raise NgsiIngestError("unknown_entity", f"entity {entity_id!r} is not in the sensor allowlist")
    if not isinstance(entity, dict):
        raise NgsiIngestError("malformed_entity", "broker answer is not a JSON object")
    remote_type = entity.get("type")
    if remote_type != spec_device["ngsi_type"]:
        raise NgsiIngestError(
            "type_mismatch",
            f"entity type {remote_type!r} does not match registered {spec_device['ngsi_type']!r}",
        )

    timestamp = _parse_timestamp(_timestamp_value(entity))

    for attribute, spec in spec_device["attributes"].items():
        try:
            value = _numeric(_attribute_value(entity, attribute))
        except NgsiIngestError as exc:
            result.rejected.append({"attribute": attribute, "code": exc.code, "detail": exc.detail})
            continue
        if last_emitted is not None and suppress_unchanged:
            previous = last_emitted.get((entity_id, attribute))
            # An observation is a duplicate ONLY when the broker shows the very
            # same observation again: same timestamp AND same value. A new
            # timestamp with an unchanged value is a genuine new measurement
            # (e.g. a stuck sensor that still reports) and is emitted with its
            # own deterministic event_id.
            if previous is not None and previous == (timestamp, value):
                result.duplicates.append(attribute)
                continue
        try:
            result.readings.append(
                _candidate(entity_id, attribute, spec, spec_device["ngsi_type"], timestamp, value)
            )
        except ValidationError as exc:  # defensive: schema drift must fail loudly
            result.rejected.append({"attribute": attribute, "code": "schema_invalid", "detail": str(exc)})
            continue
        if last_emitted is not None:
            last_emitted[(entity_id, attribute)] = (timestamp, value)

    # Report every non-metadata attribute that the agreed mapping does not
    # cover. Nothing outside the allowlist is silently ignored, and nothing is
    # guessed into a measurement.
    excluded = spec_device["excluded"]
    for attribute in entity:
        if attribute in spec_device["attributes"] or attribute in _METADATA_KEYS:
            continue
        if attribute in excluded:
            result.rejected.append(
                {"attribute": attribute, "code": "ambiguous_mapping", "detail": excluded[attribute]}
            )
        else:
            result.rejected.append(
                {
                    "attribute": attribute,
                    "code": "unsupported_attribute",
                    "detail": "not part of the agreed sensor/attribute mapping "
                    "(twin/config.json + guardian/ngsi.yaml)",
                }
            )
    return result


@dataclass
class PollResult:
    """Aggregated outcome of one polling pass over the whole allowlist."""

    readings: list[SensorReading] = field(default_factory=list)
    rejected: list[dict[str, str]] = field(default_factory=list)
    duplicates: list[str] = field(default_factory=list)
    unavailable: list[dict[str, str]] = field(default_factory=list)  # {entity_id, code}

    @property
    def empty(self) -> bool:
        return not (self.readings or self.rejected or self.duplicates or self.unavailable)


class NgsiSensorPoller:
    """Read-only polling client for the Snap4City Orion Broker Filter.

    The transport is injectable (``httpx.MockTransport`` in tests). Without an
    explicit ``base_url`` the poller refuses to run: there is no default host
    and no implicit live contact.
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 5.0,
        transport: httpx.AsyncBaseTransport | None = None,
        suppress_unchanged: bool = True,
    ) -> None:
        if base_url is None and transport is None:
            raise NgsiIngestError("not_configured", "base_url is required for live polling")
        self.base_url = base_url.rstrip("/") if base_url else None
        self.timeout = timeout
        self.transport = transport
        self.suppress_unchanged = suppress_unchanged
        self._last_emitted: dict[tuple[str, str], tuple[datetime, float]] = {}
        self._requests: list[str] = []

    async def poll(self) -> PollResult:
        """Fetch every allowlisted sensor entity once and parse the answers."""
        if self.base_url is None:
            raise NgsiIngestError("not_configured", "base_url is required for live polling")
        result = PollResult()
        async with httpx.AsyncClient(
            transport=self.transport, timeout=self.timeout, trust_env=False
        ) as client:
            for entity_id, device in SENSOR_REGISTRY.items():
                url = f"{self.base_url}/v2/entities/{entity_id}"
                self._requests.append(url)
                try:
                    response = await client.get(url)
                except httpx.HTTPError as exc:
                    result.unavailable.append(
                        {"entity_id": entity_id, "code": "transport_error", "detail": str(exc)}
                    )
                    continue
                if response.status_code == 404:
                    # A sensor that has not published yet is not invented here.
                    result.unavailable.append({"entity_id": entity_id, "code": "not_found", "detail": ""})
                    continue
                if response.status_code != 200:
                    result.unavailable.append(
                        {"entity_id": entity_id, "code": f"http_{response.status_code}", "detail": ""}
                    )
                    continue
                try:
                    entity = response.json()
                except ValueError:
                    result.unavailable.append({"entity_id": entity_id, "code": "invalid_json", "detail": ""})
                    continue
                try:
                    parsed = parse_entity(
                        entity_id,
                        entity,
                        last_emitted=self._last_emitted,
                        suppress_unchanged=self.suppress_unchanged,
                    )
                except NgsiIngestError as exc:
                    result.unavailable.append({"entity_id": entity_id, "code": exc.code, "detail": exc.detail})
                    continue
                result.readings.extend(parsed.readings)
                result.rejected.extend(
                    {"entity_id": entity_id, **item} for item in parsed.rejected
                )
                result.duplicates.extend(f"{entity_id}:{attribute}" for attribute in parsed.duplicates)
        return result

    @property
    def requested_urls(self) -> list[str]:
        """URLs requested so far (test introspection: proves GET-only usage)."""
        return list(self._requests)
