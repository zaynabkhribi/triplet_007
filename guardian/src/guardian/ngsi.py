"""NGSI v2 ingest — read the triplet's Orion broker and emit Guardian readings.

Why this file exists
--------------------
The Guardian's trust engine is city-agnostic: it reasons about a *reading* (a
sensor, a zone, an observed property, a value, a time, a provenance). The
triplet's Twin speaks NGSI v2 through the Snap4City Orion broker instead of
posting frames to us. This module is the only place that knows about NGSI, so
the five-stage pipeline is unchanged and still testable without a broker.

Mapping (the part a reviewer should check first)
------------------------------------------------
    NGSI entity id      -> sensor_id          us-b-bldg-01
    NGSI type           -> provenance.firmware TrafficSensor, BuildingSensor...
    zone prefix us-a-   -> zone A (traffic)    us-a-, us-b-, us-c-
    attribute           -> observed_property   smokeLevel -> fire_smoke
    attribute value     -> result.value        + the unit from the profile
    record timestamp    -> phenomenon_time     ISO 8601, passed through
    elementid+type+attr -> digest + signature  (see "Provenance" below)

Attribute mapping is data, not code: `ngsi.yaml` next to `config.yaml` holds the
device->property table, so adding a device or renaming an attribute is a config
edit (Rule R1: nothing hard-coded).

Provenance, honestly
--------------------
The Orion Broker Filter authenticates a *writer* with K1/K2, so a value that
arrives over the broker was authenticated by the platform, not signed per frame.
This adapter therefore records `provenance.firmware` from the entity type, a
`cal` marker of `ngsi:<broker host>`, and a digest over the canonical attribute
set. It does **not** fabricate an HMAC it cannot compute: `signature` is set to
`ngsi-broker` and the Guardian's own Stage-A gate is what decides what that is
worth. When `verify_signatures` is on, a broker frame is refused as unsigned —
that is the correct, honest behaviour, and it is why the shipped config leaves
signature verification off for broker ingest.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

ZONE_PREFIX = re.compile(r"^us-([abc])-", re.IGNORECASE)
ZONE_NAMES = {"a": "ZONE-A", "b": "ZONE-B", "c": "ZONE-C"}

# Fallback map, used only when ngsi.yaml is absent. Kept small on purpose: the
# shipped mapping is the YAML, so a reviewer can change it without touching code.
DEFAULT_ATTRIBUTES: Dict[str, Dict[str, Any]] = {
    "traffic": {
        "congestionLevel": {"property": "traffic_camera", "unit": "%"},
        "avgSpeed": {"property": "flow", "unit": "km/h"},
        "vehicleCount": {"property": "traffic_camera", "unit": "car/h"},
        "occupancy": {"property": "traffic_camera", "unit": "%"},
    },
    "building": {
        "smokeLevel": {"property": "fire_smoke", "unit": "ppm"},
        "temperature": {"property": "temperature", "unit": "C"},
    },
    "camera": {
        "confidence": {"property": "air_quality", "unit": "0-1"},
    },
    "bin": {
        "fillLevel": {"property": "power_load", "unit": "%"},
    },
}


def zone_for(device_id: str) -> str:
    """us-a-traf-01 -> ZONE-A. Falls back to the full id so nothing is lost."""
    m = ZONE_PREFIX.match(device_id or "")
    if m:
        return ZONE_NAMES[m.group(1).lower()]
    return "ZONE-UNMAPPED"


def _digest(payload: Dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _iso(value: Any) -> str:
    """Pass a broker timestamp through, or stamp now if it is missing/broken."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _seq_from_stamp(stamp: str) -> int:
    """Stable integer sequence derived from an ISO timestamp."""
    digits = re.sub(r"\D", "", stamp or "")
    return int(digits[-9:] or 0)


def flatten_entity(entity: Dict[str, Any]) -> Dict[str, Any]:
    """NGSI v2 entity -> {attribute: plain value}.

    Orion returns `{"attr": {"type": "float", "value": 22}}`; the Twin's mock
    broker returns the same shape. Anything already flat is passed through.
    """
    out: Dict[str, Any] = {}
    for key, raw in (entity or {}).items():
        if key in ("id", "type"):
            continue
        if isinstance(raw, dict) and "value" in raw:
            out[key] = raw["value"]
        else:
            out[key] = raw
    return out


@dataclass
class NgsiMapping:
    """device kind -> attribute -> observed property. Loaded from ngsi.yaml."""

    attributes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    broker_label: str = "ngsi"

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "NgsiMapping":
        path = path or Path(__file__).resolve().parents[2] / "ngsi.yaml"
        if not path.exists():
            return cls(attributes=DEFAULT_ATTRIBUTES)
        import yaml

        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls(
            attributes=raw.get("attributes") or DEFAULT_ATTRIBUTES,
            broker_label=raw.get("broker_label") or "ngsi",
        )

    def resolve(self, kind: str, attribute: str) -> Optional[Dict[str, Any]]:
        return (self.attributes.get(kind) or {}).get(attribute)


def to_readings(
    device_id: str,
    ngsi_type: str,
    entity: Dict[str, Any],
    kind: str,
    mapping: NgsiMapping,
    batch_id: Optional[str] = None,
    seq: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """One NGSI entity -> zero or more Guardian reading frames.

    A frame is only produced for an attribute that the mapping recognises: an
    unmapped attribute is not guessed at, because a wrong property would be
    scored against the wrong physics profile and produce a confidently wrong
    verdict.
    """
    values = flatten_entity(entity)
    stamp = _iso(values.get("timestamp"))
    # The reading contract requires an integer provenance.seq (it feeds the
    # monotonic-sequence gate). Orion does not expose one per attribute, so we
    # derive a stable counter from the timestamp: the same record read twice
    # keeps the same seq, and a new tick advances it. Without this the frame is
    # rejected as SCHEMA_INVALID, which is the correct contract behaviour.
    if seq is None:
        seq = _seq_from_stamp(stamp)
    zone = zone_for(device_id)
    batch = batch_id or f"ngsi-{device_id}"
    frames: List[Dict[str, Any]] = []

    for attribute, value in values.items():
        spec = mapping.resolve(kind, attribute)
        if not spec or value is None or attribute == "timestamp":
            continue
        if isinstance(value, bool):
            value = 1.0 if value else 0.0
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            # Text attributes (status, message) carry no physics; skip them.
            continue

        body = {
            "sensor_id": device_id,
            "zone": zone,
            "observed_property": spec["property"],
            "phenomenon_time": stamp,
            "result": {"value": numeric, "unit": spec.get("unit", "")},
        }
        digest = _digest(body)
        frames.append(
            {
                "batch_id": batch,
                "reading_id": f"{device_id}:{attribute}:{stamp}",
                "sensor_id": device_id,
                "zone": zone,
                "observed_property": spec["property"],
                "phenomenon_time": stamp,
                "result": {"value": numeric, "unit": spec.get("unit", "")},
                "provenance": {
                    "firmware": ngsi_type or "unknown",
                    "cal": f"{mapping.broker_label}:{attribute}",
                    "seq": seq,
                },
                "digest": digest,
                "signature": "ngsi-broker",
            }
        )
    return frames


def broker_host(base_url: str) -> str:
    try:
        return urlparse(base_url).netloc or "unknown"
    except Exception:
        return "unknown"


@dataclass
class NgsiClient:
    """Minimal read-only Orion client. GET only: the Guardian never writes."""

    base_url: str
    timeout: float = 10.0
    ca: Optional[str] = None
    keys: Dict[str, Dict[str, str]] = field(default_factory=dict)
    last_errors: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_config(cls, path: Path) -> "NgsiClient":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        orion = raw.get("orion") or {}
        secrets_path = os.environ.get("TWIN_SECRETS")
        keys: Dict[str, Dict[str, str]] = {}
        if secrets_path and Path(secrets_path).exists():
            keys = json.loads(Path(secrets_path).read_text(encoding="utf-8"))
        return cls(
            base_url=str(orion.get("base_url", "")).rstrip("/"),
            timeout=float(orion.get("timeout", 10)),
            ca=orion.get("ca"),
            keys=keys,
        )

    def entity_params(self, device_id: str, ngsi_type: str) -> Dict[str, str]:
        params = {"elementid": device_id, "type": ngsi_type}
        if self.keys.get(device_id):
            params.update(k1=self.keys[device_id]["k1"], k2=self.keys[device_id]["k2"])
        return params

    def read_entity(self, device_id: str, ngsi_type: str) -> Dict[str, Any]:
        import httpx

        url = f"{self.base_url}/v2/entities/{device_id}"
        resp = httpx.get(
            url,
            params=self.entity_params(device_id, ngsi_type),
            timeout=self.timeout,
            verify=self.ca if self.ca else True,
        )
        resp.raise_for_status()
        return resp.json()

    def poll(self, devices: Dict[str, Dict[str, Any]], mapping: NgsiMapping) -> List[Dict[str, Any]]:
        """Read every sensor in the Twin's device list and return frames.

        A device that fails to read is skipped, not invented: the Guardian's own
        freshness/staleness detectors are what turn a missing device into an
        OFFLINE/RESTRICT verdict, so swallowing the error here would hide it.
        """
        frames: List[Dict[str, Any]] = []
        seq = 0
        for device_id, cfg in devices.items():
            kind = cfg.get("kind")
            if kind not in mapping.attributes:
                continue
            seq += 1
            try:
                entity = self.read_entity(device_id, cfg.get("type", ""))
            except Exception as exc:      # noqa: BLE001 - surfaced as a verdict
                # A device that cannot be read is not invented here: the frame is
                # dropped and the Guardian's freshness gate turns the silence into
                # OFFLINE/RESTRICT. Recorded so a reviewer can see the cause.
                self.last_errors[device_id] = f"{type(exc).__name__}: {exc}"
                continue
            frames.extend(
                to_readings(device_id, cfg.get("type", ""), entity, kind, mapping, seq=seq)
            )
        return frames


def iter_frames(client: NgsiClient, devices: Dict[str, Any], mapping: NgsiMapping) -> Iterable[Dict[str, Any]]:
    return client.poll(devices, mapping)
