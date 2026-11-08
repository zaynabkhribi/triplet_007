"""Orion-facing faces: device aggregation and NGSI verdict publication.

Why this file exists
--------------------
The trust pipeline reasons per *reading*. The triplet, however, speaks per
*device*: the Twin's timeline and the Brain consume one verdict per entity
(`{"us-b-bldg-01": {"verdict": ..., "reason": ..., "checked": ...}}`), and the
root contract (INTEGRATION.md) has the Guardian *write* its verdicts back into
the broker. This module is the only place that knows about that device face, so
the five-stage pipeline stays untouched and device semantics cannot leak into it.

Two responsibilities, tested independently of the broker:

1. `aggregate_by_device` — the per-property verdict records from Stage E become
   one verdict per NGSI entity. The rule is honest about the direction:
   the *worst* property decides the device (a building whose smoke is
   untrusted cannot be trusted because its thermometer is fine).
2. `VerdictWriter` — publishes aggregate verdicts as NGSI `TrustVerdict`
   entities. It is OFF by default: the `/verdicts` JSON feed already serves the
   Twin's timeline, and writing to the broker needs the Guardian's own K1/K2
   keys, which are never committed.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Property-level disposition -> the single word the Twin/Brain vocabulary uses.
# A SUSPECT device is untrusted even if no single proof of malice exists: the
# Brain acts on trust, and "suspicious" is not trust. The mock Guardian the Twin
# ships also uses OFFLINE for devices it cannot read, so we do the same.
_DISPOSITION_WORD = {
    "TRUSTED": "TRUSTED",
    "SUSPECT": "UNTRUSTED",
    "RESTRICT": "UNTRUSTED",
    "MALICIOUS": "UNTRUSTED",
}

# Worse -> smaller, so `min(...)` is a device's WORST property and `max(...)` its
# best. Used by both the aggregation rule and the wire shape.
_SEVERITY = {"MALICIOUS": 0, "RESTRICT": 1, "SUSPECT": 2, "TRUSTED": 3}

_TEXT_FORBIDDEN = "<>\"'=;()"


def _clean_text(text: str, limit: int = 200) -> str:
    """The Orion broker refuses `< > " ' = ; ( )` in text attributes (twin/INTERFACE.md).

    Reason codes are stable tokens with no such characters; free-text detail is
    stripped defensively so a diagnostic can never wedge the writer.
    """
    for ch in _TEXT_FORBIDDEN:
        text = text.replace(ch, " ")
    return " ".join(text.split())[:limit]


@dataclass
class DeviceVerdict:
    """One row of the device face: what the Brain reads in one request."""

    device_id: str
    word: str                      # TRUSTED | UNTRUSTED | OFFLINE
    reason: str                    # comma-joined reason codes, worst first
    trust: float                   # lowest trust of the device's properties
    zone: str
    checked: str                   # HH:MM:SS of the verdict that produced this row
    properties: Dict[str, Any] = field(default_factory=dict)   # per-property detail
    evidence_digest: str = ""      # passport trail of the WORST property

    def wire(self) -> Dict[str, Any]:
        """The triplet wire shape (twin/mocks/mock_guardian.py) — three contract
        keys first, evidence behind them for anyone who wants to check.

        An OFFLINE inventory row has no per-property evidence, so it reports the
        disposition its word already implies rather than an empty string: the
        field is always one of the four, never blank.
        """
        entry = {
            "verdict": self.word,
            "reason": self.reason,
            "checked": self.checked,
            # richer keys, additive-only: consumers that want more, get more
            "trust": round(self.trust, 3),
            "zone": self.zone,
            # The device's own disposition is its WORST property's: a building
            # whose smoke is MALICIOUS is not SUSPECT because its thermometer
            # is fine. `_SEVERITY` maps worse -> smaller, so min() is the worst.
            "disposition": min(
                (p.get("disposition", "SUSPECT") for p in self.properties.values()),
                key=lambda d: _SEVERITY.get(d, 2),
                default="RESTRICT" if self.word == "OFFLINE" else "TRUSTED",
            ),
            "properties": self.properties,
        }
        if self.evidence_digest:
            entry["evidence_digest"] = self.evidence_digest
        return entry


def aggregate_by_device(
    verdicts: List[Any],
    *,
    now: Optional[float] = None,
    stale_after_s: float = 20.0,
) -> Dict[str, DeviceVerdict]:
    """Fold the pipeline's per-property verdict records into per-device verdicts.

    * latest record per `(sensor_id, observed_property)` wins;
    * a device's word is decided by its WORST property (malice in one attribute
      is not healed by virtue in another);
    * no new verdict for `stale_after_s` (or none at all) -> OFFLINE, the same
      word the Twin's mock Guardian uses for a device it cannot read. This is
      the g2 "dead sensor" signature: the broker keeps the last entity, so only
      the absence of fresh verdicts reveals it.
    """
    now = now if now is not None else time.time()
    latest: Dict[Tuple[str, str], Any] = {}
    for rec in verdicts:
        key = (rec.sensor_id, rec.observed_property)
        prev = latest.get(key)
        if prev is None or rec.verified_at >= prev.verified_at:
            latest[key] = rec

    devices: Dict[str, Dict[str, Any]] = {}
    for (device_id, prop), rec in sorted(latest.items()):
        age = now - rec.verified_at
        word = _DISPOSITION_WORD.get(rec.disposition, "UNTRUSTED")
        reasons = sorted(set(rec.reason_codes))
        if word == "TRUSTED" and age > stale_after_s:
            # Staleness is this module's finding, not the pipeline's: add the
            # reason to the ROW, never mutate the evidence record itself (the
            # same record is still served, unchanged, by /v1/verdict).
            word, reasons = "OFFLINE", ["COMM_LOSS"]
        devices.setdefault(device_id, {"props": {}, "zone": rec.zone})
        devices[device_id]["props"][prop] = {
            "verdict": word,
            "trust": round(rec.trust, 3),
            "disposition": rec.disposition,
            "reasons": reasons,
            "age_s": round(max(age, 0.0), 1),
            "evidence_digest": getattr(rec, "evidence_digest", ""),
        }

    order = {"OFFLINE": 0, "UNTRUSTED": 1, "TRUSTED": 2}
    out: Dict[str, DeviceVerdict] = {}
    for device_id, bundle in sorted(devices.items()):
        props = bundle["props"]
        worst_word = min(props.values(), key=lambda p: order.get(p["verdict"], 1))
        worst_prop = min(props.values(), key=lambda p: _SEVERITY.get(p["disposition"], 2))
        reasons: List[str] = []
        for word in (worst_word["verdict"],):
            for _prop, p in props.items():
                if p["verdict"] == word or p["disposition"] != "TRUSTED":
                    reasons.extend(p["reasons"])
        out[device_id] = DeviceVerdict(
            device_id=device_id,
            word=worst_word["verdict"],
            reason=_clean_text(", ".join(dict.fromkeys(reasons))) or "OK",
            trust=min(p["trust"] for p in props.values()),
            zone=bundle["zone"],
            checked=time.strftime("%H:%M:%S", time.localtime(max(
                r.verified_at for r in latest.values()
                if r.sensor_id == device_id))),
            properties=props,
            # the evidence hash behind the WORST property — the passport trail
            evidence_digest=str(worst_prop.get("evidence_digest", "") or ""),
        )
    return out


def catalog_offline(
    sensors: Dict[str, Dict[str, Any]],
    mapped_kinds: set,
    *,
    now: float,
    zone_for,
) -> Dict[str, DeviceVerdict]:
    """OFFLINE rows for mapped devices that no verdict has ever covered.

    A device that the Guardian has never seen (dead since startup, or not yet
    published) would otherwise vanish from the device face. The Twin's mock
    Guardian answers OFFLINE with a COMM_LOSS reason in that case, and so do we:
    honesty about the edge is the difference between a verdict and a guess.
    Only devices whose `kind` is actually mapped are listed — actuators that
    publish no sensor physics get no verdict, same as the mock's SENSOR_KINDS.
    """
    out: Dict[str, DeviceVerdict] = {}
    for device_id, cfg in sorted(sensors.items()):
        if cfg.get("kind") not in mapped_kinds:
            continue
        checked = time.strftime("%H:%M:%S", time.localtime(now))
        out[device_id] = DeviceVerdict(
            device_id=device_id, word="OFFLINE", reason="COMM_LOSS", trust=0.0,
            zone=zone_for(device_id), checked=checked,
            properties={},
        )
    return out


def device_face(
    verdicts: List[Any],
    *,
    now: Optional[float] = None,
    stale_after_s: float = 20.0,
    sensors: Optional[Dict[str, Dict[str, Any]]] = None,
    mapped_kinds: Optional[set] = None,
    zone_for=None,
) -> Dict[str, DeviceVerdict]:
    """The complete per-device face: aggregated verdicts + OFFLINE inventory rows.

    `zone_for` is injected (it lives in ngsi.py) to keep this module free of
    NGSI imports at the aggregation layer.
    """
    merged = aggregate_by_device(verdicts, now=now, stale_after_s=stale_after_s)
    if sensors and mapped_kinds and zone_for is not None:
        for device_id, row in catalog_offline(sensors, mapped_kinds, now=now, zone_for=zone_for).items():
            merged.setdefault(device_id, row)
    return merged


class DeviceCatalog:
    """Device ids/types that will be polled. Data, not code (Rule R1).

    Default: a shipped snapshot of the twin's device list (`orion_devices.json`
    inside this folder). Overridable with `GUARDIAN_DEVICES_CONFIG` pointing at
    any twin-style `config.json` — which is how a rematch proves we belong to
    the contract, and not to one team's copy of it.

    An explicit path that cannot be read raises: a catalog the operator asked
    for and did not get is a boot problem, and silently polling the snapshot
    instead would judge the wrong city.
    """

    def __init__(self, path: Optional[str]) -> None:
        self.path = path
        self.source: str = ""
        self._devices: Dict[str, Dict[str, Any]] = {}
        self.reload()

    def reload(self) -> None:
        if self.path:
            raw = json.loads(Path(self.path).read_text(encoding="utf-8"))
            self._devices = raw.get("devices", {}) or {}
            self.source = str(self.path)
            return
        default = Path(__file__).resolve().parents[2] / "orion_devices.json"
        try:
            raw = json.loads(default.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # The shipped snapshot is part of the deliverable; if it is missing
            # the deployment is incomplete, and saying so beats polling nothing.
            raise FileNotFoundError(
                f"shipped device snapshot missing or unreadable: {default}"
            ) from None
        self._devices = raw.get("devices", {}) or {}
        self.source = default.name + " (shipped snapshot)"

    def sensors(self) -> Dict[str, Dict[str, Any]]:
        """Mapped (sensor) devices only; the fixture kinds for actuators are
        filtered later by the attribute map, so passing all of them is fine."""
        return dict(self._devices)


class VerdictWriter:
    """Writes aggregate verdicts back into Orion as `TrustVerdict` entities.

    Contract status (root INTEGRATION.md asks the Guardian to confirm "the
    verdict format"): entity per device, id `<device>-verdict`, type
    `TrustVerdict`, attributes `verdict | reason | trust | zone | checked`,
    patched with the Guardian's own K1/K2 keys from `guardian_secrets.json`
    (gitignored). OFF until keys are actually loaded — a verdict feed needs no
    keys, so bring-up works before the platform hands out credentials.
    """

    LIMIT = 50  # PATCHes per cycle: bound the blast radius, not the honesty

    def __init__(self, base_url: str, timeout: float, entity_suffix: str,
                 entity_type: str, keys_path: Optional[str]) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.entity_suffix = entity_suffix
        self.entity_type = entity_type
        self.keys_path = keys_path
        self.keys: Dict[str, Dict[str, str]] = {}
        self.last_errors: Dict[str, str] = {}
        self.written: int = 0
        self.active: bool = False
        self.reload_keys()

    def reload_keys(self) -> None:
        if not self.keys_path or not Path(self.keys_path).exists():
            self.active = False
            return
        raw = json.loads(Path(self.keys_path).read_text(encoding="utf-8"))
        devices = raw.get("devices", {}) if isinstance(raw, dict) else {}
        self.keys = {k: v for k, v in devices.items()
                     if isinstance(v, dict) and v.get("k1") and v.get("k2")}
        self.active = bool(self.keys)

    def _params(self, entity_id: str) -> Dict[str, str]:
        params: Dict[str, str] = {"elementid": entity_id, "type": self.entity_type}
        key = self.keys.get(entity_id)
        if key:
            params.update(k1=key["k1"], k2=key["k2"])
        return params

    @staticmethod
    def _attrs(v: DeviceVerdict) -> Dict[str, Dict[str, Any]]:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
        return {
            "verdict": {"type": "string", "value": v.word},
            "reason": {"type": "string", "value": _clean_text(v.reason, 120)},
            "trust": {"type": "float", "value": round(v.trust, 3)},
            "zone": {"type": "string", "value": _clean_text(v.zone, 60)},
            "checked": {"type": "string", "value": v.checked},
            "timestamp": {"type": "string", "value": stamp},
        }

    def publish(self, verdicts: Dict[str, DeviceVerdict]) -> Tuple[int, int]:
        """Best-effort publish. Returns (written, skipped). Fails soft: a
        broker hiccup must never strip verdicts from the /verdicts feed."""
        if not self.active:
            return 0, len(verdicts)
        import httpx

        written = skipped = 0
        for device_id, v in list(verdicts.items())[: self.LIMIT]:
            entity_id = device_id + self.entity_suffix
            url = f"{self.base_url}/v2/entities/{entity_id}/attrs"
            try:
                resp = httpx.patch(url, params=self._params(entity_id),
                                   json=self._attrs(v), timeout=self.timeout)
                if resp.status_code in (200, 204):
                    written += 1
                    continue
                if resp.status_code == 404:   # first contact: create the entity
                    create = f"{self.base_url}/v2/entities"
                    body = self._attrs(v)
                    resp2 = httpx.post(create, params=self._params(entity_id),
                                       json=body, timeout=self.timeout)
                    if resp2.status_code in (200, 201, 204):
                        written += 1
                        continue
                self.last_errors[entity_id] = f"HTTP {resp.status_code}"
                skipped += 1
            except Exception as exc:          # noqa: BLE001 - surfaced on /orion/status
                self.last_errors[entity_id] = f"{type(exc).__name__}"
                skipped += 1
        self.written += written
        return written, skipped


class OrionPoller(threading.Thread):
    """Background poll loop: broker -> pipeline -> device verdicts -> writer.

    Runs as a daemon thread so the API process can simply be started with
    docker compose; the loop is stateless across cycles (the pipeline keeps the
    windows), so a crash inside one cycle is logged and the next tick simply
    runs. `stop()` joins within one poll interval — the container is stopped
    only between cycles, by construction of tick-driven systems.
    """

    def __init__(self, pipeline, mapping, catalog: DeviceCatalog,
                 base_url: str, *, poll_seconds: float, timeout: float,
                 stale_after_s: float, writer: Optional[VerdictWriter],
                 cycle_hook=None) -> None:
        super().__init__(name="guardian-orion-poller", daemon=True)
        self.pipeline = pipeline
        self.mapping = mapping
        self.catalog = catalog
        self.client = self._client(base_url, timeout)
        self.poll_seconds = max(float(poll_seconds), 0.05)
        self.stale_after_s = float(stale_after_s)
        self.writer = writer
        self.cycle_hook = cycle_hook          # callable(device_verdicts) for tests
        self.stop_flag = threading.Event()
        self.cycles = 0
        self.last_cycle_at: float = 0.0
        self.last_summary: Dict[str, Any] = {}
        self.errors: List[str] = []

    @staticmethod
    def _client(base_url: str, timeout: float):
        from .ngsi import NgsiClient

        return NgsiClient(base_url=base_url, timeout=timeout)

    # Duck-type the pipeline lock: the poller and the API process share the
    # pipeline object, so every cycle takes its lock in one batch.
    def _lock(self):
        return getattr(self.pipeline, "_lock", None) or threading.Lock()

    def run(self) -> None:
        while not self.stop_flag.is_set():
            started = time.time()
            try:
                frames = self.client.poll(self.catalog.sensors(), self.mapping)
                with self._lock():
                    acks = [self.pipeline.process(f) for f in frames]
                    device_verdicts = aggregate_by_device(
                        self.pipeline.all_verdicts(), now=time.time(),
                        stale_after_s=self.stale_after_s,
                    )
                written = skipped = 0
                if self.writer is not None:
                    written, skipped = self.writer.publish(device_verdicts)
                self.last_summary = {
                    "at": time.strftime("%H:%M:%S", time.localtime()),
                    "devices": len(self.catalog.sensors()),
                    "frames": len(frames),
                    "accepted": sum(1 for a in acks if a.accepted),
                    "rejected": sum(1 for a in acks if not a.accepted),
                    "unreachable": sorted(self.client.last_errors),
                    "published": written, "publish_skipped": skipped,
                }
                self.cycles += 1
                if self.cycle_hook is not None:
                    self.cycle_hook(device_verdicts)
            except Exception as exc:          # noqa: BLE001 - poll, log, continue
                self.errors.append(f"{time.strftime('%H:%M:%S')} {type(exc).__name__}: {exc}")
                self.errors[:] = self.errors[-20:]
            self.last_cycle_at = time.time()
            self.stop_flag.wait(max(self.poll_seconds - (time.time() - started), 0.1))

    def stop(self, timeout: float = 2.0) -> None:
        self.stop_flag.set()
        self.join(timeout=timeout)
