"""Device / sensor registry (plan §6.1 Stage A identity gate; §8 provenance pinning).

Day 3-4 scope: device existence, provenance pinning, per-device HMAC secrets for
signature verification (`secret_for`), and monotonic sequence tracking
(`note_seq`) that feeds the STALE/sequence-gap check. History decay and quarantine
state are consumed by the pipeline in later steps; the interface below is stable.

Backed by keys/dev_keys.json in dev. Real keys come from the environment and are
never committed (plan §8 secrets).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .errors import UNKNOWN_DEVICE, GuardianError


@dataclass(frozen=True)
class Device:
    device_id: str
    zone: str
    sensor_type: str
    firmware: str
    cal: str
    public_key: Optional[str] = None
    secret: Optional[str] = None
    quarantined: bool = False


class DeviceRegistry:
    def __init__(self, devices: Dict[str, Device]) -> None:
        self._devices = devices
        self._last_seq: Dict[str, int] = {}
        self._quarantine: Dict[str, str] = {}

    @classmethod
    def empty(cls) -> "DeviceRegistry":
        return cls({})

    @classmethod
    def from_keyring(cls, path: Path) -> "DeviceRegistry":
        path = Path(path)
        if not path.exists():
            return cls.empty()
        with path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
        devices: Dict[str, Device] = {}
        for d in raw.get("devices", []):
            dev = Device(
                device_id=d["device_id"],
                zone=d.get("zone", ""),
                sensor_type=d.get("sensor_type", ""),
                firmware=d.get("firmware", ""),
                cal=d.get("cal", ""),
                public_key=d.get("public_key"),
                secret=d.get("secret"),
                quarantined=bool(d.get("quarantined", False)),
            )
            devices[dev.device_id] = dev
        return cls(devices)

    def get(self, device_id: str) -> Optional[Device]:
        return self._devices.get(device_id)

    def require(self, device_id: str) -> Device:
        dev = self._devices.get(device_id)
        if dev is None:
            raise GuardianError(UNKNOWN_DEVICE, f"Unknown device: {device_id}", http_status=400)
        return dev

    def is_quarantined(self, device_id: str) -> bool:
        if device_id in self._quarantine:
            return True
        dev = self._devices.get(device_id)
        return bool(dev and dev.quarantined)

    def quarantine(self, device_id: str, reason: str = "") -> None:
        """Runtime quarantine (overlay on the keyring flag) set by witness feedback."""
        if device_id:
            self._quarantine[device_id] = reason or "runtime quarantine"

    def clear_quarantine(self, device_id: str) -> None:
        self._quarantine.pop(device_id, None)

    def runtime_quarantines(self) -> List[str]:
        """Devices quarantined at runtime (not the static keyring flags)."""
        return list(self._quarantine)

    def quarantine_reason(self, device_id: str) -> Optional[str]:
        return self._quarantine.get(device_id)

    def secret_for(self, device_id: str) -> Optional[str]:
        dev = self._devices.get(device_id)
        return dev.secret if dev else None

    def peek_seq(self, device_id: str) -> Optional[int]:
        """Current monotonic watermark WITHOUT mutating it (safe to call while validating)."""
        return self._last_seq.get(device_id)

    def commit_seq(self, device_id: str, seq: Optional[int]) -> Optional[int]:
        """Advance the watermark after a reading has been ACCEPTED.

        Only ever moves forward: a rejected frame (a replayed old seq, or a gap)
        must never roll the watermark backwards, or the next old frame would be
        accepted as "monotonic". Returns the watermark in effect after the commit.
        """
        if seq is None:
            return self._last_seq.get(device_id)
        prev = self._last_seq.get(device_id)
        if prev is None or seq > prev:
            self._last_seq[device_id] = seq
        return self._last_seq[device_id]

    def known_ids(self):
        return sorted(self._devices.keys())
