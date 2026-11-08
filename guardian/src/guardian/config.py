"""Configuration loading with env overrides and robust path resolution.

Design rules (plan §2.1, §7.4):
  * No hard-coded partner hosts — every endpoint is overridable via GUARDIAN_* env.
  * All relative paths resolve against the directory that holds config.yaml, so the
    same artifact runs from a laptop, from Docker, or on the stage router.
  * `policy.yaml` is the single source of truth for weights/thresholds/version.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


def guardian_root() -> Path:
    """.../guardian  (this file is src/guardian/config.py).

    Everything the Guardian needs lives under this directory, so the folder is
    a complete deliverable on its own: no file outside `guardian/` is read at
    run time, which is what Rule R1 asks for.
    """
    return Path(__file__).resolve().parents[2]


def repo_root() -> Path:
    """Parent of `guardian/`. Only used to *find* an optional shared/ overlay."""
    return guardian_root().parent


def shared_dir() -> Path:
    """Schemas and fixtures the Guardian validates against.

    Resolution order, most specific first:
      1. `GUARDIAN_SHARED_DIR` — set by the Makefile and by Docker, so a host
         that lays the contract out differently can point at it without a code
         change (the "config, not hard-coded" half of R1).
      2. `guardian/shared/` — the copy shipped inside this folder. This is the
         default and the reason `cd guardian && make test` works in a clone.
      3. `<repo>/shared/` — only if a triplet-wide contract folder exists.
    """
    override = os.environ.get("GUARDIAN_SHARED_DIR")
    if override:
        return Path(override).resolve()
    local = guardian_root() / "shared"
    if local.is_dir():
        return local
    return repo_root() / "shared"


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    return os.environ.get(name, default)


def _load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Missing config file: {path}")
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


@dataclass(frozen=True)
class ServiceConfig:
    name: str
    host: str
    port: int
    log_level: str


@dataclass(frozen=True)
class PartnerConfig:
    base_url: str
    timeout_s: float


@dataclass(frozen=True)
class PartnersConfig:
    twin: PartnerConfig
    brain: PartnerConfig


@dataclass(frozen=True)
class AuthConfig:
    scheme: str
    verify_signatures: bool
    keyring_path: str
    key_env_var: str


@dataclass(frozen=True)
class TtlConfig:
    passport_s: int
    reading_max_age_s: int
    seen_window_s: int
    enforce_freshness: bool


@dataclass(frozen=True)
class LatencyConfig:
    design_target_p95_ms: int
    contractual_floor_s: int


@dataclass(frozen=True)
class PathsConfig:
    audit_log: str
    sensor_profiles: str
    static_dir: str


@dataclass(frozen=True)
class TimelineConfig:
    poll_interval_ms: int


@dataclass(frozen=True)
class OrionConfig:
    """How the Guardian talks to the triplet's Orion broker (orion/orion.py).

    `base_url` is NOT hard-coded: env override GUARDIAN_BROKER_URL. `devices_config`
    points at any Twin-style device list (config.json) — the shipped default is
    the snapshot `orion_devices.json` committed next to config.yaml.
    """

    enabled: bool
    base_url: str
    devices_config: str          # "" -> shipped orion_devices.json snapshot
    poll_seconds: float
    timeout_s: float
    stale_after_s: float         # no fresh verdict for this long -> OFFLINE/COMM_LOSS
    publish_enabled: bool        # write TrustVerdict entities back into Orion
    secrets_path: str            # Guardian's own K1/K2 keys (gitignored)
    entity_suffix: str           # verdict entity id = "<device><suffix>"
    entity_type: str


@dataclass(frozen=True)
class Settings:
    service: ServiceConfig
    partners: PartnersConfig
    auth: AuthConfig
    ttl: TtlConfig
    latency: LatencyConfig
    paths: PathsConfig
    timeline: TimelineConfig
    orion: OrionConfig
    config_dir: Path

    # -- path helpers (resolve relative paths against config_dir) --
    def resolve(self, rel: str) -> Path:
        return (self.config_dir / rel).resolve()


def load_settings(config_path: Optional[Path] = None) -> Settings:
    cfg_path = (config_path or (guardian_root() / "config.yaml")).resolve()
    raw = _load_yaml(cfg_path)

    svc = raw.get("service", {}) or {}
    part = raw.get("partners", {}) or {}
    auth = raw.get("auth", {}) or {}
    ttl = raw.get("ttl", {}) or {}
    lat = raw.get("latency", {}) or {}
    paths = raw.get("paths", {}) or {}
    tl = raw.get("timeline", {}) or {}
    orn = raw.get("orion", {}) or {}

    twin_url = _env("GUARDIAN_TWIN_BASE_URL", (part.get("twin", {}) or {}).get("base_url", "http://127.0.0.1:8081"))
    brain_url = _env("GUARDIAN_BRAIN_BASE_URL", (part.get("brain", {}) or {}).get("base_url", "http://127.0.0.1:8082"))
    broker_url = _env("GUARDIAN_BROKER_URL", orn.get("base_url", "https://smartopia.polytecsousse.dev/orion-filter/orion-1"))
    devices_cfg = _env("GUARDIAN_DEVICES_CONFIG", orn.get("devices_config", "")) or ""
    port = int(_env("GUARDIAN_PORT", str(svc.get("port", 8090))))
    verify_sig = str(_env("GUARDIAN_VERIFY_SIGNATURES", str(auth.get("verify_signatures", False)))).lower() in ("1", "true", "yes")
    enforce_fresh = str(_env("GUARDIAN_ENFORCE_FRESHNESS", str(ttl.get("enforce_freshness", False)))).lower() in ("1", "true", "yes")
    orion_enabled = str(_env("GUARDIAN_ORION_ENABLED", str(orn.get("enabled", True)))).lower() in ("1", "true", "yes")
    publish = str(_env("GUARDIAN_PUBLISH_VERDICTS", str(orn.get("publish_enabled", False)))).lower() in ("1", "true", "yes")

    return Settings(
        service=ServiceConfig(
            name=svc.get("name", "guardian"),
            host=svc.get("host", "0.0.0.0"),
            port=port,
            log_level=svc.get("log_level", "INFO"),
        ),
        partners=PartnersConfig(
            twin=PartnerConfig(base_url=twin_url, timeout_s=float((part.get("twin", {}) or {}).get("timeout_s", 2.0))),
            brain=PartnerConfig(base_url=brain_url, timeout_s=float((part.get("brain", {}) or {}).get("timeout_s", 2.0))),
        ),
        auth=AuthConfig(
            scheme=auth.get("scheme", "hmac-sha256"),
            verify_signatures=verify_sig,
            keyring_path=auth.get("keyring_path", "keys/dev_keys.json"),
            key_env_var=auth.get("key_env_var", "GUARDIAN_HMAC_KEY"),
        ),
        ttl=TtlConfig(
            passport_s=int(ttl.get("passport_s", 6)),
            reading_max_age_s=int(ttl.get("reading_max_age_s", 7)),
            seen_window_s=int(ttl.get("seen_window_s", 60)),
            enforce_freshness=enforce_fresh,
        ),
        latency=LatencyConfig(
            design_target_p95_ms=int(lat.get("design_target_p95_ms", 300)),
            contractual_floor_s=int(lat.get("contractual_floor_s", 10)),
        ),
        paths=PathsConfig(
            audit_log=paths.get("audit_log", "logs/audit.jsonl"),
            sensor_profiles=paths.get("sensor_profiles", "sensor_profiles.yaml"),
            static_dir=paths.get("static_dir", "static"),
        ),
        timeline=TimelineConfig(poll_interval_ms=int(tl.get("poll_interval_ms", 500))),
        orion=OrionConfig(
            enabled=orion_enabled,
            base_url=broker_url,
            devices_config=devices_cfg,
            poll_seconds=float(_env("GUARDIAN_POLL_SECONDS", str(orn.get("poll_seconds", 5.0)))),
            timeout_s=float(orn.get("timeout_s", 10.0)),
            stale_after_s=float(_env("GUARDIAN_STALE_AFTER_S", str(orn.get("stale_after_s", 20.0)))),
            publish_enabled=publish,
            secrets_path=orn.get("secrets_path", "guardian_secrets.json"),
            entity_suffix=str((orn.get("publish", {}) or {}).get("entity_suffix", "-verdict")),
            entity_type=str((orn.get("publish", {}) or {}).get("entity_type", "TrustVerdict")),
        ),
        config_dir=cfg_path.parent,
    )


def load_policy(settings: Settings) -> Dict[str, Any]:
    return _load_yaml(settings.config_dir / "policy.yaml")


def load_sensor_profiles(settings: Settings) -> Dict[str, Any]:
    data = _load_yaml(settings.config_dir / settings.paths.sensor_profiles)
    return data.get("profiles", {}) or {}
