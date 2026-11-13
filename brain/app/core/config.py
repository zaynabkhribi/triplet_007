import os
from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Task 7.3E-1: the launcher may point this at the Real-Readonly env file
    # via the ENV_FILE environment variable (a path). When unset, the default
    # `.env` applies, preserving the existing mock/demo behaviour.
    model_config = SettingsConfigDict(
        env_file=os.environ.get("ENV_FILE", ".env"), extra="ignore"
    )

    app_name: str = "City Brain"
    environment: str = "development"
    log_level: str = "INFO"
    database_url: str = "sqlite:///./city_brain.db"
    brain_api_key: SecretStr | None = None
    twin_api_key: SecretStr | None = None
    guardian_api_key: SecretStr | None = None
    brain_base_url: AnyHttpUrl | None = None
    twin_base_url: AnyHttpUrl | None = None
    guardian_base_url: AnyHttpUrl | None = None
    max_request_bytes: int = Field(default=65536, ge=1024, le=1048576)
    replay_window_seconds: int = Field(default=300, ge=1, le=3600)
    guardian_identity: str = "mock-guardian"
    event_freshness_seconds: int = Field(default=300, ge=1, le=2678400)
    verdict_timeout_seconds: int = Field(default=60, ge=1, le=3600)
    verdict_ttl_seconds: int = Field(default=300, ge=1, le=86400)
    worker_poll_seconds: float = Field(default=0.25, ge=0.01, le=60)
    worker_batch_size: int = Field(default=100, ge=1, le=1000)
    worker_max_attempts: int = Field(default=3, ge=1, le=20)
    worker_retry_seconds: float = Field(default=1, ge=0.01, le=60)
    worker_enabled: bool = True
    city_registry_file: str | None = None
    incident_rules_file: str | None = None
    decision_policy_file: str | None = None
    snap4city_ingest_enabled: bool = False
    snap4city_devices_file: str | None = None
    snap4city_poll_seconds: float = Field(default=5.0, ge=0.5, le=3600)
    guardian_integration_token: SecretStr | None = None
    # Task 7.3E-3: which Guardian evidence source the shadow reconciliation
    # consumes. "integration_verdicts" (the authenticated HTTPS contract) is
    # the default; "audit_tail" consumes GET /v1/verdict?since= from an
    # UNAUTHENTICATED endpoint and is only permitted on loopback HTTP in the
    # development environment.
    guardian_evidence_source: Literal["integration_verdicts", "audit_tail"] = (
        "integration_verdicts"
    )
    guardian_audit_cursor_file: str | None = None
    # Task 7.3E-1: explicit, narrowly scoped local-integration escape hatch.
    # Permits plain HTTP to a Guardian listening on a LOOPBACK address only
    # (127.0.0.0/8, ::1, localhost). Never for LAN/internet HTTP endpoints,
    # never honored in production environments, and ignored unless this flag
    # is set to true. Default remains HTTPS-only, fail-closed.
    guardian_allow_loopback_http: bool = False
    # Task 7.3C-3A: opt-in verification-only Guardian shadow reconciliation.
    # Observes and validates real Guardian evidence; never grants trust.
    guardian_shadow_reconciliation_enabled: bool = False
    guardian_shadow_poll_seconds: float = Field(default=30.0, ge=1.0, le=3600)
    # Resource bounds (Task 7.3C-3B): oversized Guardian responses and huge
    # candidate scans are failed loudly, never silently truncated.
    guardian_shadow_max_rows: int = Field(default=500, ge=1, le=100000)
    guardian_shadow_max_candidates: int = Field(default=2000, ge=1, le=100000)
    guardian_shadow_timeout_seconds: float = Field(default=5.0, gt=0, le=120)
    actuator_execution_enabled: bool = False
    actuator_transport: Literal["orion", "mock_twin"] = "orion"
    command_ttl_seconds: int = Field(default=60, ge=1, le=86400)
    command_feedback_timeout_seconds: int = Field(default=30, ge=1, le=86400)
    command_max_attempts: int = Field(default=3, ge=1, le=20)
    command_retry_seconds: float = Field(default=1, ge=0.01, le=300)
    command_timeout_seconds: float = Field(default=5, gt=0, le=60)
    orion_base_url: AnyHttpUrl | None = None
    orion_bearer_token: SecretStr | None = None
    orion_api_key: SecretStr | None = None
    orion_api_key_header: str = "X-API-Key"
    orion_fiware_service: str | None = None
    orion_fiware_service_path: str | None = None
    orion_entity_prefix: str = "urn:ngsi-ld:Actuator:"
    orion_command_attribute: str = "command"
    orion_state_attribute: str = "commandState"
    orion_tls_ca_file: str | None = None
    orion_tls_cert_file: str | None = None
    orion_tls_key_file: str | None = None
    # Task 7.3G: git-ignored per-actuator K1/K2 secrets for the hosted Orion
    # Broker Filter (same schema as twin/secrets.json). Required for real
    # actuator writes; never committed, never logged, never echoed.
    orion_actuator_secrets_file: str | None = None
    mock_twin_allowed_actions: str = "test"
    mock_twin_failure_mode: Literal["none", "fail_once", "always"] = "none"
    mock_twin_delay_seconds: float = Field(default=0, ge=0, le=60)
    mock_guardian_default_status: Literal["trusted", "rejected", "unknown"] = "trusted"
    dashboard_session_seconds: int = Field(default=3600, ge=60, le=86400)
    simulation_interval_seconds: float = Field(default=1.0, ge=0.05, le=10)
    simulation_max_ticks: int = Field(default=600, ge=10, le=3600)
    simulation_seed: int = 2026
    operational_demo_enabled: bool = False
    operational_auto_approve: bool = False
    operational_coordination_seconds: float = Field(default=0.5, ge=0.1, le=10)
    mock_simulation_auto_start: bool = False
    mock_simulation_interval_seconds: float = Field(default=1.0, ge=0.1, le=10)
    mock_simulation_seed: int = 2026
    traffic_model_dir: str | None = None
    water_model_path: str | None = None
    tls_ca_file: str | None = None
    tls_cert_file: str | None = None
    tls_key_file: str | None = None

    @model_validator(mode="after")
    def reject_development_secrets_in_production(self) -> "Settings":
        keys = [self.brain_api_key, self.twin_api_key, self.guardian_api_key]
        values = [key.get_secret_value() for key in keys if key is not None]
        if any(len(value) < 32 for value in values) or len(set(values)) != len(values):
            raise ValueError("service keys must be distinct and at least 32 characters")
        if bool(self.tls_cert_file) != bool(self.tls_key_file):
            raise ValueError("TLS certificate and key must be configured together")
        if bool(self.orion_tls_cert_file) != bool(self.orion_tls_key_file):
            raise ValueError("Orion TLS certificate and key must be configured together")
        if self.orion_bearer_token and self.orion_api_key:
            raise ValueError("configure one Orion authentication mechanism")
        if self.snap4city_ingest_enabled:
            if not self.orion_base_url:
                raise ValueError("Orion URL required when Snap4City ingestion is enabled")
            if not self.snap4city_devices_file:
                raise ValueError("device mapping file required when Snap4City ingestion is enabled")
        if self.actuator_execution_enabled:
            if self.actuator_transport == "orion" and self.orion_base_url is None:
                raise ValueError("Orion URL required when Orion execution is enabled")
            if self.actuator_transport == "mock_twin" and self.twin_base_url is None:
                raise ValueError("Twin URL required when mock execution is enabled")
        if self.environment.lower() == "production":
            if self.guardian_allow_loopback_http:
                raise ValueError(
                    "guardian_allow_loopback_http is forbidden in production"
                )
            if self.operational_demo_enabled or self.operational_auto_approve:
                raise ValueError("operational demo automation is forbidden in production")
            if len(values) != 3:
                raise ValueError("production API keys must be configured")
            urls = [self.brain_base_url, self.twin_base_url, self.guardian_base_url]
            if any(url is None or url.scheme != "https" for url in urls):
                raise ValueError("production URLs must use HTTPS")
            if self.actuator_execution_enabled and (
                self.actuator_transport != "orion" or self.orion_base_url.scheme != "https"
            ):
                raise ValueError("production actuator execution requires Orion HTTPS")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
