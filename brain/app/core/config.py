from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

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
        if self.actuator_execution_enabled:
            if self.actuator_transport == "orion" and self.orion_base_url is None:
                raise ValueError("Orion URL required when Orion execution is enabled")
            if self.actuator_transport == "mock_twin" and self.twin_base_url is None:
                raise ValueError("Twin URL required when mock execution is enabled")
        if self.environment.lower() == "production":
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
