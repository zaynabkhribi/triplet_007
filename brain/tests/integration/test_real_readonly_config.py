"""Offline configuration validation for the Real-Integration deployment
(Task 7.3D-2/-R). No live calls, no containers: only Settings/worker
construction semantics are proven, plus Compose/env consistency via static
YAML parsing (Docker is unavailable on the dev machine)."""

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from app.core.config import Settings
from app.integration.guardian_compat import GuardianCompatError, GuardianShadowWorker
from app.integration.ngsi_twin import NgsiTwinIngestWorker, load_mapping

REPO = Path(__file__).resolve().parents[2]  # brain/
COMPOSE = REPO / "docker-compose.real-readonly.yml"
ENV_EXAMPLE = REPO / ".env.real-readonly.example"
CITY_FILE = REPO / "config" / "city.real-readonly.yaml"
INCIDENTS_FILE = REPO / "config" / "incidents.real-readonly.yaml"
DEVICES_FILE = REPO / "config" / "devices.real-readonly.yaml"
EXAMPLE_DEVICES_FILE = REPO / "config" / "devices.snap4city.example.yaml"
POLICIES_FILE = REPO / "config" / "policies.yaml"


def real_settings(tmp_path, **overrides) -> Settings:
    base = dict(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'real_integration.db'}",
        brain_api_key="b" * 48,
        twin_api_key="t" * 48,
        guardian_api_key="g" * 48,
        brain_base_url="http://brain-real:8000",
        worker_enabled=True,
        snap4city_ingest_enabled=True,
        snap4city_devices_file=str(DEVICES_FILE),
        guardian_shadow_reconciliation_enabled=True,
        guardian_base_url="https://guardian.example.internal",
        guardian_integration_token="placeholder-token",
        guardian_identity="triplet-guardian",
        orion_base_url="http://orion:1026",
        city_registry_file=str(CITY_FILE),
        incident_rules_file=str(INCIDENTS_FILE),
        decision_policy_file=str(POLICIES_FILE),
        actuator_execution_enabled=False,
    )
    base.update(overrides)
    return Settings(**base)


def _compose_services() -> dict:
    """Parse the Compose file structurally (comments never affect checks)."""
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    return document.get("services") or {}


def test_deployment_files_exist_and_are_consistent():
    assert COMPOSE.is_file()
    assert ENV_EXAMPLE.is_file()
    assert CITY_FILE.is_file()
    assert INCIDENTS_FILE.is_file()
    assert DEVICES_FILE.is_file()
    assert EXAMPLE_DEVICES_FILE.is_file()  # broader example stays available
    services = _compose_services()
    # Exactly the intended Real-Integration service, no mocks, no bridge.
    assert set(services) == {"brain-real"}
    service = services["brain-real"]
    environment = service.get("environment") or {}
    assert environment["DATABASE_URL"] == "sqlite:////data/real_integration.db"
    assert environment["ACTUATOR_EXECUTION_ENABLED"] == "false"
    assert environment["OPERATIONAL_AUTO_APPROVE"] == "false"
    assert environment["WORKER_ENABLED"] == "true"
    assert environment["SNAP4CITY_INGEST_ENABLED"] == "true"
    assert environment["GUARDIAN_SHADOW_RECONCILIATION_ENABLED"] == "true"
    assert environment["SNAP4CITY_DEVICES_FILE"] == "config/devices.real-readonly.yaml"
    assert environment["GUARDIAN_IDENTITY"] == "triplet-guardian"
    # No obsolete/inert variables anywhere in the parsed document.
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert "ORION_CONTRACT" not in str(document)
    assert "ORION_ACTUATOR_MAPPING_FILE" not in str(document)
    assert "triplet_bridge" not in str(document)
    # Isolated database: never the mock volume/default sqlite.
    assert "city_brain.db" not in str(document)
    assert "brain-real-data" in (document.get("volumes") or {})


def test_real_settings_construct_with_valid_dummy_values(tmp_path):
    settings = real_settings(tmp_path)
    assert settings.snap4city_ingest_enabled is True
    assert settings.guardian_shadow_reconciliation_enabled is True
    assert settings.actuator_execution_enabled is False
    assert Path(settings.city_registry_file).is_file()
    assert Path(settings.incident_rules_file).is_file()


def test_device_mapping_loads_and_is_ambiguity_free():
    mapping = load_mapping(str(EXAMPLE_DEVICES_FILE))
    ids = [m.sensor_id for m in mapping.sensors]
    assert ids, "broader example allowlist must not be empty"
    props = [
        (m.entity_id, m.guardian_property)
        for m in mapping.sensors
        if m.guardian_property
    ]
    assert len(props) == len(set(props)), "ambiguous guardian_property mapping"
    assert not any(m.guardian_property == "traffic_camera" for m in mapping.sensors)


def test_real_and_mock_database_configurations_differ(tmp_path):
    real = real_settings(tmp_path)
    mock_style = Settings(
        _env_file=None,
        database_url="sqlite:///./city_brain.db",
        brain_api_key="b" * 48,
        twin_api_key="t" * 48,
        guardian_api_key="g" * 48,
        brain_base_url="http://brain",
    )
    assert real.database_url != mock_style.database_url
    assert "real_integration" in real.database_url


def test_missing_guardian_https_url_fails_closed(tmp_path):
    settings = real_settings(tmp_path)
    broken = settings.model_copy(
        update={"guardian_base_url": None, "guardian_integration_token": "tok"}
    )
    with pytest.raises(GuardianCompatError, match="guardian_base_url"):
        GuardianShadowWorker.from_settings(broken, database=None)


def test_http_guardian_endpoint_fails_closed(tmp_path):
    settings = real_settings(tmp_path)
    broken = settings.model_copy(update={"guardian_base_url": "http://guardian:8080"})
    with pytest.raises(GuardianCompatError, match="HTTPS"):
        GuardianShadowWorker.from_settings(broken, database=None)


def test_missing_guardian_token_fails_closed(tmp_path):
    settings = real_settings(tmp_path)
    broken = settings.model_copy(update={"guardian_integration_token": None})
    with pytest.raises(GuardianCompatError, match="token"):
        GuardianShadowWorker.from_settings(broken, database=None)


def test_missing_orion_url_fails_at_settings_validation(tmp_path):
    """Settings itself fail-closes before any worker is constructed."""
    with pytest.raises(ValidationError, match="Orion URL required"):
        real_settings(tmp_path, orion_base_url=None)


def test_missing_sensor_mapping_fails_closed(tmp_path):
    settings = real_settings(
        tmp_path, snap4city_devices_file="/nonexistent/devices.yaml"
    )
    with pytest.raises(OSError):
        NgsiTwinIngestWorker.from_settings(settings, database=None)


def test_both_workers_configure_without_network_calls(tmp_path):
    settings = real_settings(tmp_path)
    # Construction only: no HTTP occurs until cycle()/poll() is awaited.
    worker = NgsiTwinIngestWorker.from_settings(settings, database=None)
    assert worker.poller.settings.orion_base_url
    shadow = GuardianShadowWorker.from_settings(settings, database=None)
    assert shadow.stats.as_dict()["trusted_granted"] == 0
    assert shadow.max_rows == settings.guardian_shadow_max_rows


def test_real_mode_registry_sensors_match_device_mapping():
    """Registry ↔ Real-Readonly ingestion allowlist must agree exactly.

    Compares the DEPLOYED allowlist (devices.real-readonly.yaml), not the
    broader example. Bidirectional: every allowlisted sensor is registered,
    and every registered sensor is allowlisted.
    """
    registry = yaml.safe_load(CITY_FILE.read_text(encoding="utf-8"))
    mapping = load_mapping(str(DEVICES_FILE))
    registry_ids = {s["sensor_id"]: s for s in registry["sensors"]}
    assert set(registry_ids) == {m.sensor_id for m in mapping.sensors}
    for m in mapping.sensors:
        entry = registry_ids[m.sensor_id]
        assert entry["unit"] == m.unit
        assert entry["measurement"] == m.measurement
        assert entry["zone_id"] == m.entity_id.split("-")[1].upper()


def test_real_readonly_profile_enables_only_smoke_and_temperature():
    """Congestion/fill/ambiguous channels must not ride into this profile."""
    mapping = load_mapping(str(DEVICES_FILE))
    attributes = {m.attribute for m in mapping.sensors}
    assert attributes == {"smokeLevel", "temperature"}
    assert all(m.entity_id == "us-b-bldg-01" for m in mapping.sensors)
    assert all(m.guardian_zone == "ZONE-B" for m in mapping.sensors)


def test_real_twin_and_shadow_workers_accept_dedicated_allowlist(tmp_path):
    settings = real_settings(tmp_path)
    worker = NgsiTwinIngestWorker.from_settings(settings, database=None)
    assert worker.poller.mapping.sensors == load_mapping(str(DEVICES_FILE)).sensors
    shadow = GuardianShadowWorker.from_settings(settings, database=None)
    assert shadow.verifier.by_entity  # non-empty mapping join


def test_mapping_file_available_inside_container_layout():
    """The Compose mount must cover the configured mapping path.

    The image bakes only app/ and mocks/, so the ./config volume mount must
    exist and be read-only, and its target must contain the Compose working
    directory-relative config path.
    """
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    service = compose["services"]["brain-real"]
    mounts = [v for v in service.get("volumes", []) if "config" in v]
    assert any(
        mount.startswith("./config:") and mount.rstrip(":").endswith("/service/config:ro")
        or (mount.startswith("./config") and ":ro" in mount and "/service/config" in mount)
        for mount in mounts
    ), f"missing read-only config mount: {mounts}"


def test_env_example_contains_no_real_credentials():
    text = ENV_EXAMPLE.read_text(encoding="utf-8")

    for key in (
        "BRAIN_API_KEY=",
        "TWIN_API_KEY=",
        "GUARDIAN_API_KEY=",
        "GUARDIAN_INTEGRATION_TOKEN=",
    ):
        line = next(
            (
                candidate
                for candidate in text.splitlines()
                if candidate.startswith(key)
            ),
            "",
        )
        assert line.rstrip() == key, f"{key} must stay empty in template"

    # Keep the existing safety-pin assertions below.
    # Safety pins documented in the template.
    assert "ACTUATOR_EXECUTION_ENABLED=false" in text


def test_filled_real_env_is_git_ignored():
    """The filled .env.real-readonly must never be committed."""
    gitignore = (REPO / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".env.real-readonly" in gitignore or ".env.*" in gitignore

def test_real_registry_conforms_to_registry_schema():
    """The real-mode registry must survive app.state.registry validation.

    Guards against schema drift: zones are plain strings, measurement is the
    strict Literal, and units belong to the allowed per-measurement set.
    """
    from app.state.registry import Registry

    raw = yaml.safe_load(CITY_FILE.read_text(encoding="utf-8"))
    registry = Registry.model_validate(raw)
    assert {z for z in registry.zones} >= {"A", "B"}
    by_id = {s.sensor_id: s for s in registry.sensors}
    assert by_id["us-b-bldg-01:fire_smoke"].measurement == "smoke"
    assert by_id["us-b-bldg-01:fire_smoke"].unit == "ppm"
    assert by_id["us-b-bldg-01:temperature"].unit == "degC"
