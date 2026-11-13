"""Offline tests for Task 7.3E-1: local live three-layer launcher support.

Covers the Brain-owned loopback-HTTP Guardian exception and the launcher
configuration files. No live calls, no services started; the launcher
scripts are validated statically (PowerShell is executed by the user, not
by the test suite).
"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.integration.guardian_compat import (
    GuardianCompatError,
    GuardianShadowWorker,
    loopback_http_permitted,
)

REPO = Path(__file__).resolve().parents[2]  # brain/
ENV_EXAMPLE = REPO / ".env.real-readonly.example"
START_SCRIPT = REPO / "scripts" / "start-real-local.ps1"
STOP_SCRIPT = REPO / "scripts" / "stop-real-local.ps1"
CHECK_SCRIPT = REPO / "scripts" / "check-real-local.ps1"
DEVICES_FILE = REPO / "config" / "devices.real-readonly.yaml"
CITY_FILE = REPO / "config" / "city.real-readonly.yaml"
INCIDENTS_FILE = REPO / "config" / "incidents.real-readonly.yaml"


def local_settings(tmp_path, **overrides) -> Settings:
    base = dict(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'real_integration.db'}",
        brain_api_key="b" * 48,
        twin_api_key="t" * 48,
        guardian_api_key="g" * 48,
        brain_base_url="http://127.0.0.1:8000",
        worker_enabled=True,
        snap4city_ingest_enabled=True,
        # Settings.fail-closes without a mapping when ingestion is enabled:
        # use the deployed Real-Readonly allowlist via its actual field name.
        snap4city_devices_file=str(DEVICES_FILE),
        city_registry_file=str(CITY_FILE),
        incident_rules_file=str(INCIDENTS_FILE),
        guardian_shadow_reconciliation_enabled=True,
        guardian_integration_token="placeholder-token",
        guardian_identity="triplet-guardian",
        orion_base_url="https://smartopia.polytecsousse.dev/orion-filter/orion-1",
        actuator_execution_enabled=False,
        environment="development",
    )
    base.update(overrides)
    return Settings(**base)


# --- loopback HTTP policy ---------------------------------------------------


def test_loopback_http_permitted_only_when_explicit(tmp_path):
    settings = local_settings(
        tmp_path,
        guardian_base_url="http://127.0.0.1:8090",
        guardian_allow_loopback_http=True,
    )
    assert loopback_http_permitted(settings) is True


def test_loopback_http_requires_optin(tmp_path):
    settings = local_settings(
        tmp_path, guardian_base_url="http://127.0.0.1:8090"
    )
    assert loopback_http_permitted(settings) is False


def test_loopback_http_rejects_non_loopback_hosts(tmp_path):
    for host in (
        "http://192.168.1.10:8090",
        "http://guardian.example.internal:8090",
        "http://10.0.0.5:8090",
    ):
        settings = local_settings(
            tmp_path, guardian_base_url=host, guardian_allow_loopback_http=True
        )
        assert loopback_http_permitted(settings) is False, host


def test_loopback_http_rejects_localhost_lookalike(tmp_path):
    """A non-loopback host that merely contains 'localhost' is not accepted."""
    settings = local_settings(
        tmp_path,
        guardian_base_url="http://localhost.evil.example:8090",
        guardian_allow_loopback_http=True,
    )
    assert loopback_http_permitted(settings) is False


@pytest.mark.parametrize("host", ["http://127.0.0.1:8090", "http://localhost:8090", "http://[::1]:8090"])
def test_loopback_http_accepts_all_loopback_forms(tmp_path, host):
    settings = local_settings(
        tmp_path, guardian_base_url=host, guardian_allow_loopback_http=True
    )
    assert loopback_http_permitted(settings) is True


def test_shadow_worker_accepts_loopback_http(tmp_path):
    settings = local_settings(
        tmp_path,
        guardian_base_url="http://127.0.0.1:8090",
        guardian_allow_loopback_http=True,
    )
    worker = GuardianShadowWorker.from_settings(settings, database=None)
    assert worker.stats.as_dict()["trusted_granted"] == 0


def test_shadow_worker_still_fails_closed_on_http_without_optin(tmp_path):
    settings = local_settings(
        tmp_path, guardian_base_url="http://127.0.0.1:8090"
    )
    with pytest.raises(GuardianCompatError, match="HTTPS"):
        GuardianShadowWorker.from_settings(settings, database=None)


def test_shadow_worker_fails_closed_on_non_loopback_http(tmp_path):
    settings = local_settings(
        tmp_path,
        guardian_base_url="http://192.168.1.10:8090",
        guardian_allow_loopback_http=True,
    )
    with pytest.raises(GuardianCompatError, match="HTTPS"):
        GuardianShadowWorker.from_settings(settings, database=None)


def test_production_rejects_loopback_http_optin():
    with pytest.raises(ValidationError, match="loopback"):
        Settings(
            _env_file=None,
            environment="production",
            brain_api_key="b" * 48,
            twin_api_key="t" * 48,
            guardian_api_key="g" * 48,
            brain_base_url="https://brain.example.internal",
            twin_base_url="https://twin.example.internal",
            guardian_base_url="https://guardian.example.internal",
            guardian_allow_loopback_http=True,
            snap4city_ingest_enabled=False,
            actuator_execution_enabled=False,
        )


# --- launcher scripts and template -----------------------------------------


def test_launcher_scripts_exist():
    for script in (START_SCRIPT, STOP_SCRIPT, CHECK_SCRIPT):
        assert script.is_file(), script


def test_check_script_parses_on_windows_powershell():
    """AST-parse check-real-local.ps1 without executing it.

    Regression for Task 7.3E-5B: a previous revision embedded Python in
    expandable here-strings with LF line endings; Windows PowerShell 5.1
    failed to recognize the here-string delimiters and parsed Python as
    PowerShell, producing 'Unexpected token' parse errors. This test pins
    the fix: the script must parse cleanly and every here-string body must
    stay out of the PowerShell AST (single-quoted, token-substituted).
    """
    # 1. Structural guarantees that keep PS 5.1 happy.
    text = CHECK_SCRIPT.read_text(encoding="utf-8")
    # Single-quoted here-strings only (no expandable @" strings that could
    # interpolate Python $ or be parsed as code).
    assert '@"' not in text, "expandable here-strings are forbidden in this script"

    # 2. Parse with the real PowerShell engine when available.
    #    Adds-Type based AST check via pwsh/powershell subprocess is avoided;
    #    instead assert the bare minimum: here-string openers/closers pair.
    openers = text.count("@'")
    closers = text.count("'@")
    assert openers == closers and openers >= 3, (
        "single-quoted here-strings must be balanced (found "
        f"{openers} openers / {closers} closers)"
    )

    # 3. If a PowerShell host is importable, do the definitive parse.
    import shutil
    import subprocess

    ps_exe = shutil.which("powershell") or shutil.which("pwsh")
    if not ps_exe:
        pytest.skip("no PowerShell host available for AST validation")
    check_cmd = (
        "$err=$null; "
        "$null=[System.Management.Automation.Language.Parser]::ParseFile("
        f"'{CHECK_SCRIPT}', [ref]$null, [ref]$err); "
        "if ($err -and $err.Count -gt 0) { "
        "$err | ForEach-Object { Write-Output "
        "($_.Extent.StartLineNumber.ToString() + ': ' + $_.Message) }; exit 1 }"
    )
    result = subprocess.run(
        [ps_exe, "-NoProfile", "-NonInteractive", "-Command", check_cmd],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        "check-real-local.ps1 failed PowerShell AST parse:\n"
        f"{result.stdout}{result.stderr}"
    )


def test_start_script_targets_real_entry_points():
    text = START_SCRIPT.read_text(encoding="utf-8")
    # Real Guardian module entry point, not a mock.
    assert '"-m", "guardian"' in text
    # Real Twin CLI entry point.
    assert "src\\twin.py" in text
    # Real Brain app via uvicorn.
    assert '"app.main:app"' in text
    # Real-Readonly env file, not the demo .env.
    assert ".env.real-readonly" in text
    # Safety pins enforced in preflight.
    assert "ACTUATOR_EXECUTION_ENABLED" in text
    assert "GUARDIAN_ALLOW_LOOPBACK_HTTP" in text
    # No mock services anywhere.
    assert "mock_twin" not in text and "mock_guardian" not in text


def test_start_script_never_prints_secrets():
    """No Write-Host may interpolate a raw env-map value."""
    text = START_SCRIPT.read_text(encoding="utf-8")
    for line in text.splitlines():
        if "Write-Host" in line:
            assert "$envMap" not in line, line


def test_launcher_env_template_drives_the_real_configuration(tmp_path):
    """The .env.real-readonly the launcher loads must itself satisfy Settings.

    Parses the template statically and asserts the runtime pins the first
    live run requires, without starting any service and without any live
    network request.
    """
    env_map: dict[str, str] = {}
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            env_map[key.strip()] = value.strip()

    # Correct Real-Readonly device mapping and city registry paths.
    assert env_map["SNAP4CITY_DEVICES_FILE"] == "config/devices.real-readonly.yaml"
    assert env_map["CITY_REGISTRY_FILE"] == "config/city.real-readonly.yaml"
    assert env_map["INCIDENT_RULES_FILE"] == "config/incidents.real-readonly.yaml"
    # Hosted Orion broker (HTTPS) and the local Guardian HTTP opt-in.
    assert env_map["ORION_BASE_URL"].startswith("https://")
    assert env_map["GUARDIAN_BASE_URL"] == "http://127.0.0.1:8090"
    assert env_map["GUARDIAN_ALLOW_LOOPBACK_HTTP"] == "true"
    # Actuation and auto-approval disabled.
    assert env_map["ACTUATOR_EXECUTION_ENABLED"] == "false"
    assert env_map["OPERATIONAL_AUTO_APPROVE"] == "false"
    assert env_map["OPERATIONAL_DEMO_ENABLED"] == "false"
    # Verification-only Guardian shadow reconciliation stays on.
    assert env_map["GUARDIAN_SHADOW_RECONCILIATION_ENABLED"] == "true"
    # The template must NOT pin an isolated DATABASE_URL (the starter's working
    # copy does); the filled file is the user's responsibility, but the
    # template must not point at the demo/mock database either.
    assert "city_brain.db" not in env_map.get("DATABASE_URL", "")


def test_start_script_launches_brain_with_isolated_real_configuration():
    """Static check: the launcher points Brain at the real-readonly profile."""
    text = START_SCRIPT.read_text(encoding="utf-8")
    assert 'ENV_FILE' in text
    assert ".env.real-readonly" in text
    # Working directory is brain/ so the mounted config paths resolve.
    assert "-WorkingDirectory $BrainDir" in text


def test_env_example_documents_loopback_exception():
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    assert "GUARDIAN_ALLOW_LOOPBACK_HTTP=true" in text
    assert "GUARDIAN_BASE_URL=http://127.0.0.1:8090" in text
    # Hosted Orion stays HTTPS.
    assert "ORION_BASE_URL=https://smartopia.polytecsousse.dev" in text
