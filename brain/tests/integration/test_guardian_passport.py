"""Task 7.3G-6: Guardian-native passport eligibility — isolated tests.

Every test runs against a mocked Guardian transport. No live Guardian, Orion
or real-database access. The passport fixtures are built with Guardian's own
signing algorithm (mirrored in app.integration.guardian_passport) so validity,
tampering, expiry and digest-binding cases are all exercised offline.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import yaml
from pydantic import SecretStr

from app.decision.config import DecisionPolicies
from app.integration.guardian_passport import (
    GUARDIAN_TRUSTED_DISPOSITION,
    GuardianPassportAuthorizer,
    PassportError,
    _sign,
)
from app.integration.ngsi_twin import SensorMapping
from app.intelligence.incident_rules import IncidentRules

ENTITY_TIMESTAMP = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
REPO_CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


def _settings(**overrides) -> SimpleNamespace:
    base = SimpleNamespace(
        environment="development",
        guardian_passport_enabled=True,
        guardian_passport_hmac_key=SecretStr("real-shared-secret-at-least-not-default"),
        guardian_integration_token=SecretStr("token"),
        guardian_base_url="https://guardian.invalid",
        event_freshness_seconds=300,
        guardian_passport_max_evidence_age_seconds=3600,
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def _mapping() -> SensorMapping:
    return SensorMapping(
        entity_id="us-b-bldg-01",
        ngsi_type="BuildingSensor",
        attribute="smokeLevel",
        sensor_id="us-b-bldg-01:fire_smoke",
        measurement="smoke",
        unit="ppm",
        guardian_property="fire_smoke",
        guardian_zone="ZONE-B",
        guardian_unit="ppm",
    )


def _reading(value: float = 12.0):
    from uuid import UUID

    from app.schemas.sensor import SensorReading

    return SensorReading(
        event_id=UUID("00000000-0000-0000-0000-000000004242"),
        correlation_id=UUID("00000000-0000-0000-0000-000000000001"),
        occurred_at=datetime.now(UTC),
        sensor_id="us-b-bldg-01:fire_smoke",
        sensor_type="smoke",
        value=value,
        unit="ppm",
        attributes={
            "entity_id": "us-b-bldg-01",
            "attribute": "smokeLevel",
            "zone_id": "B",
            "entity_timestamp": ENTITY_TIMESTAMP,
        },
    )


def _passport_body(digest: str, issued_at: datetime, ttl: int = 6) -> dict:
    return {
        "passport_id": "psp-test",
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "ttl_s": ttl,
        "zone": "ZONE-B",
        "disposition": GUARDIAN_TRUSTED_DISPOSITION,
        "trust": 0.95,
        "reason_codes": [],
        "evidence_digest": digest,
        "source_ids": ["us-b-bldg-01"],
        "policy_version": "v1.0",
        "allowed_actions": ["monitor"],
        "conditions": [],
        "signature": "",
    }


TEST_PASSPORT_KEY = b"real-shared-secret-at-least-not-default"


def _signed_passport(
    digest: str,
    issued_at: datetime,
    ttl: int = 6,
    key: bytes = TEST_PASSPORT_KEY,
) -> dict:
    body = _passport_body(digest, issued_at, ttl)
    body["signature"] = _sign(body, key)
    return body


def _expected_digest(entry: SensorMapping, value: float = 12.0) -> str:
    from app.integration.guardian_compat import evidence_body, evidence_digest

    return evidence_digest(
        evidence_body(
            entry.entity_id,
            entry.guardian_zone,
            entry.guardian_property,
            ENTITY_TIMESTAMP,
            value,
            entry.guardian_unit,
        )
    )


def _transport(passport: dict | None, status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        if passport is None:
            return httpx.Response(status, request=request)
        return httpx.Response(status, request=request, json=passport)

    return httpx.MockTransport(handler)


@pytest.fixture
def entry() -> SensorMapping:
    return _mapping()


@pytest.fixture
def authorizer() -> GuardianPassportAuthorizer:
    return GuardianPassportAuthorizer(_settings())


async def test_valid_passport_authorizes(authorizer, entry) -> None:
    digest = _expected_digest(entry)
    issued = datetime.now(UTC)
    authorizer.transport = _transport(_signed_passport(digest, issued))
    eligibility = await authorizer.authorize(_reading(), entry)
    assert eligibility.evidence_digest == digest
    assert eligibility.expires_at > eligibility.issued_at


async def test_disabled_adapter_fails_closed(entry) -> None:
    authorizer = GuardianPassportAuthorizer(_settings(guardian_passport_enabled=False))
    with pytest.raises(PassportError, match="guardian_passport_enabled"):
        await authorizer.authorize(_reading(), entry)


async def test_production_environment_refused(entry) -> None:
    authorizer = GuardianPassportAuthorizer(_settings(environment="production"))
    with pytest.raises(PassportError, match="restricted"):
        await authorizer.authorize(_reading(), entry)


async def test_missing_key_refused(entry) -> None:
    authorizer = GuardianPassportAuthorizer(_settings(guardian_passport_hmac_key=None))
    with pytest.raises(PassportError, match="guardian_passport_hmac_key"):
        await authorizer.authorize(_reading(), entry)


async def test_dev_default_key_refused(entry) -> None:
    settings = _settings(
        guardian_passport_hmac_key=SecretStr("dev-guardian-service-key")
    )
    authorizer = GuardianPassportAuthorizer(settings)
    with pytest.raises(PassportError, match="development default"):
        await authorizer.authorize(_reading(), entry)


async def test_invalid_signature_rejected(authorizer, entry) -> None:
    digest = _expected_digest(entry)
    passport = _signed_passport(digest, datetime.now(UTC))
    passport["signature"] = "hmac-sha256:" + "0" * 64
    authorizer.transport = _transport(passport)
    with pytest.raises(PassportError, match="signature"):
        await authorizer.authorize(_reading(), entry)


async def test_wrong_digest_rejected(authorizer, entry) -> None:
    passport = _signed_passport("sha256:" + "a" * 64, datetime.now(UTC))
    authorizer.transport = _transport(passport)
    with pytest.raises(PassportError, match="different evidence"):
        await authorizer.authorize(_reading(), entry)


async def test_wrong_disposition_rejected(authorizer, entry) -> None:
    digest = _expected_digest(entry)
    body = _passport_body(digest, datetime.now(UTC))
    body["disposition"] = "REJECTED"
    body["signature"] = _sign(body, TEST_PASSPORT_KEY)
    authorizer.transport = _transport(body)
    with pytest.raises(PassportError, match="REJECTED"):
        await authorizer.authorize(_reading(), entry)


async def test_expired_passport_rejected(authorizer, entry) -> None:
    digest = _expected_digest(entry)
    stale = datetime.now(UTC) - timedelta(seconds=3600)
    authorizer.transport = _transport(_signed_passport(digest, stale))
    with pytest.raises(PassportError, match="validity window"):
        await authorizer.authorize(_reading(), entry)


async def test_stale_observation_rejected(authorizer, entry) -> None:
    digest = _expected_digest(entry)
    authorizer.transport = _transport(_signed_passport(digest, datetime.now(UTC)))
    reading = _reading().model_copy(
        update={"occurred_at": datetime.now(UTC) - timedelta(seconds=3600)}
    )
    with pytest.raises(PassportError, match="freshness"):
        await authorizer.authorize(reading, entry)


async def test_guardian_missing_verdict_fails_closed(authorizer, entry) -> None:
    authorizer.transport = _transport(None, status=404)
    with pytest.raises(PassportError, match="404"):
        await authorizer.authorize(_reading(), entry)


async def test_guardian_unavailable_fails_closed(authorizer, entry) -> None:
    def handler(request):
        raise httpx.ConnectError("down")

    authorizer.transport = httpx.MockTransport(handler)
    with pytest.raises(PassportError, match="unavailable"):
        await authorizer.authorize(_reading(), entry)


async def test_value_change_invalidates_binding(authorizer, entry) -> None:
    """A passport for the observed value must not authorize a DIFFERENT value."""
    digest = _expected_digest(entry, value=12.0)
    issued = datetime.now(UTC)
    authorizer.transport = _transport(_signed_passport(digest, issued))
    tampered = _reading(value=400.0)  # spoofed high reading
    with pytest.raises(PassportError):
        # authorize() recomputes the digest from the reading's OWN value; a
        # 400 ppm reading hashes to a different digest than the certified one.
        await authorizer.authorize(tampered, entry)


async def test_candidate_configs_validate() -> None:
    """Both inactive candidate configs parse against their real schemas."""
    rules = IncidentRules.model_validate(
        yaml.safe_load(
            (REPO_CONFIG_DIR / "incidents.real-zoneb.candidate.yaml").read_text(
                encoding="utf-8"
            )
        )
    )
    assert rules.rules[0].measurement == "smoke"
    assert rules.rules[0].zones == ["B"]
    policy = DecisionPolicies.model_validate(
        yaml.safe_load(
            (REPO_CONFIG_DIR / "policies.real-zoneb.candidate.yaml").read_text(
                encoding="utf-8"
            )
        )
    )
    assert policy.approved is False  # inactive by design
    assert {a.actuator_id for a in policy.actions} == {"us-b-alarm-01", "us-b-disp-01"}
