"""Offline regression: native passport trust cannot override safety evidence."""

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from pydantic import SecretStr

from app.database.models import CityRegistryRecord
from app.integration.guardian_passport import GuardianPassportAuthorizer, PassportError
from app.main import create_app
from app.security.passport_trust import PassportEligibilityIndex
from app.state.registry import Registry
from tests.integration.test_guardian_passport import (
    TEST_PASSPORT_KEY,
    _expected_digest,
    _mapping,
    _reading,
    _settings,
    _signed_passport,
    _transport,
)
from tests.integration.test_trust_pipeline import post, verdict


@pytest.fixture(autouse=True)
def fresh_source_timestamp(monkeypatch):
    from tests.integration import test_guardian_passport as fixtures

    monkeypatch.setattr(
        fixtures, "ENTITY_TIMESTAMP", (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    )


async def test_reissued_passport_cannot_refresh_old_source_time():
    reading = _reading()
    now = datetime.now(UTC)
    reading.attributes["entity_timestamp"] = (now - timedelta(seconds=31)).isoformat()
    authorizer = GuardianPassportAuthorizer(
        _settings(guardian_passport_max_evidence_age_seconds=30),
        transport=_transport(_signed_passport(_expected_digest(_mapping()), now)),
    )
    with pytest.raises(PassportError, match="original evidence"):
        await authorizer.authorize(reading, _mapping(), now)


async def test_passport_cannot_relabel_a_different_entity():
    reading = _reading()
    reading.attributes["entity_id"] = "different-entity"
    authorizer = GuardianPassportAuthorizer(
        _settings(),
        transport=_transport(_signed_passport(_expected_digest(_mapping()), datetime.now(UTC))),
    )
    with pytest.raises(PassportError, match="channel mapping"):
        await authorizer.authorize(reading, _mapping())


async def test_receipt_clock_accepts_new_issuance_and_rejects_network_expiry():
    started = datetime.now(UTC)
    issued = started + timedelta(seconds=1)
    reading = _reading().model_copy(update={"occurred_at": started - timedelta(seconds=1)})
    authorizer = GuardianPassportAuthorizer(
        _settings(),
        clock=lambda: started + timedelta(seconds=2),
        transport=_transport(_signed_passport(_expected_digest(_mapping()), issued)),
    )
    result = await authorizer.authorize(reading, _mapping(), started)
    assert result.authorized_at == started + timedelta(seconds=2)
    authorizer._clock = lambda: started + timedelta(seconds=8)
    with pytest.raises(PassportError, match="validity window"):
        await authorizer.authorize(reading, _mapping(), started)


@pytest.mark.parametrize("status", ["revoked", "rejected", "unknown"])
async def test_city_accepts_native_passport_but_never_overrides_durable_denial(settings, status):
    settings.worker_enabled = False
    settings.guardian_passport_enabled = True
    settings.guardian_passport_hmac_key = SecretStr(TEST_PASSPORT_KEY.decode())
    settings.guardian_base_url = "https://guardian.invalid"
    settings.guardian_passport_max_evidence_age_seconds = 300
    app = create_app(settings)
    event = _reading()
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://brain") as client,
    ):
        registry = Registry.model_validate(
            {
                "zones": ["B"],
                "sensors": [
                    {
                        "sensor_id": event.sensor_id,
                        "zone_id": "B",
                        "measurement": "smoke",
                        "unit": "ppm",
                    }
                ],
            }
        )
        with app.state.database.transaction() as session:
            session.merge(CityRegistryRecord(id=1, payload=registry.model_dump()))
        city = app.state.city_engine
        city.eligibility = PassportEligibilityIndex(settings, [_mapping()])
        city.eligibility.authorizer.transport = _transport(
            _signed_passport(_expected_digest(_mapping()), datetime.now(UTC))
        )
        assert (await post(client, settings, "/readings", event, "twin")).status_code == 202
        await app.state.processor.tick()
        await city.refresh_passports()
        snapshot = city.snapshot()
        assert snapshot["sensors"][event.sensor_id]["value"] == event.value
        assert snapshot["sensors"][event.sensor_id]["evidence"][0]["trust_source"] == (
            "guardian_passport"
        )
        login = await client.post(
            "/dashboard/session",
            headers={"X-API-Key": settings.brain_api_key.get_secret_value()}, json={},
        )
        assert login.status_code == 200
        city.eligibility.clear()
        dashboard = (await client.get("/dashboard/api/snapshot")).json()
        assert dashboard["metrics"]["trusted_readings"] == 1
        assert dashboard["metrics"]["eligible_sensors"] == 1
        assert dashboard["metrics"]["durable_trusted_readings"] == 0
        assert dashboard["evidence_mode"] == "guardian_passports"
        assert dashboard["readings"][0]["currently_eligible"] is True
        assert dashboard["readings"][0]["authorization_expires_at"]
        assert dashboard["city"]["sensors"][event.sensor_id]["value"] == event.value
        original_clock = city.eligibility.authorizer._clock
        city.eligibility.authorizer._clock = lambda: datetime.now(UTC) + timedelta(seconds=100)
        expired = (await client.get("/dashboard/api/snapshot")).json()
        assert expired["metrics"]["trusted_readings"] == 0
        assert expired["metrics"]["eligible_sensors"] == 0
        assert expired["city"]["sensors"][event.sensor_id]["value"] is None
        assert expired["raw_latest"][event.sensor_id]["value"] == event.value
        assert expired["readings"][0]["currently_eligible"] is False
        city.eligibility.authorizer._clock = original_clock
        await post(client, settings, "/verdicts", verdict(event, status=status), "guardian")
        # Even an unexpired, successfully signed passport cannot override it.
        assert city.snapshot()["sensors"][event.sensor_id]["value"] is None
        denied = (await client.get("/dashboard/api/snapshot")).json()
        assert denied["metrics"]["trusted_readings"] == 0


async def test_native_passport_cannot_enqueue_live_orion(settings):
    settings.worker_enabled = False
    settings.actuator_transport = "orion"
    settings.guardian_passport_enabled = True
    settings.guardian_passport_hmac_key = SecretStr(TEST_PASSPORT_KEY.decode())
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        with pytest.raises(PermissionError, match="contract_incomplete"):
            app.state.actuator_manager.enqueue(None, {}, None, datetime.now(UTC))


async def test_native_passport_incident_optimizer_and_explicit_approval(settings, tmp_path):
    """Offline native-trust chain; isolated policy approval is synthetic, never live."""
    from tests.integration.test_decisions import evaluate, simulation_policy
    from tests.integration.test_incidents import rule, setup

    configured = rule(incident_type="smoke_alert", measurement="smoke", unit="ppm")
    policy = simulation_policy(configured)
    policy_path = tmp_path / "synthetic-policy.json"
    policy_path.write_text(json.dumps(policy))
    settings.decision_policy_file = str(policy_path)
    settings.guardian_passport_enabled = True
    settings.guardian_passport_hmac_key = SecretStr(TEST_PASSPORT_KEY.decode())
    settings.guardian_base_url = "https://guardian.invalid"
    async with setup(settings, tmp_path, configured) as (app, client, _):
        mapping = _mapping().model_copy(update={"sensor_id": "fixture-0"})
        city = app.state.city_engine
        city.eligibility = PassportEligibilityIndex(settings, [mapping])
        city.decisions.passport_eligibility = city.eligibility

        def guardian(request):
            digest = json.loads(request.content)["evidence_digest"]
            return httpx.Response(200, json=_signed_passport(digest, datetime.now(UTC)))

        city.eligibility.authorizer.transport = httpx.MockTransport(guardian)
        now = datetime.now(UTC)
        for offset in (10, 5):
            stamp = now - timedelta(seconds=offset)
            event = _reading().model_copy(
                update={
                    "event_id": uuid4(),
                    "sensor_id": "fixture-0",
                    "occurred_at": stamp,
                    "attributes": {
                        "entity_id": mapping.entity_id,
                        "attribute": mapping.attribute,
                        "zone_id": "simulation",
                        "entity_timestamp": stamp.isoformat(),
                    },
                }
            )
            assert (await post(client, settings, "/readings", event, "twin")).status_code == 202
        await app.state.processor.tick()
        decision = (await evaluate(client, settings)).json()
        assert decision["status"] == "EVALUATED", decision
        assert decision["reason"] == "optimal_verified"
        assert decision["incident_ids"]
        assert not decision["approved_actions"]
        # The explicit approval endpoint re-fetches native trust and rechecks the policy.
        approved = (
            await evaluate(
                client,
                settings,
                {
                    "approval": {
                        "decision_id": decision["decision_id"],
                        "reason": "isolated synthetic operator approval",
                    }
                },
            )
        ).json()
        assert approved["status"] == "APPROVED", approved
        assert approved["approval"]["reason"] == "isolated synthetic operator approval"
