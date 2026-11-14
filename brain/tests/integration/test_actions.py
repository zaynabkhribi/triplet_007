"""Actuator tests use synthetic decisions and simulated devices only."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, UUID, uuid5

import httpx
import pytest
from pydantic import AnyHttpUrl, SecretStr
from sqlalchemy import func, select

from app.database.models import ActuatorCommandRecord, DecisionRecord, DecisionRevision
from app.execution.actuator_manager import MockTwinAdapter
from app.integration.orion_adapter import Delivery, OrionAdapter, OrionError
from app.main import create_app
from app.schemas.actuator import ActuatorCommand, ActuatorFeedback, FeedbackStatus
from app.schemas.guardian import QuarantineNotification
from mocks.mock_twin import create_app as create_twin
from tests.integration.test_decisions import evaluate, scenario
from tests.integration.test_trust_pipeline import post, verdict


class AcceptingAdapter:
    def __init__(self) -> None:
        self.calls = 0

    async def deliver(self, command):
        self.calls += 1
        return Delivery(True, 204)


class FailingAdapter:
    def __init__(self, failures: int, *, uncertain: bool = False) -> None:
        self.failures, self.uncertain, self.calls = failures, uncertain, 0

    async def deliver(self, command):
        self.calls += 1
        if self.calls <= self.failures:
            raise OrionError("simulated_delivery_failure", True, self.uncertain)
        return Delivery(True, 204)


async def approved(client, settings):
    decision = (await evaluate(client, settings)).json()
    if decision["status"] == "EVALUATED":
        decision = (
            await evaluate(
                client,
                settings,
                {
                    "approval": {
                        "decision_id": decision["decision_id"],
                        "reason": "synthetic approval",
                    },
                },
            )
        ).json()
    assert decision["status"] == "APPROVED"
    return decision


async def execute(client, settings, decision_id, role="brain"):
    return await client.post(
        "/v1/actions/execute",
        json={"decision_id": decision_id},
        headers={
            "X-API-Key": getattr(settings, f"{role}_api_key").get_secret_value(),
        },
    )


async def test_delivery_feedback_idempotency_history_and_restart(settings, tmp_path):
    settings.actuator_execution_enabled = True  # isolated mock delivery only
    async with scenario(settings, tmp_path) as (app, client, _):
        adapter = AcceptingAdapter()
        app.state.actuator_manager.adapter = adapter
        decision = await approved(client, settings)
        assert (await execute(client, settings, decision["decision_id"], "twin")).status_code == 403
        response = await execute(client, settings, decision["decision_id"])
        assert response.status_code == 200
        assert response.json()["dispatch_enabled"] is True
        command = response.json()["commands"][0]
        assert command["status"] == "PENDING"
        assert (await execute(client, settings, decision["decision_id"])).json()["commands"][0][
            "command_id"
        ] == command["command_id"]
        await asyncio.gather(*(app.state.actuator_manager.tick() for _ in range(3)))
        assert adapter.calls == 1
        headers = {"X-API-Key": settings.brain_api_key.get_secret_value()}
        detail = await client.get(f"/v1/actions/{command['command_id']}", headers=headers)
        assert detail.json()["status"] == "DELIVERED"
        feedback = ActuatorFeedback(
            feedback_id=uuid5(NAMESPACE_URL, command["command_id"]),
            command_id=command["command_id"],
            correlation_id=command["correlation_id"],
            occurred_at=datetime.now(UTC),
            status=FeedbackStatus.EXECUTED,
            detail="synthetic execution confirmation",
        )
        twin = {"X-API-Key": settings.twin_api_key.get_secret_value()}
        path = f"/v1/actions/{command['command_id']}/feedback"
        assert (
            await client.post(path, headers=twin, json=feedback.model_dump(mode="json"))
        ).status_code == 200
        assert (
            await client.post(path, headers=twin, json=feedback.model_dump(mode="json"))
        ).json()["status"] == "duplicate"
        assert (await client.get("/v1/actions")).status_code == 401
        assert (await client.get("/v1/actions", headers=headers)).status_code == 200
        history = await client.get(
            f"/v1/actions/history?command_id={command['command_id']}",
            headers=headers,
        )
        assert [item["status"] for item in reversed(history.json())] == [
            "PENDING",
            "DISPATCHING",
            "DELIVERED",
            "EXECUTED",
        ]
    restored = create_app(settings)
    async with restored.router.lifespan_context(restored):
        with restored.state.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, UUID(command["command_id"]))
            assert row.status == "EXECUTED"


@pytest.mark.parametrize("unsafe", ["unapproved", "revoked", "quarantined"])
async def test_authorization_and_safety_rejection(settings, tmp_path, unsafe):
    async with scenario(settings, tmp_path) as (app, client, event):
        decision = (await evaluate(client, settings)).json()
        if unsafe != "unapproved":
            decision = (
                await evaluate(
                    client,
                    settings,
                    {
                        "approval": {
                            "decision_id": decision["decision_id"],
                            "reason": "synthetic approval",
                        },
                    },
                )
            ).json()
        if unsafe == "revoked":
            await post(
                client,
                settings,
                "/verdicts",
                verdict(event, revision=1, status="revoked"),
                "guardian",
            )
        elif unsafe == "quarantined":
            notice = QuarantineNotification(
                notification_id=uuid5(NAMESPACE_URL, "synthetic-actuator-quarantine"),
                correlation_id=event.correlation_id,
                issued_at=datetime.now(UTC),
                guardian_id=settings.guardian_identity,
                target_type="actuator",
                target_id="fixture-actuator",
                action="quarantine",
                revision=1,
                reason_code="synthetic",
            )
            await post(client, settings, "/quarantines", notice, "guardian")
        response = await execute(client, settings, decision["decision_id"])
        assert response.status_code == 403
        with app.state.database.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ActuatorCommandRecord)) == 0


async def test_conflicting_active_command_and_invalid_feedback(settings, tmp_path):
    async with scenario(settings, tmp_path) as (app, client, _):
        decision = await approved(client, settings)
        command = (await execute(client, settings, decision["decision_id"])).json()["commands"][0]
        with app.state.database.transaction() as session:
            source = session.get(DecisionRecord, UUID(decision["decision_id"]))
            conflicting = DecisionRecord(
                id=uuid5(NAMESPACE_URL, "synthetic-conflicting-decision"),
                correlation_id=source.correlation_id,
                occurred_at=datetime.now(UTC),
                status="APPROVED",
                payload=source.payload,
            )
            session.add(conflicting)
            session.flush()
            state = app.state.city_engine.rebuild(session, datetime.now(UTC))
            with pytest.raises(ValueError, match="conflicting_active_command"):
                app.state.actuator_manager.enqueue(
                    session,
                    state,
                    conflicting.id,
                    datetime.now(UTC),
                )
        feedback = ActuatorFeedback(
            feedback_id=uuid5(NAMESPACE_URL, "wrong-feedback"),
            command_id=command["command_id"],
            correlation_id=uuid5(NAMESPACE_URL, "wrong-correlation"),
            occurred_at=datetime.now(UTC),
            status=FeedbackStatus.EXECUTED,
        )
        twin = {"X-API-Key": settings.twin_api_key.get_secret_value()}
        response = await client.post(
            f"/v1/actions/{command['command_id']}/feedback",
            headers=twin,
            json=feedback.model_dump(mode="json"),
        )
        assert response.status_code == 409
        with app.state.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, UUID(command["command_id"]))
            assert row.status == "PENDING"


async def test_retry_expiry_unknown_and_missing_feedback(settings, tmp_path):
    settings.actuator_execution_enabled = True  # isolated mock delivery only

    def idempotent(policy):
        policy["actions"][0]["idempotent"] = True

    async with scenario(settings, tmp_path, change=idempotent) as (app, client, _):
        settings.command_retry_seconds = 0.01
        decision = await approved(client, settings)
        command = (await execute(client, settings, decision["decision_id"])).json()["commands"][0]
        app.state.actuator_manager.adapter = FailingAdapter(2)
        start = datetime.now(UTC)
        for offset in (0, 1, 2):
            await app.state.actuator_manager.tick(start + timedelta(seconds=offset))
        with app.state.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, UUID(command["command_id"]))
            assert row.status == "DELIVERED" and row.payload["attempts"] == 3
        await app.state.actuator_manager.tick(start + timedelta(seconds=40))
        with app.state.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, UUID(command["command_id"]))
            assert row.status == "UNKNOWN"
    expiry_path = tmp_path / "expiry"
    expiry_path.mkdir()
    async with scenario(settings, expiry_path) as (app, client, _):
        settings.command_ttl_seconds = 1
        decision = await approved(client, settings)
        command = (await execute(client, settings, decision["decision_id"])).json()["commands"][0]
        await app.state.actuator_manager.tick(datetime.now(UTC) + timedelta(seconds=2))
        with app.state.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, UUID(command["command_id"]))
            assert row.status == "EXPIRED"
    uncertain_path = tmp_path / "uncertain"
    uncertain_path.mkdir()
    async with scenario(settings, uncertain_path) as (app, client, _):
        decision = await approved(client, settings)
        command = (await execute(client, settings, decision["decision_id"])).json()["commands"][0]
        app.state.actuator_manager.adapter = FailingAdapter(1, uncertain=True)
        await app.state.actuator_manager.tick()
        with app.state.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, UUID(command["command_id"]))
            assert row.status == "UNKNOWN"


async def test_mock_twin_end_to_end(settings, tmp_path):
    settings.actuator_transport = "mock_twin"
    settings.twin_base_url = "http://twin"
    settings.actuator_execution_enabled = True  # isolated mock delivery only
    settings.mock_twin_allowed_actions = "simulation_response"
    async with scenario(settings, tmp_path) as (app, client, _):
        twin = create_twin(settings)
        twin.state.transport = httpx.ASGITransport(app)
        app.state.actuator_manager.adapter = MockTwinAdapter(settings, httpx.ASGITransport(twin))
        decision = await approved(client, settings)
        command = (await execute(client, settings, decision["decision_id"])).json()["commands"][0]
        await app.state.actuator_manager.tick()
        with app.state.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, UUID(command["command_id"]))
            assert row.status == "EXECUTED"
        assert twin.state.actuators["fixture-actuator"]["status"] == "executed"


async def test_restart_recovers_interrupted_delivery(settings, tmp_path):
    settings.actuator_execution_enabled = True  # isolated mock delivery only

    def idempotent(policy):
        policy["actions"][0]["idempotent"] = True

    async with scenario(settings, tmp_path, change=idempotent) as (app, client, _):
        decision = await approved(client, settings)
        command = (await execute(client, settings, decision["decision_id"])).json()["commands"][0]
        with app.state.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, UUID(command["command_id"]))
            app.state.actuator_manager.transition(
                session,
                row,
                "DISPATCHING",
                "synthetic_interruption",
                datetime.now(UTC),
            )
    restored = create_app(settings)
    async with restored.router.lifespan_context(restored):
        with restored.state.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, UUID(command["command_id"]))
            assert row.status == "PENDING"


async def test_orion_payload_auth_and_reconciliation(settings):
    settings.orion_base_url = AnyHttpUrl("https://orion.invalid")
    settings.orion_bearer_token = SecretStr("synthetic-token")
    settings.orion_fiware_service = "city"
    settings.orion_fiware_service_path = "/simulation"
    seen = []

    def handler(request):
        seen.append(request)
        if request.method == "PATCH":
            return httpx.Response(204)
        return httpx.Response(
            200,
            json={
                "type": "StructuredValue",
                "value": {"command_id": "command", "status": "executed"},
            },
        )

    adapter = OrionAdapter(settings, httpx.MockTransport(handler))
    now = datetime.now(UTC)
    from app.schemas.actuator import ActuatorCommand

    command = ActuatorCommand(
        command_id=uuid5(NAMESPACE_URL, "command"),
        decision_id=uuid5(NAMESPACE_URL, "decision"),
        correlation_id=uuid5(NAMESPACE_URL, "correlation"),
        issued_at=now,
        actuator_id="fixture/1",
        action="set_level",
        parameters={"level": 1},
        expires_at=now + timedelta(minutes=1),
    )
    assert (await adapter.deliver(command)).transport_status == 204
    payload = __import__("json").loads(seen[0].content)
    # Task 7.3G: REAL Twin contract = plain NGSI attributes, no legacy
    # StructuredValue "command" wrapper.
    assert "command" not in payload
    assert payload["level"] == {"type": "float", "value": 1.0}
    assert seen[0].headers["authorization"] == "Bearer synthetic-token"
    assert seen[0].headers["fiware-service"] == "city"
    assert "fixture%2F1" in str(seen[0].url)
    # Twin contract: PATCH with elementid/type query params (no k1/k2 here —
    # no secrets file configured in this test → fail-closed unauthenticated).
    query = str(seen[0].url).split("?")[-1]
    assert "elementid=" in query and "fixture%2F1" in query
    assert "type=" in query and "k1" not in query and "k2" not in query
    assert (await adapter.state("fixture/1"))["status"] == "executed"


async def test_orion_per_device_credentials_and_readback(settings, tmp_path):
    """Task 7.3G: device-scoped k1/k2 from the secrets file attach to the
    PATCH of THAT device only, and readback uses the plain entity GET."""
    secrets_file = tmp_path / "secrets.json"
    secrets_file.write_text(
        json.dumps({"us-b-alarm-01": {"k1": "K1", "k2": "K2"}}), encoding="utf-8"
    )
    settings.orion_base_url = AnyHttpUrl("https://orion.invalid")
    settings.orion_actuator_secrets_file = str(secrets_file)
    settings.orion_entity_prefix = ""
    settings.orion_bearer_token = SecretStr("synthetic-token")
    seen = []

    def handler(request):
        seen.append(request)
        if request.method == "PATCH":
            return httpx.Response(204)
        return httpx.Response(
            200,
            json={
                "id": "us-b-alarm-01",
                "type": "FireAlarm",
                "alarmState": {"type": "string", "value": "on"},
            },
        )

    adapter = OrionAdapter(settings, httpx.MockTransport(handler))
    now = datetime.now(UTC)
    command = ActuatorCommand(
        command_id=uuid5(NAMESPACE_URL, "alarm"),
        decision_id=uuid5(NAMESPACE_URL, "decision"),
        correlation_id=uuid5(NAMESPACE_URL, "correlation"),
        issued_at=now,
        actuator_id="us-b-alarm-01",
        action="alarmState",
        parameters={"alarmState": "on"},
        expires_at=now + timedelta(minutes=1),
    )
    assert (await adapter.deliver(command)).transport_status == 204
    url = str(seen[0].url)
    assert "us-b-alarm-01" in url
    assert "k1=K1" in url and "k2=K2" in url
    assert "elementid=us-b-alarm-01" in url
    assert "type=FireAlarm" in url
    payload = json.loads(seen[0].content)
    assert payload == {"alarmState": {"type": "string", "value": "on"}}

    # Readback: plain entity GET with elementid/type, NO credentials.
    entity = await adapter.read_entity("us-b-alarm-01")
    read_url = str(seen[-1].url)
    assert read_url.startswith("https://orion.invalid/v2/entities/us-b-alarm-01")
    assert "elementid=us-b-alarm-01" in read_url and "type=FireAlarm" in read_url
    assert "k1" not in read_url and "k2" not in read_url

    # Unknown device: no credentials attached (fail-closed, honest attempt).
    command_unknown = command.model_copy(update={"actuator_id": "us-a-light-01"})
    await adapter.deliver(command_unknown)
    assert seen[-1].method == "PATCH"
    assert "k1" not in seen[-1].url.params and "k2" not in seen[-1].url.params
    assert entity == {"alarmState": "on"}


@pytest.mark.parametrize("status,retryable", [(401, False), (503, True)])
async def test_orion_structured_delivery_errors(settings, status, retryable):
    settings.orion_base_url = AnyHttpUrl("https://orion.invalid")
    adapter = OrionAdapter(
        settings,
        httpx.MockTransport(lambda _: httpx.Response(status)),
    )
    now = datetime.now(UTC)
    from app.schemas.actuator import ActuatorCommand

    command = ActuatorCommand(
        command_id=uuid5(NAMESPACE_URL, f"command-{status}"),
        decision_id=uuid5(NAMESPACE_URL, "decision"),
        correlation_id=uuid5(NAMESPACE_URL, "correlation"),
        issued_at=now,
        actuator_id="fixture",
        action="set_level",
        expires_at=now + timedelta(minutes=1),
    )
    with pytest.raises(OrionError) as error:
        await adapter.deliver(command)
    assert error.value.retryable is retryable
    assert error.value.code.startswith("orion_")


async def test_orion_rejects_malformed_state(settings):
    settings.orion_base_url = AnyHttpUrl("https://orion.invalid")
    adapter = OrionAdapter(
        settings,
        httpx.MockTransport(lambda _: httpx.Response(200, json={"value": []})),
    )
    with pytest.raises(OrionError, match="orion_state_invalid_payload"):
        await adapter.state("fixture")


async def test_approved_orion_command_requires_later_twin_publication(settings, tmp_path):
    """Full isolated Zone-B chain through Orion publication and dashboard readback."""
    settings.actuator_execution_enabled = True
    settings.orion_base_url = AnyHttpUrl("https://orion.invalid")
    settings.orion_entity_prefix = ""
    settings.command_retry_seconds = 0.01
    secrets_file = tmp_path / "synthetic-keys.json"
    secrets_file.write_text(json.dumps({"us-b-alarm-01": {"k1": "fixture", "k2": "fixture"}}))
    settings.orion_actuator_secrets_file = str(secrets_file)

    def policy_change(policy):
        actuator = policy["actuators"].pop("fixture-actuator")
        actuator["capabilities"] = {
            "simulation_response": {"alarmState": {"values": ["on", "off"]}}
        }
        policy["actuators"]["us-b-alarm-01"] = actuator
        policy["actions"][0].update(actuator_id="us-b-alarm-01", parameters={"alarmState": "on"})

    async with scenario(settings, tmp_path, change=policy_change) as (app, client, _):
        observed = {"timestamp": datetime.now(UTC) - timedelta(seconds=1)}
        patches = []

        def handler(request):
            if request.method == "PATCH":
                patches.append(request)
                return httpx.Response(204)
            return httpx.Response(
                200,
                json={
                    "id": "us-b-alarm-01",
                    "type": "FireAlarm",
                    "alarmState": {"type": "string", "value": "on"},
                    "timestamp": {"type": "string", "value": observed["timestamp"].isoformat()},
                },
            )

        manager = app.state.actuator_manager
        manager.adapter = OrionAdapter(settings, httpx.MockTransport(handler))
        decision = await approved(client, settings)
        response = await execute(client, settings, decision["decision_id"])
        identifier = UUID(response.json()["commands"][0]["command_id"])
        await manager.tick()
        assert len(patches) == 1
        assert json.loads(patches[0].content) == {"alarmState": {"type": "string", "value": "on"}}
        assert patches[0].url.params["type"] == "FireAlarm"
        assert patches[0].url.params["k1"] == "fixture"
        with app.state.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, identifier)
            command = ActuatorCommand.model_validate(row.payload["command"])
            delivered = datetime.fromisoformat(row.payload["delivered_at"])
        # The broker already echoes the target but Twin has not republished it.
        await manager._reconcile_or_timeout(identifier, command, delivered + timedelta(seconds=1))
        with app.state.database.transaction() as session:
            assert session.get(ActuatorCommandRecord, identifier).status == "DELIVERED"
        observed["timestamp"] = delivered + timedelta(seconds=2)
        await manager._reconcile_or_timeout(identifier, command, delivered + timedelta(seconds=3))
        with app.state.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, identifier)
            assert row.status == "EXECUTED"
            assert row.payload["execution"]["source"] == "orion_entity"
        await manager.tick(delivered + timedelta(seconds=4))
        assert len(patches) == 1

        # The operator view must agree with the authoritative persisted chain:
        # incident -> optimal decision -> explicit approval -> executed command.
        login = await client.post(
            "/dashboard/session",
            headers={"X-API-Key": settings.brain_api_key.get_secret_value()},
            json={},
        )
        assert login.status_code == 200
        dashboard = (await client.get("/dashboard/api/snapshot")).json()
        assert dashboard["metrics"]["active_incidents"] == 1
        assert dashboard["metrics"]["approved_decisions"] == 1
        assert dashboard["metrics"]["executed_commands"] == 1
        assert dashboard["decisions"][0]["reason"] == "explicit_service_approval"
        assert dashboard["decisions"][0]["approval"]["reason"] == "synthetic approval"
        assert dashboard["decisions"][0]["selected_actions"][0]["actuator_id"] == (
            "us-b-alarm-01"
        )
        assert dashboard["actions"][0]["command_id"] == str(identifier)
        assert dashboard["actions"][0]["status"] == "EXECUTED"
        assert dashboard["actions"][0]["execution"]["source"] == "orion_entity"
        with app.state.database.transaction() as session:
            revisions = list(
                session.scalars(
                    select(DecisionRevision).order_by(DecisionRevision.created_at)
                )
            )
        assert any(
            revision.payload.get("reason") == "optimal_verified" for revision in revisions
        )
