"""Synthetic policies, capacities, actions and observations for simulation only."""

import asyncio
import json
from contextlib import asynccontextmanager
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from app.database.models import (
    ActuatorCommandRecord,
    CityRegistryRecord,
    DecisionRecord,
    DecisionRevision,
    ForecastRecord,
)
from app.decision.config import DecisionPolicies, digest, load_policy
from app.decision.optimizer import optimize, verify
from app.intelligence.incident_rules import IncidentRules
from app.main import create_app
from app.schemas.guardian import QuarantineNotification
from app.state.registry import Registry
from tests.integration.test_incidents import rule, sample, setup
from tests.integration.test_trust_pipeline import post, verdict


def simulation_policy(configured, *, critical=True):
    now = datetime.now(UTC)
    availability = {
        "observed_at": (now - timedelta(minutes=1)).isoformat(),
        "valid_until": (now + timedelta(minutes=5)).isoformat(),
        "available": True,
    }
    return {
        "version": "1.0.0",
        "simulation_only": True,
        "approved": True,
        "approval_reference": "synthetic-test-review",
        "approved_incident_config_sha256": digest(
            IncidentRules.model_validate(
                {
                    "version": "1.0.0",
                    "simulation_only": True,
                    "rules": [configured],
                }
            ).model_dump()
        ),
        "resources": {"fixture-budget": {**availability, "capacity": 1, "zones": ["simulation"]}},
        "actuators": {
            "fixture-actuator": {
                **availability,
                "zone": "simulation",
                "capabilities": {"simulation_response": {"level": {"minimum": 0, "maximum": 1}}},
            }
        },
        "actions": [
            {
                "id": "fixture-action",
                "incident_types": [configured["incident_type"]],
                "zones": ["simulation"],
                "minimum_severity": "medium",
                "action_type": "simulation_response",
                "actuator_id": "fixture-actuator",
                "parameters": {"level": 1},
                "resources": {"fixture-budget": 1},
                "cost": 1,
                "benefit": 1,
                "safety_critical": critical,
                "requires_approval": critical,
            }
        ],
        "optimization": {
            "max_actions": 2,
            "severity_weights": {"medium": 10, "high": 20},
            "urgency_weights": {configured["incident_type"]: 1},
            "zone_weights": {"simulation": 1},
            "cost_weight": 1,
        },
    }


@asynccontextmanager
async def scenario(settings, tmp_path, configured=None, change=None, critical=True):
    configured = configured or rule()
    policy = simulation_policy(configured, critical=critical)
    if change:
        change(policy)
    path = tmp_path / "simulation-policies.json"
    path.write_text(json.dumps(policy))
    settings.decision_policy_file = str(path)
    async with setup(settings, tmp_path, configured) as (app, client, registry):
        now = datetime.now(UTC)
        await sample(app, client, settings, registry, 11, now - timedelta(seconds=10))
        event = await sample(app, client, settings, registry, 12, now - timedelta(seconds=5))
        yield app, client, event


async def evaluate(client, settings, body=None, role="brain"):
    return await client.post(
        "/v1/decisions/evaluate",
        json=body or {},
        headers={
            "X-API-Key": getattr(settings, f"{role}_api_key").get_secret_value(),
        },
    )


async def test_approval_audit_idempotency_and_restart(settings, tmp_path):
    async with scenario(settings, tmp_path) as (app, client, _):
        response = await evaluate(client, settings)
        assert response.status_code == 200
        result = response.json()
        assert result["status"] == "EVALUATED", result
        assert not result["approved_actions"]
        identifier = result["decision_id"]
        responses = await asyncio.gather(*(evaluate(client, settings) for _ in range(3)))
        assert all(r.json()["decision_id"] == identifier for r in responses)
        body = {"approval": {"decision_id": identifier, "reason": "synthetic test approval"}}
        assert (await evaluate(client, settings, body, role="twin")).status_code == 403
        result = (await evaluate(client, settings, body)).json()
        assert result["status"] == "APPROVED"
        assert len(result["approved_actions"]) == 1
        assert result["execution_enabled"] is False
        assert (await evaluate(client, settings, body)).json()["status"] == "APPROVED"
        with app.state.database.transaction() as session:
            assert session.scalar(select(func.count()).select_from(DecisionRecord)) == 1
            states = [r.payload["status"] for r in session.scalars(select(DecisionRevision))]
            assert states == ["PROPOSED", "EVALUATED", "APPROVED"]
            assert session.scalar(select(func.count()).select_from(ActuatorCommandRecord)) == 0
        headers = {"X-API-Key": settings.brain_api_key.get_secret_value()}
        for path in ("", "/history", f"/{identifier}"):
            assert (await client.get("/v1/decisions" + path)).status_code == 401
            assert (await client.get("/v1/decisions" + path, headers=headers)).status_code == 200
        assert (await client.post("/v1/decisions/evaluate", json={})).status_code == 401
        assert (await evaluate(client, settings, role="guardian")).status_code == 403
    restarted = create_app(settings)
    async with restarted.router.lifespan_context(restarted):
        await restarted.state.processor.tick()
        with restarted.state.database.transaction() as session:
            row = session.scalar(select(DecisionRecord))
            assert str(row.id) == identifier
            assert row.status == "APPROVED"


@pytest.mark.parametrize(
    "change,reason",
    [
        (lambda p: p.update(approved=False), "policy_not_approved"),
        (
            lambda p: p.update(approved_incident_config_sha256="unreviewed"),
            "incident_thresholds_not_approved",
        ),
        (
            lambda p: p["actuators"]["fixture-actuator"].update(available=False),
            "actuator_availability_unverified",
        ),
        (lambda p: p["resources"]["fixture-budget"].update(capacity=0), "resource_unavailable"),
        (lambda p: p["actions"][0].update(zones=["elsewhere"]), "zone_restriction"),
        (
            lambda p: p["actions"][0].update(parameters={"level": 99}),
            "actuator_capability_violation",
        ),
        (lambda p: p["optimization"].update(urgency_weights={}), "priority_missing_or_nonpositive"),
    ],
)
async def test_policy_rejection(settings, tmp_path, change, reason):
    async with scenario(settings, tmp_path, change=change) as (_, client, _):
        result = (await evaluate(client, settings)).json()
        assert result["status"] == "REJECTED"
        assert result["outcome"] == "NO_ACTION"
        assert not result["approved_actions"]
        reasons = [r["reason"] for r in result["rejected_alternatives"]] + [result["reason"]]
        assert reason in reasons


@pytest.mark.parametrize(
    "kind", ["revocation", "sensor_quarantine", "actuator_quarantine", "expiry"]
)
async def test_cancel_unsafe_decision(settings, tmp_path, kind):
    async with scenario(settings, tmp_path, critical=False) as (app, client, event):
        result = (await evaluate(client, settings)).json()
        assert result["status"] == "APPROVED"
        if kind == "revocation":
            await post(
                client,
                settings,
                "/verdicts",
                verdict(event, revision=1, status="revoked"),
                "guardian",
            )
        elif "quarantine" in kind:
            notice = QuarantineNotification(
                notification_id=uuid4(),
                correlation_id=uuid4(),
                issued_at=datetime.now(UTC),
                guardian_id=settings.guardian_identity,
                target_type="actuator" if kind == "actuator_quarantine" else "sensor",
                target_id="fixture-actuator" if kind == "actuator_quarantine" else event.sensor_id,
                action="quarantine",
                revision=1,
                reason_code="simulation",
            )
            assert (
                await post(client, settings, "/quarantines", notice, "guardian")
            ).status_code == 202
        await app.state.processor.tick(
            datetime.now(UTC) + timedelta(minutes=10) if kind == "expiry" else None
        )
        with app.state.database.transaction() as session:
            decision = session.scalar(select(DecisionRecord))
            assert decision.status == "CANCELLED"
            assert decision.payload["approved_actions"] == []
        approval = {"approval": {"decision_id": result["decision_id"], "reason": "stale approval"}}
        assert (await evaluate(client, settings, approval)).status_code == 409


async def test_missing_policy_and_empty_thresholds(settings, tmp_path):
    async with setup(settings, tmp_path) as (_, client, _):
        result = (await evaluate(client, settings)).json()
        assert result["reason"] == "policy_not_configured"
        assert result["outcome"] == "NO_ACTION"
    async with scenario(settings, tmp_path) as (app, client, _):
        app.state.city_engine.incidents.rules.rules = []
        result = (await evaluate(client, settings)).json()
        assert result["reason"] == "incident_thresholds_not_approved"
        assert result["selected_actions"] == []


def test_optimizer_resources_conflicts_priorities():
    policy = DecisionPolicies.model_validate(simulation_policy(rule()))
    first = {
        **policy.actions[0].model_dump(),
        "candidate_id": "first",
        "incident_id": "first",
        "score": 10,
    }
    second = {
        **first,
        "candidate_id": "second",
        "incident_id": "second",
        "actuator_id": "second",
        "score": 20,
    }
    available = [first, second]
    selected, reason = optimize(available, policy)
    assert reason == "optimal_verified" and selected == [second]
    assert not verify(available, available, policy)
    policy.resources["fixture-budget"].capacity = 2
    assert optimize(available, policy)[0] == available
    second["conflicts"] = [first["id"]]
    assert optimize(available, policy)[0] == [second]
    policy.optimization.max_actions = 0
    assert optimize(available, policy)[0] == []


async def test_solver_failure_and_unverified_result(settings, tmp_path, monkeypatch):
    async with scenario(settings, tmp_path) as (_, client, _):
        monkeypatch.setattr(
            "app.decision.engine.optimize",
            lambda *_: ([{"candidate_id": "forged"}], "optimal_verified"),
        )
        result = (await evaluate(client, settings)).json()
        assert result["outcome"] == "NO_ACTION"
        assert result["reason"] == "safety_recheck_failed"


def test_solver_errors_and_timeout(monkeypatch):
    from ortools.sat.python import cp_model

    policy = DecisionPolicies.model_validate(simulation_policy(rule()))
    action = {
        **policy.actions[0].model_dump(),
        "candidate_id": "fixture",
        "incident_id": "fixture",
        "score": 1,
    }
    for status in (
        cp_model.UNKNOWN,
        cp_model.FEASIBLE,
        cp_model.INFEASIBLE,
        cp_model.MODEL_INVALID,
    ):
        monkeypatch.setattr(cp_model.CpSolver, "solve", lambda *_, status=status: status)
        assert optimize([action], policy) == ([], "solver_did_not_prove_optimality")

    def fail(*_):
        raise RuntimeError("synthetic solver failure")

    monkeypatch.setattr(cp_model.CpSolver, "solve", fail)
    assert optimize([action], policy) == ([], "solver_unavailable_or_failed")


@pytest.mark.parametrize(
    "kind,measurement,unit,mode,thresholds",
    [
        ("traffic_congestion", "traffic", "METR-LA_native_speed", "below", {"medium": 100}),
        ("high_water", "water_level", "ft", "above", {"medium": 10}),
        ("power_overload", "power_load", "kW", "above", {"medium": 10}),
        ("air_pollution", "air_quality", "ug/m3", "above", {"medium": 10}),
        ("smoke_alert", "smoke", "ppm", "above", {"medium": 10}),
    ],
)
async def test_response_domains(settings, tmp_path, kind, measurement, unit, mode, thresholds):
    configured = rule(
        incident_type=kind, measurement=measurement, unit=unit, mode=mode, thresholds=thresholds
    )
    async with scenario(settings, tmp_path, configured) as (_, client, _):
        result = (await evaluate(client, settings)).json()
        assert result["status"] == "EVALUATED", result
        assert result["selected_actions"][0]["incident_types"] == [kind]


async def test_simultaneous_incidents_across_zones(settings, tmp_path):
    def changes(policy):
        policy["resources"]["fixture-budget"]["zones"].append("second-zone")
        actuator = deepcopy(policy["actuators"]["fixture-actuator"])
        actuator["zone"] = "second-zone"
        policy["actuators"]["second-actuator"] = actuator
        action = deepcopy(policy["actions"][0])
        action.update(id="second-action", actuator_id="second-actuator", zones=["second-zone"])
        policy["actions"].append(action)
        policy["optimization"]["zone_weights"]["second-zone"] = 1

    async with scenario(settings, tmp_path, change=changes) as (app, client, _):
        with app.state.database.transaction() as session:
            record = session.get(CityRegistryRecord, 1)
            registry = Registry.model_validate(record.payload)
            registry.zones.append("second-zone")
            registry.sensors.append(
                registry.sensors[0].model_copy(
                    update={
                        "sensor_id": "second-sensor",
                        "zone_id": "second-zone",
                    }
                )
            )
            record.payload = registry.model_dump()
        now = datetime.now(UTC)
        await sample(app, client, settings, registry, 25, now - timedelta(seconds=10), index=1)
        await sample(app, client, settings, registry, 25, now - timedelta(seconds=5), index=1)
        result = (await evaluate(client, settings)).json()
        assert len(result["incident_ids"]) == 2
        assert len(result["selected_actions"]) == 1
        assert result["selected_actions"][0]["zone_id"] == "second-zone"
        assert result["rejected_alternatives"]


def test_configuration_fails_closed():
    policy, error = load_policy("config/policies.simulation.yaml")
    assert error is None and not policy.approved
    assert not any(actuator.current(datetime.now(UTC)) for actuator in policy.actuators.values())
    assert load_policy("absent-policy.yaml") == (None, "policy_invalid_or_missing")
    data = simulation_policy(rule())
    data["actions"][0]["requires_approval"] = False
    with pytest.raises(ValueError, match="safety-critical"):
        DecisionPolicies.model_validate(data)


async def test_simulation_cannot_authorize_production(settings, tmp_path):
    async with scenario(settings, tmp_path) as (_, client, _):
        settings.environment = "production"
        result = (await evaluate(client, settings)).json()
        assert result["reason"] == "simulation_policy_in_production"
        assert result["outcome"] == "NO_ACTION"


async def test_resource_expiry_cancels_plan(settings, tmp_path):
    async with scenario(settings, tmp_path, critical=False) as (app, client, _):
        resource = app.state.city_engine.decisions.policy.resources["fixture-budget"]
        resource.valid_until = datetime.now(UTC) + timedelta(seconds=5)
        assert (await evaluate(client, settings)).json()["status"] == "APPROVED"
        await app.state.processor.tick(resource.valid_until + timedelta(seconds=1))
        with app.state.database.transaction() as session:
            assert session.scalar(select(DecisionRecord)).status == "CANCELLED"


async def test_forecast_response_requires_policy_and_current_evidence(settings, tmp_path):
    configured = rule(
        incident_type="high_water",
        measurement="water_level",
        unit="ft",
        source="forecast",
        min_samples=1,
        persistence_seconds=0,
    )
    async with scenario(settings, tmp_path, configured) as (app, client, event):
        state = app.state.city_engine.snapshot()
        with app.state.database.transaction() as session:
            session.add(
                ForecastRecord(
                    id=uuid4(),
                    correlation_id=uuid4(),
                    occurred_at=datetime.now(UTC),
                    family="water",
                    status="succeeded",
                    payload={
                        "request": {"sensor_id": event.sensor_id},
                        "sensor_mappings": state["registry"]["sensors"],
                        "evidence": state["sensors"][event.sensor_id]["evidence"],
                        "predictions": [
                            {
                                "unit": "ft",
                                "value": 12,
                                "horizon_minutes": 60,
                                "forecast_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                            }
                        ],
                        "fixture": "synthetic forecast; not a production prediction",
                    },
                )
            )
        result = (await evaluate(client, settings)).json()
        assert result["status"] == "REJECTED"
        assert result["rejected_alternatives"][0]["reason"] == "forecast_response_not_authorized"
        app.state.city_engine.decisions.policy.actions[0].allow_forecast_warning = True
        result = (await evaluate(client, settings)).json()
        assert result["status"] == "EVALUATED"
        await post(
            client, settings, "/verdicts", verdict(event, revision=1, status="revoked"), "guardian"
        )
        await app.state.processor.tick()
        with app.state.database.transaction() as session:
            assert (
                session.scalar(
                    select(DecisionRecord).where(
                        DecisionRecord.status == "CANCELLED",
                    )
                )
                is not None
            )
