"""End-to-end core pipeline verification: Sensor → Guardian → Trust →
Incident → Decision → Approval → Mock Twin command → Execution Feedback.

Uses only synthetic data, the in-process MockTwinAdapter, and the existing
scenario/approved/execute helpers. Forecast-based decisions are excluded
(only the default observed-incident scenario policy is used).
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import httpx
from sqlalchemy import func, select

from app.database.models import (
    ActuatorCommandRecord,
    AuditEvent,
    CommandRevision,
    DecisionRecord,
    DecisionRevision,
)
from app.execution.actuator_manager import MockTwinAdapter
from mocks.mock_twin import create_app as create_twin
from tests.integration.test_actions import AcceptingAdapter, approved, execute
from tests.integration.test_decisions import evaluate, scenario
from tests.integration.test_incidents import rows
from tests.integration.test_trust_pipeline import post, status, verdict


async def test_full_core_pipeline_end_to_end(settings, tmp_path):
    """Single sequential pass through the whole core pipeline."""
    settings.actuator_execution_enabled = True  # isolated mock delivery only
    settings.actuator_transport = "mock_twin"
    settings.twin_base_url = "http://twin"
    settings.mock_twin_allowed_actions = "simulation_response"
    async with scenario(settings, tmp_path) as (app, client, event):
        twin = create_twin(settings)
        twin.state.transport = httpx.ASGITransport(app)
        app.state.actuator_manager.adapter = MockTwinAdapter(
            settings, httpx.ASGITransport(twin)
        )

        # 1-2. Sensor reading + Guardian verdict were posted by scenario();
        # both stored by ingestion (202) with a Guardian-verified trust chain.
        result = await status(client, settings, event)
        assert result["state"] == "TRUSTED"

        # 3. Trust verification produced an incident via city rebuild.
        with app.state.database.transaction() as session:
            state = app.state.city_engine.rebuild(session, datetime.now(UTC))
        assert state["sensors"][event.sensor_id]["availability"] == "available"

        # 4. Decision → approval (explicit, not auto) → command enqueue.
        decision = await approved(client, settings)
        assert decision["status"] == "APPROVED"
        # The decision payload records the static policy flag, which the
        # decision engine always stores as False; the runtime dispatch gate is
        # reported by the execute API as dispatch_enabled.
        assert decision["execution_enabled"] is False
        execution = await execute(client, settings, decision["decision_id"])
        assert execution.status_code == 200
        assert execution.json()["dispatch_enabled"] is True
        command = execution.json()["commands"][0]
        assert command["status"] == "PENDING"
        assert command["decision_id"] == decision["decision_id"]
        assert command["command_id"] is not None

        # 5-6. Mock actuator command delivered in-process; feedback recorded.
        await app.state.actuator_manager.tick()
        with app.state.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, UUID(command["command_id"]))
            assert row.status == "EXECUTED"
            # The command carries the decision's correlation ID, which is
            # distinct from the originating sensor reading's correlation ID.
            assert row.correlation_id is not None
            assert row.correlation_id == UUID(decision["correlation_id"])
            assert row.correlation_id == UUID(command["correlation_id"])
        assert twin.state.actuators["fixture-actuator"]["status"] == "executed"

        # 7. Audit records are per-entity: sensor ingestion audits use the
        # sensor event ID; command audits use the command ID; decision audits
        # use the decision ID. Verify each against its own entity identifier.
        with app.state.database.transaction() as session:
            # 7a. Sensor event_received audit for the real sensor event.
            sensor_audits = session.scalars(
                select(AuditEvent).where(
                    AuditEvent.payload["event_id"].as_string() == str(event.event_id)
                )
            ).all()
            assert {a.action for a in sensor_audits} >= {"event_received"}
            # Verify Sensor Reading ingestion audit
            sensor_received = [
              a for a in sensor_audits
              if a.action == "event_received"
              and a.payload.get("record_type") == "sensor_events"
            ]

            assert sensor_received, "Missing sensor ingestion audit"
            assert all(a.actor == "twin" for a in sensor_received)
            assert all(
              a.correlation_id == event.correlation_id
              for a in sensor_received
            )

# Verify Guardian Verdict ingestion audit
            guardian_received = [
              a for a in sensor_audits
              if a.action == "event_received"
              and a.payload.get("record_type") == "guardian_verdicts"
            ]

            assert guardian_received, "Missing Guardian verdict audit"
            assert all(a.actor == "guardian" for a in guardian_received)
            assert all(
              a.correlation_id == event.correlation_id
              for a in guardian_received
       )
            assert all(a.correlation_id == event.correlation_id for a in sensor_audits)

            # 7b. Command transition audits under the command ID, carrying the
            # decision's correlation ID chain.
            command_audits = session.scalars(
                select(AuditEvent).where(
                    AuditEvent.payload["event_id"].as_string() == str(row.id)
                )
            ).all()
            assert {a.action for a in command_audits} >= {"command_transition"}
            assert all(a.actor == "actuator-manager" for a in command_audits)
            assert all(a.correlation_id == row.correlation_id for a in command_audits)
            assert {a.payload["status"] for a in command_audits} >= {
                "PENDING",
                "DISPATCHING",
                "EXECUTED",
            }

            # 7c. Decision transition audits under the real decision ID.
            decision_audits = session.scalars(
                select(AuditEvent).where(
                    AuditEvent.payload["event_id"].as_string()
                    == decision["decision_id"]
                )
            ).all()
            assert {a.action for a in decision_audits} >= {"decision_transition"}
            assert all(a.actor == "decision-engine" for a in decision_audits)
            assert {a.payload["status"] for a in decision_audits} >= {
                "PROPOSED",
                "EVALUATED",
                "APPROVED",
            }

        # CommandRevision lifecycle history for the command entity.
        with app.state.database.transaction() as session:
            revisions = session.scalars(
                select(CommandRevision).where(CommandRevision.command_id == row.id)
            ).all()
            assert [r.payload["status"] for r in revisions] == [
                "PENDING",
                "DISPATCHING",
                "EXECUTED",
            ]

        # DecisionRevision lifecycle history for the decision entity.
        with app.state.database.transaction() as session:
            decision_revisions = session.scalars(
                select(DecisionRevision).where(
                    DecisionRevision.decision_id == UUID(decision["decision_id"])
                )
            ).all()
            assert [r.payload["status"] for r in decision_revisions] == [
                "PROPOSED",
                "EVALUATED",
                "APPROVED",
            ]


async def test_untrusted_events_cannot_authorize_actions(settings, tmp_path):
    """Revoking one reading must make THAT event untrusted/ineligible, and
    revoked evidence must not independently authorize incidents or actions.

    The scenario fixture posts two trusted readings (values 11 and 12) to the
    same sensor. Revoking the newest reading leaves one still-trusted point,
    so per CityEngine semantics the sensor can remain "available"; however a
    single eligible point cannot satisfy the rule's min_samples (2), so no
    incident exists and nothing unsafe can be authorized.
    """
    async with scenario(settings, tmp_path) as (app, client, event):
        # Revoke the newest reading via a newer guardian verdict.
        await post(
            client,
            settings,
            "/verdicts",
            verdict(event, revision=1, status="revoked"),
            "guardian",
        )
        await app.state.processor.tick()

        # 1. The revoked event itself is UNTRUSTED and ineligible.
        result = await status(client, settings, event)
        assert result["state"] == "UNTRUSTED"
        assert not result["eligible"]

        with app.state.database.transaction() as session:
            state = app.state.city_engine.rebuild(session, datetime.now(UTC))

        # 2+3. Sensor semantics: a remaining trusted reading keeps availability
        # per rebuild() rules; revoked evidence contributes no points.
        sensor_state = state["sensors"][event.sensor_id]
        if sensor_state["availability"] == "available":
            # Only the surviving trusted reading may back this availability.
            eligible_events = {
                item["event_id"]
                for signal_values in [sensor_state["evidence"]]
                for item in signal_values
            }
            assert str(event.event_id) not in eligible_events, (
                "revoked evidence must not back sensor availability"
            )
        else:
            assert sensor_state["availability"] in {"stale", "unavailable"}

        # 4. Revoked evidence cannot independently confirm an incident
        # (min_samples=2 is unreachable with one eligible point). Incident
        # history may retain the record (e.g. in DETECTED state), but only
        # ACTIVE/ESCALATED incidents are eligible for decision candidates, so
        # the retained record must not be actionable.
        assert all(
            record.payload["status"] not in {"ACTIVE", "ESCALATED"}
            for record in rows(app)
        ), "revoked evidence must not leave an actionable incident"

        # 5. A new evaluation against the post-revocation state must not
        # authorize any action, and no unsafe command may exist.
        decision = (await evaluate(client, settings)).json()
        assert decision["status"] in {"EVALUATED", "REJECTED"}
        assert not decision.get("approved_actions")
        with app.state.database.transaction() as session:
            active = session.scalars(
                select(DecisionRecord).where(
                    DecisionRecord.status.in_(["PROPOSED", "EVALUATED", "APPROVED"])
                )
            ).all()
            for decision_row in active:
                assert decision_row.payload.get("approved_actions") in ([], None)
            assert (
                session.scalar(
                    select(func.count()).select_from(ActuatorCommandRecord)
                )
                == 0
            ), "no unsafe command may be created from revoked evidence"


async def test_idle_tick_without_active_decisions_skips_rebuild(settings, tmp_path):
    """Idle fast path: zero events + no active decisions → no snapshot growth."""
    async with scenario(settings, tmp_path) as (app, client, _):
        await app.state.processor.tick()  # process pending, writes a snapshot
        with app.state.database.transaction() as session:
            before = session.scalar(select(func.count()).select_from(AuditEvent))
        for _ in range(4):
            await app.state.processor.tick()
        with app.state.database.transaction() as session:
            after = session.scalar(select(func.count()).select_from(AuditEvent))
            # No new audit rows ⇒ no rebuild, no incident/decision work ran.
            assert after == before


async def test_dispatch_blocked_without_execution_flag(settings, tmp_path):
    """Requirement 5: execution disabled blocks outbound dispatch end to end."""
    async with scenario(settings, tmp_path) as (app, client, _):
        adapter = AcceptingAdapter()
        app.state.actuator_manager.adapter = adapter
        settings.actuator_execution_enabled = False

        decision = await approved(client, settings)
        response = await execute(client, settings, decision["decision_id"])
        assert response.status_code == 200
        assert response.json()["dispatch_enabled"] is False
        command = response.json()["commands"][0]
        assert command["status"] == "PENDING"

        # Boundary gate: tick() itself refuses to dispatch when disabled.
        assert await app.state.actuator_manager.tick() == 0
        assert adapter.calls == 0, "no outbound dispatch without the flag"
        with app.state.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, UUID(command["command_id"]))
            assert row.status == "PENDING"


async def test_boundary_gate_allows_mock_delivery_when_enabled(settings, tmp_path):
    """Requirement: enabling the flag in an isolated mock env permits delivery."""
    settings.actuator_execution_enabled = True  # isolated mock delivery only
    settings.actuator_transport = "mock_twin"
    settings.twin_base_url = "http://twin"
    settings.mock_twin_allowed_actions = "simulation_response"
    async with scenario(settings, tmp_path) as (app, client, _):
        twin = create_twin(settings)
        twin.state.transport = httpx.ASGITransport(app)
        adapter = MockTwinAdapter(settings, httpx.ASGITransport(twin))
        app.state.actuator_manager.adapter = adapter

        decision = await approved(client, settings)
        response = await execute(client, settings, decision["decision_id"])
        assert response.status_code == 200
        assert response.json()["dispatch_enabled"] is True
        command = response.json()["commands"][0]
        assert command["status"] == "PENDING"

        assert await app.state.actuator_manager.tick() == 1
        with app.state.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, UUID(command["command_id"]))
            assert row.status == "EXECUTED"
        assert twin.state.actuators["fixture-actuator"]["status"] == "executed"


async def test_quarantine_and_resource_expiry_block_dispatch(settings, tmp_path):
    """Requirement 8: unsafe state changes prevent authorized dispatch."""
    async with scenario(settings, tmp_path, critical=False) as (app, client, _):
        from app.schemas.guardian import QuarantineNotification

        decision = await approved(client, settings)
        notice = QuarantineNotification(
            notification_id=uuid4(),
            correlation_id=uuid4(),
            issued_at=datetime.now(UTC),
            guardian_id=settings.guardian_identity,
            target_type="actuator",
            target_id="fixture-actuator",
            action="quarantine",
            revision=1,
            reason_code="synthetic-quarantine",
        )
        assert (
            await post(client, settings, "/quarantines", notice, "guardian")
        ).status_code == 202
        await app.state.processor.tick()
        with app.state.database.transaction() as session:
            decision_row = session.scalar(select(DecisionRecord))
            assert decision_row.status == "CANCELLED"
            assert decision_row.payload["approved_actions"] == []
        response = await execute(client, settings, decision["decision_id"])
        assert response.status_code == 403
        with app.state.database.transaction() as session:
            assert (
                session.scalar(select(func.count()).select_from(ActuatorCommandRecord))
                == 0
            )

    expiry_path = tmp_path / "expiry"
    expiry_path.mkdir(parents=True, exist_ok=True)
    # The settings fixture pins a single SQLite file in tmp_path, so without a
    # fresh database the first scenario's persisted actuator quarantine would
    # leak into this context. Point the settings at an isolated database before
    # the second app is constructed (never touching the first database file).
    settings.database_url = f"sqlite:///{expiry_path / 'events.db'}"
    async with scenario(settings, expiry_path, critical=False) as (app, client, _):
        resource = app.state.city_engine.decisions.policy.resources["fixture-budget"]
        resource.valid_until = datetime.now(UTC) + timedelta(seconds=5)
        decision = await approved(client, settings)
        await app.state.processor.tick(resource.valid_until + timedelta(seconds=1))
        with app.state.database.transaction() as session:
            assert session.scalar(select(DecisionRecord)).status == "CANCELLED"
        response = await execute(client, settings, decision["decision_id"])
        assert response.status_code == 403
        with app.state.database.transaction() as session:
            assert (
                session.scalar(select(func.count()).select_from(ActuatorCommandRecord))
                == 0
            )
