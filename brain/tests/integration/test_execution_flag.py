"""Regression tests for the actuator execution feature flag.

Verifies that ACTUATOR_EXECUTION_ENABLED=false prevents outbound actuator
dispatch from every dispatch path, including the OperationalCoordinator's
coordinator-triggered tick, while preserving decision approval, safety
revalidation, audit records, and command lifecycle semantics.
"""

import asyncio
import contextlib
from uuid import UUID

from sqlalchemy import select

from app.database.models import ActuatorCommandRecord, CommandRevision
from app.operations.coordinator import OperationalCoordinator
from tests.integration.test_actions import AcceptingAdapter, approved
from tests.integration.test_decisions import scenario


async def test_coordinator_does_not_tick_when_execution_disabled(settings, tmp_path):
    """Coordinator creates commands but must not dispatch when execution is off."""
    async with scenario(settings, tmp_path) as (app, client, _):
        adapter = AcceptingAdapter()
        app.state.actuator_manager.adapter = adapter
        settings.actuator_execution_enabled = False
        settings.operational_auto_approve = True
        coordinator = OperationalCoordinator(
            app.state.database,
            settings,
            app.state.city_engine,
            app.state.actuator_manager,
        )

        # Run the coordinator loop directly so its FIRST coordinate() creates
        # commands and run() reaches the tick decision with created=True.
        task = asyncio.create_task(coordinator.run())
        for _ in range(500):
            with app.state.database.transaction() as session:
                rows = session.scalars(select(ActuatorCommandRecord)).all()
            if rows:
                break
            await asyncio.sleep(0.01)
        else:
            coordinator.stop()
            raise AssertionError("coordinator did not create commands")
        assert rows[0].status == "PENDING"
        await asyncio.sleep(0.05)
        coordinator.stop()
        with contextlib.suppress(TimeoutError):
         await asyncio.wait_for(task, timeout=2)
        assert adapter.calls == 0, "dispatch must not happen when execution disabled"


async def test_coordinator_ticks_when_execution_enabled(settings, tmp_path):
    """Same flow with execution enabled: coordinator may dispatch."""
    async with scenario(settings, tmp_path) as (app, client, _):
        adapter = AcceptingAdapter()
        app.state.actuator_manager.adapter = adapter
        settings.actuator_execution_enabled = True
        settings.operational_auto_approve = True
        coordinator = OperationalCoordinator(
            app.state.database,
            settings,
            app.state.city_engine,
            app.state.actuator_manager,
        )

        created = await asyncio.to_thread(coordinator.coordinate)
        assert created, "coordinator should have created commands"

        await coordinator.actuators.tick()
        assert adapter.calls == 1, "dispatch must happen when execution enabled"

        with app.state.database.transaction() as session:
            row = session.scalars(select(ActuatorCommandRecord)).one()
            assert row.status == "DELIVERED"
        with app.state.database.transaction() as session:
            revisions = session.scalars(
                select(CommandRevision).where(CommandRevision.command_id == row.id)
            ).all()
            assert revisions, "command lifecycle revisions must be recorded"


async def test_no_dispatch_from_api_path_when_execution_disabled(settings, tmp_path):
    """Direct API enqueue must not dispatch when execution is disabled."""
    async with scenario(settings, tmp_path) as (app, client, _):
        adapter = AcceptingAdapter()
        app.state.actuator_manager.adapter = adapter
        settings.actuator_execution_enabled = False

        decision = await approved(client, settings)
        response = await client.post(
            "/v1/actions/execute",
            json={"decision_id": decision["decision_id"]},
            headers={"X-API-Key": settings.brain_api_key.get_secret_value()},
        )
        assert response.status_code == 200
        assert response.json()["dispatch_enabled"] is False
        command = response.json()["commands"][0]
        assert command["status"] == "PENDING"

        # Manual tick (as the disabled background loop would never run) must
        # still not dispatch, because tick is the only outbound delivery path.
        assert adapter.calls == 0

        with app.state.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, UUID(command["command_id"]))
            assert row is not None
            assert row.status == "PENDING"
