"""Regression tests for the audit() event-ID lookup on SQLite.

Verifies that the JSON-extract expression used for the audit sequence COUNT
matches the ix_audit_events_event_id_json expression index (no full table
scan), and that sequence numbering, payload format, trust, and lifecycle
outcomes are unchanged.
"""

import secrets
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, literal_column, select

from app.core.config import Settings
from app.database.models import AuditEvent
from app.database.session import Database
from app.state.lifecycle import audit


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'audit.db'}",
        brain_api_key=secrets.token_urlsafe(48),
        twin_api_key=secrets.token_urlsafe(48),
        guardian_api_key=secrets.token_urlsafe(48),
        brain_base_url="http://brain",
    )


@pytest.fixture
def database(settings: Settings) -> Database:
    database = Database(settings)
    database.initialize()
    return database


def _event_id_count_query(event_id):
    """Mirror of the corrected SQLite branch inside audit()."""
    return (
        select(func.count())
        .select_from(AuditEvent)
        .where(
            func.json_extract(
                AuditEvent.payload,
                literal_column("'$.\"event_id\"'"),
            )
            == str(event_id)
        )
    )


def test_sqlite_query_plan_uses_expression_index(database: Database) -> None:
    """The audit sequence COUNT must SEARCH via the expression index."""
    event_id = uuid4()
    with database.transaction() as session:
        audit(session, event_id, uuid4(), "test_action", {}, datetime.now(UTC))
        session.flush()

    compiled = _event_id_count_query(event_id).compile(
        dialect=database.engine.dialect
    )
    params = tuple(
        compiled.params[key]
        for key in compiled.positiontup
    )
    with database.engine.connect() as connection:
        plan = connection.exec_driver_sql(
            f"EXPLAIN QUERY PLAN {compiled.string}",
            params,
        ).all()
    plan_text = "\n".join(str(row[-1]) for row in plan)
    assert "ix_audit_events_event_id_json" in plan_text, plan_text
    assert "SCAN audit_events" not in plan_text, plan_text


def test_repeated_audit_same_event_increments_sequence(database: Database) -> None:
    now = datetime.now(UTC)
    event_id = uuid4()
    with database.transaction() as session:
        for expected in (1, 2, 3):
            audit(session, event_id, uuid4(), "state_transition", {"n": expected}, now)
            session.flush()
            count = session.scalar(_event_id_count_query(event_id))
            assert count == expected


def test_independent_sequences_per_event(database: Database) -> None:
    now = datetime.now(UTC)
    first, second = uuid4(), uuid4()
    with database.transaction() as session:
        audit(session, first, uuid4(), "a", {}, now)
        audit(session, second, uuid4(), "a", {}, now)
        session.flush()
        assert session.scalar(_event_id_count_query(first)) == 1
        assert session.scalar(_event_id_count_query(second)) == 1
        audit(session, second, uuid4(), "b", {}, now)
        session.flush()
        assert session.scalar(_event_id_count_query(first)) == 1
        assert session.scalar(_event_id_count_query(second)) == 2


def test_audit_payload_format_unchanged(database: Database) -> None:
    now = datetime.now(UTC)
    event_id = uuid4()
    correlation_id = uuid4()
    with database.transaction() as session:
        audit(
            session,
            event_id,
            correlation_id,
            "event_received",
            {"record_type": "sensor_events"},
            now,
            actor="twin",
        )
        row = session.scalars(select(AuditEvent)).one()
        session.expunge_all()
    payload = row.payload
    assert payload["event_id"] == str(event_id)
    assert payload["sequence"] == 1
    assert payload["record_type"] == "sensor_events"
    assert row.actor == "twin"
    assert row.action == "event_received"
    assert row.correlation_id == correlation_id
    # SQLite stores naive UTC wall-clock datetimes; compare the same wall clock.
    assert row.occurred_at == now.replace(tzinfo=None)


def test_full_lifecycle_outcomes_unchanged(settings: Settings) -> None:
    """End-to-end: worker still drives an event to TRUSTED with audit rows intact."""
    import asyncio

    import httpx

    from app.main import create_app
    from tests.integration.test_trust_pipeline import post, status, verdict
    from tests.security.test_contracts import reading

    settings.worker_poll_seconds = 0.01
    app = create_app(settings)
    event = reading()

    async def run() -> None:
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app), base_url="http://brain"
            ) as client,
        ):
            await post(client, settings, "/verdicts", verdict(event), "guardian")
            await post(client, settings, "/readings", event, "twin")
            for _ in range(500):
                if (await status(client, settings, event))["eligible"]:
                    break
                await asyncio.sleep(0.01)
            else:
                raise AssertionError("background worker did not process the event")
            result = await status(client, settings, event)
            assert result["state"] == "TRUSTED"
            assert result["trust_state"] == "trusted"

    asyncio.run(run())

    with app.state.database.transaction() as session:
        counts = session.scalar(
            select(func.count()).select_from(AuditEvent).where(
                AuditEvent.correlation_id == event.correlation_id
            )
        )
        assert counts >= 1
        actions = {
            row.action
            for row in session.scalars(
                select(AuditEvent).where(
                    AuditEvent.correlation_id == event.correlation_id
                )
            )
        }
        assert "event_received" in actions
        assert "event_acknowledged" in actions
