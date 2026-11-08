import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import func, select

from app.database.models import AuditEvent, EventLifecycle, GuardianVerdictRecord, SensorEvent
from app.database.session import Database
from app.main import create_app
from app.schemas.guardian import GuardianVerdict, QuarantineNotification, TrustStatus
from app.security.event_hash import event_hash
from app.state.lifecycle import transition
from app.streaming.event_processor import EventProcessor
from tests.security.test_contracts import reading


def verdict(event, **changes) -> GuardianVerdict:
    return GuardianVerdict.model_validate(
        {
            "verdict_id": uuid4(),
            "event_id": event.event_id,
            "correlation_id": event.correlation_id,
            "event_hash": event_hash(event),
            "issued_at": datetime.now(UTC),
            "status": TrustStatus.TRUSTED,
            "reason_code": "test",
            "guardian_id": "mock-guardian",
            **changes,
        }
    )


@pytest.fixture
async def pipeline(settings):
    settings.worker_enabled = False
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://brain") as client,
    ):
        yield app, client, settings


async def post(client, settings, path, event, role):
    return await client.post(
        path,
        json=event.model_dump(mode="json"),
        headers={"X-API-Key": getattr(settings, f"{role}_api_key").get_secret_value()},
    )


async def status(client, settings, event):
    response = await client.get(
        f"/events/{event.event_id}",
        headers={
            "X-API-Key": settings.brain_api_key.get_secret_value(),
        },
    )
    assert response.status_code == 200
    return response.json()


@pytest.mark.parametrize(
    "value,expected",
    [
        (TrustStatus.TRUSTED, "TRUSTED"),
        (TrustStatus.REJECTED, "UNTRUSTED"),
        (TrustStatus.UNKNOWN, "UNCERTAIN"),
        (TrustStatus.REVOKED, "UNTRUSTED"),
    ],
)
async def test_verdict_states_and_history(pipeline, value, expected):
    app, client, settings = pipeline
    event = reading()
    assert (await post(client, settings, "/readings", event, "twin")).status_code == 202
    assert (await status(client, settings, event))["state"] == "RECEIVED"
    await app.state.processor.tick()
    assert (await status(client, settings, event))["state"] == "PENDING_VERDICT"
    assert not app.state.state_manager.snapshot()["sensors"]
    response = await post(client, settings, "/verdicts", verdict(event, status=value), "guardian")
    assert response.status_code == 202
    await app.state.processor.tick()
    result = await status(client, settings, event)
    assert result["state"] == expected
    assert result["eligible"] == (expected == "TRUSTED")
    assert result["processing"] == "acknowledged"
    history = await client.get(
        f"/events/{event.event_id}/history",
        headers={
            "X-API-Key": settings.brain_api_key.get_secret_value(),
        },
    )
    changes = [
        entry["detail"]["to"]
        for entry in history.json()["audit"]
        if entry["action"] == "state_transition"
    ]
    assert changes == ["VALIDATED", "PENDING_VERDICT", expected]
    assert len(history.json()["verdicts"]) == 1


async def test_out_of_order_and_superseded_verdicts(pipeline):
    app, client, settings = pipeline
    event = reading()
    old = verdict(event, status=TrustStatus.TRUSTED)
    newest = verdict(event, revision=2, status=TrustStatus.REJECTED)
    assert (await post(client, settings, "/verdicts", newest, "guardian")).status_code == 202
    assert (await post(client, settings, "/readings", event, "twin")).status_code == 202
    await app.state.processor.tick()
    assert (await status(client, settings, event))["state"] == "UNTRUSTED"
    assert (await post(client, settings, "/verdicts", old, "guardian")).status_code == 202
    await app.state.processor.tick()
    assert (await status(client, settings, event))["verdict_id"] == str(newest.verdict_id)
    assert (await post(client, settings, "/verdicts", old, "guardian")).status_code == 409


async def test_revocation_invalidates_immediately(pipeline):
    app, client, settings = pipeline
    event = reading()
    await post(client, settings, "/readings", event, "twin")
    await post(client, settings, "/verdicts", verdict(event), "guardian")
    await app.state.processor.tick()
    assert app.state.state_manager.snapshot()["sensors"]
    revoked = verdict(event, revision=1, status=TrustStatus.REVOKED)
    await post(client, settings, "/verdicts", revoked, "guardian")
    assert not app.state.state_manager.snapshot()["sensors"]
    assert not (await status(client, settings, event))["eligible"]
    await app.state.processor.tick()
    assert (await status(client, settings, event))["reason"] == "verdict_revoked"


async def test_missing_guardian_and_late_recovery(pipeline):
    app, client, settings = pipeline
    event = reading()
    await post(client, settings, "/readings", event, "twin")
    await app.state.processor.tick()
    await app.state.processor.tick(
        datetime.now(UTC)
        + timedelta(
            seconds=settings.verdict_timeout_seconds + 1,
        )
    )
    result = await status(client, settings, event)
    assert result["state"] == "EXPIRED"
    assert result["reason"] == "verdict_missing"
    assert not app.state.state_manager.snapshot()["sensors"]
    await post(client, settings, "/verdicts", verdict(event), "guardian")
    await app.state.processor.tick()
    assert (await status(client, settings, event))["eligible"]


async def test_verdict_expiration_no_fallback(pipeline):
    app, client, settings = pipeline
    event = reading()
    await post(client, settings, "/readings", event, "twin")
    await post(client, settings, "/verdicts", verdict(event), "guardian")
    expired = verdict(
        event,
        revision=1,
        issued_at=datetime.now(UTC) - timedelta(seconds=20),
        expires_at=datetime.now(UTC) - timedelta(seconds=10),
    )
    await post(client, settings, "/verdicts", expired, "guardian")
    await app.state.processor.tick()
    assert (await status(client, settings, event))["reason"] == "verdict_expired"


async def test_hash_mismatch_before_and_after_reading(pipeline):
    app, client, settings = pipeline
    event = reading()
    bad = verdict(event, event_hash="0" * 64)
    assert (await post(client, settings, "/verdicts", bad, "guardian")).status_code == 202
    await post(client, settings, "/readings", event, "twin")
    await app.state.processor.tick()
    assert (await status(client, settings, event))["state"] == "UNCERTAIN"
    bad = verdict(event, event_hash="1" * 64)
    assert (await post(client, settings, "/verdicts", bad, "guardian")).status_code == 409
    assert not app.state.state_manager.snapshot()["sensors"]


async def test_unauthorized_identity_and_roles(pipeline):
    _, client, settings = pipeline
    event = reading()
    assert (await post(client, settings, "/verdicts", verdict(event), "twin")).status_code == 403
    bad = verdict(event, guardian_id="impostor")
    assert (await post(client, settings, "/verdicts", bad, "guardian")).status_code == 403
    assert (await client.get(f"/events/{event.event_id}")).status_code == 401


@pytest.mark.parametrize("kind", ["sensor", "actuator"])
async def test_quarantine_ordering_release_and_persistence(pipeline, kind):
    app, client, settings = pipeline
    event = reading()
    await post(client, settings, "/readings", event, "twin")
    await post(client, settings, "/verdicts", verdict(event), "guardian")
    await app.state.processor.tick()
    notification = QuarantineNotification(
        notification_id=uuid4(),
        correlation_id=event.correlation_id,
        guardian_id=settings.guardian_identity,
        issued_at=datetime.now(UTC),
        target_type=kind,
        target_id=event.sensor_id,
        action="quarantine",
        revision=2,
        reason_code="test",
    )
    assert (await post(client, settings, "/quarantines", notification, "twin")).status_code == 403
    assert (
        await post(client, settings, "/quarantines", notification, "guardian")
    ).status_code == 202
    if kind == "sensor":
        assert not app.state.state_manager.snapshot()["sensors"]
        await app.state.processor.tick()
        assert (await status(client, settings, event))["reason"] == "sensor_quarantined"
    old_release = notification.model_copy(
        update={
            "notification_id": uuid4(),
            "action": "release",
            "revision": 1,
        }
    )
    await post(client, settings, "/quarantines", old_release, "guardian")
    headers = {"X-API-Key": settings.brain_api_key.get_secret_value()}
    path = f"/quarantines/{kind}/{event.sensor_id}"
    assert (await client.get(path, headers=headers)).json()["quarantined"]
    release = old_release.model_copy(update={"notification_id": uuid4(), "revision": 3})
    await post(client, settings, "/quarantines", release, "guardian")
    assert not (await client.get(path, headers=headers)).json()["quarantined"]
    await app.state.processor.tick()
    assert (await status(client, settings, event))["eligible"]


async def test_concurrent_workers_and_duplicate_ingress(pipeline):
    app, client, settings = pipeline
    event = reading()
    results = await asyncio.gather(
        *[post(client, settings, "/readings", event, "twin") for _ in range(5)]
    )
    assert sorted(response.status_code for response in results) == [202, 409, 409, 409, 409]
    await post(client, settings, "/verdicts", verdict(event), "guardian")
    other_db = Database(settings)
    other = EventProcessor(other_db, settings)
    try:
        await asyncio.gather(app.state.processor.tick(), other.tick(), app.state.processor.tick())
    finally:
        other_db.close()
    assert (await status(client, settings, event))["eligible"]
    with app.state.database.transaction() as session:
        count = session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(
                AuditEvent.action == "event_acknowledged",
            )
        )
        assert count == 1


async def test_restart_recovers_buffer_and_history(settings):
    settings.worker_enabled = False
    event = reading()
    for attempt in range(2):
        app = create_app(settings)
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://brain") as c,
        ):
            if attempt == 0:
                await post(c, settings, "/readings", event, "twin")
                await post(c, settings, "/verdicts", verdict(event), "guardian")
            else:
                await app.state.processor.tick()
                assert (await status(c, settings, event))["eligible"]
                with app.state.database.transaction() as session:
                    assert (
                        session.scalar(select(func.count()).select_from(GuardianVerdictRecord)) == 1
                    )


async def test_bounded_retry_rollback_and_new_evidence_recovery(pipeline, monkeypatch):
    app, client, settings = pipeline
    event = reading()
    await post(client, settings, "/readings", event, "twin")
    engine = app.state.processor.trust
    original = engine.evaluate

    def fail(*args):
        raise RuntimeError("injected failure")

    monkeypatch.setattr(engine, "evaluate", fail)
    now = datetime.now(UTC)
    for attempt in range(settings.worker_max_attempts):
        await app.state.processor.tick(now + timedelta(seconds=10 * attempt))
    result = await status(client, settings, event)
    assert result["processing"] == "failed"
    assert result["attempts"] == settings.worker_max_attempts
    assert not result["eligible"]
    with app.state.database.transaction() as session:
        assert session.get(EventLifecycle, event.event_id).state == "RECEIVED"
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(
                    AuditEvent.action == "state_transition",
                )
            )
            == 0
        )
    monkeypatch.setattr(engine, "evaluate", original)
    await post(client, settings, "/verdicts", verdict(event), "guardian")
    await app.state.processor.tick()
    assert (await status(client, settings, event))["eligible"]


async def test_newest_sensor_evidence_prevents_time_regression(pipeline):
    app, client, settings = pipeline
    newer = reading()
    older = newer.model_copy(
        update={
            "event_id": uuid4(),
            "occurred_at": newer.occurred_at - timedelta(seconds=5),
        }
    )
    for event in (newer, older):
        await post(client, settings, "/readings", event, "twin")
        await post(client, settings, "/verdicts", verdict(event), "guardian")
        await app.state.processor.tick()
    snapshot = app.state.state_manager.snapshot()
    assert snapshot["sensors"][newer.sensor_id]["event_id"] == str(newer.event_id)
    await post(
        client,
        settings,
        "/verdicts",
        verdict(newer, status=TrustStatus.REVOKED, revision=1),
        "guardian",
    )
    assert not app.state.state_manager.snapshot()["sensors"]


async def test_event_expiration_and_transition_guard(pipeline):
    app, client, settings = pipeline
    event = reading()
    await post(client, settings, "/readings", event, "twin")
    with app.state.database.transaction() as session:
        row = session.get(EventLifecycle, event.event_id)
        with pytest.raises(ValueError):
            transition(session, row, event.correlation_id, "TRUSTED", "invalid", datetime.now(UTC))
    await post(client, settings, "/verdicts", verdict(event), "guardian")
    await app.state.processor.tick()
    await app.state.processor.tick(
        datetime.now(UTC)
        + timedelta(
            seconds=settings.event_freshness_seconds + 1,
        )
    )
    assert (await status(client, settings, event))["reason"] == "event_expired"
    assert not app.state.state_manager.snapshot()["sensors"]


async def test_legacy_sensor_event_recovered(pipeline):
    app, client, settings = pipeline
    event = reading()
    with app.state.database.transaction() as session:
        session.add(
            SensorEvent(
                id=event.event_id,
                correlation_id=event.correlation_id,
                occurred_at=event.occurred_at,
                sensor_id=event.sensor_id,
                payload={"event": event.model_dump(mode="json"), "sha256": event_hash(event)},
            )
        )
    await app.state.processor.tick()
    assert (await status(client, settings, event))["state"] == "PENDING_VERDICT"
