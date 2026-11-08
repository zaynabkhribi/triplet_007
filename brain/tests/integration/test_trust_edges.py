import asyncio
from datetime import UTC, datetime, timedelta

import httpx

from app.database.models import EventLifecycle
from app.main import create_app
from tests.integration.test_trust_pipeline import post, status, verdict
from tests.security.test_contracts import reading


async def test_background_worker_processes_without_manual_tick(settings):
    settings.worker_poll_seconds = 0.01
    app = create_app(settings)
    event = reading()
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://brain") as client,
    ):
        await post(client, settings, "/verdicts", verdict(event), "guardian")
        await post(client, settings, "/readings", event, "twin")
        async with asyncio.timeout(5):
            for _ in range(500):
                if (await status(client, settings, event))["eligible"]:
                    break
                await asyncio.sleep(0.01)
            else:
                raise AssertionError("background worker did not process the event")
        assert app.state.state_manager.snapshot()["sensors"]


async def test_same_rank_verdicts_fail_closed(settings):
    settings.worker_enabled = False
    app = create_app(settings)
    event = reading()
    issued_at = datetime.now(UTC)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://brain") as client,
    ):
        await post(client, settings, "/readings", event, "twin")
        for _ in range(2):
            await post(
                client, settings, "/verdicts", verdict(event, issued_at=issued_at), "guardian"
            )
        await app.state.processor.tick()
        result = await status(client, settings, event)
        assert result["state"] == "UNCERTAIN"
        assert result["reason"] == "conflicting_verdicts"
        assert not result["eligible"]


async def test_read_time_expiration_with_worker_stopped(settings):
    settings.worker_enabled = False
    app = create_app(settings)
    event = reading()
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://brain") as client,
    ):
        await post(client, settings, "/readings", event, "twin")
        await post(client, settings, "/verdicts", verdict(event), "guardian")
        await app.state.processor.tick()
        with app.state.database.transaction() as session:
            row = session.get(EventLifecycle, event.event_id)
            row.eligible_until = datetime.now(UTC) - timedelta(seconds=1)
        result = await status(client, settings, event)
        assert result["state"] == "TRUSTED"
        assert result["trust_state"] == "expired"
        assert not result["eligible"]
        assert not app.state.state_manager.snapshot()["sensors"]
