from unittest.mock import AsyncMock

import pytest

from app.streaming.nats_adapter import NatsAdapter


async def test_ack_only_after_durable_ingestion() -> None:
    message = AsyncMock()
    message.data = b"event"

    async def persist(data: bytes) -> None:
        assert data == b"event"
        message.ack.assert_not_awaited()

    await NatsAdapter(persist).handle(message)
    message.ack.assert_awaited_once()
    message.nak.assert_not_awaited()


async def test_failed_ingestion_is_not_acknowledged() -> None:
    message = AsyncMock()
    persist = AsyncMock(side_effect=RuntimeError("database unavailable"))
    with pytest.raises(RuntimeError):
        await NatsAdapter(persist).handle(message)
    message.ack.assert_not_awaited()
    message.nak.assert_awaited_once()
