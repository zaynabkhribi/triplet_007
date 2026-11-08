import httpx
import pytest

from app.core.config import Settings
from app.main import create_app


@pytest.mark.parametrize(
    "path,role",
    [
        ("/readings", "guardian"),
        ("/verdicts", "twin"),
        ("/feedback", "guardian"),
    ],
)
async def test_wrong_roles(settings, path, role) -> None:
    app = create_app(settings)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app),
        base_url="http://brain",
    ) as client:
        response = await client.post(
            path,
            json={},
            headers={
                "X-API-Key": getattr(settings, f"{role}_api_key").get_secret_value(),
                "X-Service-Role": "twin",
            },
        )
        assert response.status_code == 403


async def test_unconfigured_service_rejects_requests() -> None:
    app = create_app(Settings(_env_file=None))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app),
        base_url="http://brain",
    ) as client:
        response = await client.post("/readings", json={}, headers={"X-API-Key": "anything"})
        assert response.status_code == 401


async def test_chunked_body_limit(settings) -> None:
    app = create_app(settings)

    async def chunks():
        for _ in range(70):
            yield b"x" * 1024

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app),
        base_url="http://brain",
    ) as client:
        response = await client.post(
            "/readings",
            content=chunks(),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413
