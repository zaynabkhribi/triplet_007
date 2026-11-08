import httpx

from app.core.config import Settings
from app.main import create_app


async def test_health_endpoints() -> None:
    app = create_app(Settings(database_url="sqlite://", _env_file=None))
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://test") as client,
    ):
        assert (await client.get("/health/live")).json() == {"status": "ok"}
        assert (await client.get("/health/ready")).json() == {"status": "ready"}
        assert (await client.get("/docs")).status_code == 200
        assert (await client.get("/openapi.json")).status_code == 200
