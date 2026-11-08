import httpx

from app.intelligence.artifacts import ArtifactRegistry
from app.main import create_app


def test_missing_artifacts_fail_closed() -> None:
    registry = ArtifactRegistry(None, None)
    assert len(registry.status()) == 6
    assert all(not item["loaded"] and not item["inference_ready"] for item in registry.status())


async def test_forecast_blocking_persistence_and_restart(settings) -> None:
    settings.worker_enabled = False
    for attempt in range(2):
        app = create_app(settings)
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app), base_url="http://brain"
            ) as client,
        ):
            headers = {"X-API-Key": settings.brain_api_key.get_secret_value()}
            assert (await client.get("/v1/models")).status_code == 401
            models = await client.get("/v1/models", headers=headers)
            assert len(models.json()) == 6
            if attempt == 0:
                for family, horizons in (("traffic", [15, 30, 60]), ("water", [60, 180, 360])):
                    response = await client.post(
                        f"/v1/forecasts/{family}",
                        headers=headers,
                        json={"sensor_id": "unmapped", "horizons_minutes": horizons},
                    )
                    assert response.status_code == 503
                    assert response.json()["detail"]["predictions"] == []
                assert (
                    await client.post(
                        "/v1/forecasts/traffic",
                        headers=headers,
                        json={"sensor_id": "unmapped", "horizons_minutes": [1]},
                    )
                ).status_code == 422
            history = await client.get("/v1/forecasts/history", headers=headers)
            assert len(history.json()) == 2
            assert all(record["status"] == "blocked" for record in history.json())
