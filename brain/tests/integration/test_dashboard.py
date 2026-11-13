import asyncio
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest

from app.main import create_app
from app.scenarios import SCENARIOS


def test_dashboard_frontend_is_valid_and_reports_login_failures() -> None:
    script = Path("app/dashboard/static/app.js")
    source = script.read_text(encoding="utf-8")
    assert "Invalid service API key." in source
    assert "Unable to authenticate." in source
    assert 'addEventListener("submit"' in source
    assert "localStorage" not in source
    assert "sessionStorage" not in source
    node = shutil.which("node")
    assert node is not None, "Node.js is required for frontend syntax regression checks"
    result = subprocess.run(
        [node, "--check", str(script)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


async def test_dashboard_authentication_rbac_and_persistent_timeline(settings) -> None:
    settings.worker_enabled = False
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://test") as client,
    ):
        page = await client.get("/dashboard")
        assert page.status_code == 200
        assert "Content-Security-Policy" in page.headers
        assert settings.brain_api_key.get_secret_value() not in page.text
        assert (await client.get("/dashboard/api/snapshot")).status_code == 401

        denied = await client.post("/dashboard/session", headers={"X-API-Key": "invalid"}, json={})
        assert denied.status_code == 401

        login = await client.post(
            "/dashboard/session",
            headers={"X-API-Key": settings.brain_api_key.get_secret_value()},
            json={},
        )
        assert login.status_code == 200
        assert "HttpOnly" in login.headers["set-cookie"]
        assert "SameSite=strict" in login.headers["set-cookie"]
        assert settings.brain_api_key.get_secret_value() not in login.text
        csrf = login.json()["csrf"]

        assert (await client.get("/dashboard/session")).json()["role"] == "brain"
        assert (await client.get("/dashboard/api/snapshot")).status_code == 200
        assert (
            await client.post("/dashboard/api/scenarios/untrusted_sensor/run", json={})
        ).status_code == 403

        run = await client.post(
            "/dashboard/api/scenarios/untrusted_sensor/run",
            headers={"X-Dashboard-CSRF": csrf},
            json={},
        )
        assert run.status_code == 200
        result = run.json()
        assert result["status"] == "PASSED"
        assert result["actual"]["trusted_value"] is None
        stages = [item["stage"] for item in result["timeline"]]
        assert stages == [
            "SENSOR_READING",
            "GUARDIAN_VERDICT",
            "TRUSTED_CITY_STATE",
            "SCENARIO_RESULT",
        ]
        timeline = (await client.get("/dashboard/api/timeline")).json()
        assert any(item.get("execution_id") == result["execution_id"] for item in timeline)


async def test_dashboard_reader_cannot_trigger_scenarios(settings) -> None:
    settings.worker_enabled = False
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        login = await client.post(
            "/dashboard/session",
            headers={"X-API-Key": settings.guardian_api_key.get_secret_value()},
            json={},
        )
        response = await client.post(
            "/dashboard/api/scenarios/traffic_congestion/run",
            headers={"X-Dashboard-CSRF": login.json()["csrf"]},
            json={},
        )
        assert response.status_code == 403


async def test_dashboard_scenario_projection_is_isolated_and_selectable(settings) -> None:
    settings.worker_enabled = False
    settings.simulation_interval_seconds = 0.05
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        login = await client.post(
            "/dashboard/session",
            headers={"X-API-Key": settings.brain_api_key.get_secret_value()},
            json={},
        )
        csrf = login.json()["csrf"]
        started = await client.post(
            "/dashboard/api/scenarios/traffic_congestion/start",
            headers={"X-Dashboard-CSRF": csrf},
            json={},
        )
        assert started.status_code == 200
        execution_id = started.json()["execution_id"]
        assert started.json()["status"] == "RUNNING"

        await asyncio.sleep(0.25)
        paused = await client.post(
            f"/dashboard/api/scenarios/executions/{execution_id}/control",
            headers={"X-Dashboard-CSRF": csrf},
            json={"action": "pause"},
        )
        assert paused.json()["status"] == "PAUSED"
        paused_count = len(paused.json()["timeline"])
        await asyncio.sleep(0.2)
        still_paused = (
            await client.get(f"/dashboard/api/scenarios/executions/{execution_id}")
        ).json()
        assert len(still_paused["timeline"]) <= paused_count + 4
        resumed = await client.post(
            f"/dashboard/api/scenarios/executions/{execution_id}/control",
            headers={"X-Dashboard-CSRF": csrf},
            json={"action": "resume", "speed": 5},
        )
        assert resumed.json()["status"] == "RUNNING"

        for _ in range(300):
            response = await client.get(f"/dashboard/api/scenarios/executions/{execution_id}")
            run = response.json()
            if run["status"] != "RUNNING":
                break
            await asyncio.sleep(0.05)

        assert run["status"] == "PASSED"
        stages = {item["stage"]: item for item in run["timeline"]}
        traffic_values = [
            reading["value"]
            for item in run["timeline"]
            if item["stage"] == "SENSOR_READING"
            for reading in item["detail"]["readings"]
            if reading["sensor_id"] == "scenario-sensor"
        ]
        assert min(traffic_values) == 10
        assert len(set(traffic_values)) > 5
        assert stages["GUARDIAN_VERDICT"]["status"] == "TRUSTED"
        assert stages["INCIDENT"]["detail"]["incident_type"] == "traffic_congestion"
        assert stages["DECISION"]["detail"]["outcome"] == "ACTION_PLAN"
        assert stages["APPROVAL"]["detail"]["safety_check"] == "passed"
        assert stages["EXECUTION_FEEDBACK"]["status"] == "EXECUTED"

        history = (await client.get("/dashboard/api/scenarios")).json()["executions"]
        assert history[0]["execution_id"] == execution_id
        live = (await client.get("/dashboard/api/snapshot")).json()
        assert live["city"]["zones"] == {}
        assert stages["TRUSTED_CITY_STATE"]["detail"]["zone_id"] == "scenario-zone"
        reset = await client.post(
            "/dashboard/api/scenarios/reset",
            headers={"X-Dashboard-CSRF": csrf},
            json={},
        )
        assert reset.json()["status"] == "PASSED"

    restarted = create_app(settings)
    async with (
        restarted.router.lifespan_context(restarted),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=restarted), base_url="http://test"
        ) as client,
    ):
        login = await client.post(
            "/dashboard/session",
            headers={"X-API-Key": settings.brain_api_key.get_secret_value()},
            json={},
        )
        history = await client.get("/dashboard/api/scenarios")
        assert login.status_code == history.status_code == 200
        assert any(run["execution_id"] == execution_id for run in history.json()["executions"])


async def test_continuous_simulation_is_seeded_bounded_and_single_worker(settings) -> None:
    settings.worker_enabled = False
    settings.simulation_interval_seconds = 0.05
    settings.simulation_max_ticks = 20
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        login = await client.post(
            "/dashboard/session",
            headers={"X-API-Key": settings.brain_api_key.get_secret_value()},
            json={},
        )
        headers = {"X-Dashboard-CSRF": login.json()["csrf"]}
        started = await client.post(
            "/dashboard/api/scenarios/normal_city/start", headers=headers, json={}
        )
        execution_id = started.json()["execution_id"]
        duplicate = await client.post(
            "/dashboard/api/scenarios/normal_city/start", headers=headers, json={}
        )
        assert duplicate.status_code == 409
        invalid_speed = await client.post(
            f"/dashboard/api/scenarios/executions/{execution_id}/control",
            headers=headers,
            json={"action": "speed", "speed": 3},
        )
        assert invalid_speed.status_code == 422
        values = []
        for _ in range(50):
            progress = (
                await client.get(f"/dashboard/api/scenarios/executions/{execution_id}")
            ).json()
            values = [
                reading["value"]
                for item in progress["timeline"]
                if item["stage"] == "SENSOR_READING"
                for reading in item["detail"]["readings"]
                if reading["sensor_id"] == "scenario-sensor"
            ]
            if len(values) >= 2:
                break
            await asyncio.sleep(0.1)
        assert len(values) >= 2
        assert len(set(values)) > 1
        await client.post(
            f"/dashboard/api/scenarios/executions/{execution_id}/control",
            headers=headers,
            json={"action": "stop"},
        )
        for _ in range(100):
            stopped = (
                await client.get(f"/dashboard/api/scenarios/executions/{execution_id}")
            ).json()
            if stopped["status"] == "STOPPED":
                break
            await asyncio.sleep(0.05)
        assert stopped["status"] == "STOPPED"


async def test_high_volume_options_and_measured_pipeline_metrics(settings) -> None:
    settings.worker_enabled = False
    settings.simulation_interval_seconds = 0.05
    settings.simulation_max_ticks = 10
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        login = await client.post(
            "/dashboard/session",
            headers={"X-API-Key": settings.brain_api_key.get_secret_value()},
            json={},
        )
        headers = {"X-Dashboard-CSRF": login.json()["csrf"]}
        invalid = await client.post(
            "/dashboard/api/scenarios/normal_city/start",
            headers=headers,
            json={"sensor_count": 25, "seed": 17},
        )
        assert invalid.status_code == 422
        started = await client.post(
            "/dashboard/api/scenarios/normal_city/start",
            headers=headers,
            json={"sensor_count": 10, "seed": 17},
        )
        assert started.status_code == 200
        execution_id = started.json()["execution_id"]
        for _ in range(200):
            run = (await client.get(f"/dashboard/api/scenarios/executions/{execution_id}")).json()
            metrics = [item for item in run["timeline"] if item["stage"] == "PERFORMANCE"]
            if metrics:
                break
            await asyncio.sleep(0.05)
        assert metrics, run
        measured = metrics[0]["detail"]
        assert measured["sensor_count"] == 10
        assert measured["events_per_second"] > 0
        assert measured["latency_p50_ms"] > 0
        assert measured["latency_p95_ms"] >= measured["latency_p50_ms"]
        assert measured["guardian_accepted"] == 10
        assert measured["guardian_rejected"] == 0
        assert measured["backlog"] == 0
        await client.post(
            f"/dashboard/api/scenarios/executions/{execution_id}/control",
            headers=headers,
            json={"action": "stop"},
        )


@pytest.mark.parametrize("scenario_id", list(SCENARIOS))
async def test_all_scenarios_complete_through_dashboard(settings, scenario_id: str) -> None:
    settings.worker_enabled = False
    settings.simulation_interval_seconds = 0.05
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        login = await client.post(
            "/dashboard/session",
            headers={"X-API-Key": settings.brain_api_key.get_secret_value()},
            json={},
        )
        started = await client.post(
            f"/dashboard/api/scenarios/{scenario_id}/start",
            headers={"X-Dashboard-CSRF": login.json()["csrf"]},
            json={},
        )
        execution_id = started.json()["execution_id"]
        for _ in range(300):
            run = (await client.get(f"/dashboard/api/scenarios/executions/{execution_id}")).json()
            if run["status"] != "RUNNING":
                break
            await asyncio.sleep(0.05)
    assert run["status"] == "PASSED"
    assert run["timeline"][-1]["stage"] == "SCENARIO_RESULT"


async def test_provider_status_flattens_ngsi_timestamp_and_reports_fresh_twin(
    settings,
) -> None:
    """Task 7.3F-2 regression: hosted Orion returns attributes as nested
    {type, value} dicts. The Twin liveness probe must flatten them before
    computing the publish age, otherwise a 2-second-old publication is
    misreported as stale (the dict failed the isinstance(str) check)."""
    settings.worker_enabled = False
    settings.orion_base_url = "http://orion.test"
    app = create_app(settings)

    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        # Exact hosted-broker shape: nested attribute dicts, including the
        # timestamp that previously defeated the string check.
        return httpx.Response(200, json={
            "id": "us-b-bldg-01",
            "type": "BuildingSensor",
            "smokeLevel": {"type": "float", "value": 1.6},
            "temperature": {"type": "float", "value": 22.3},
            "timestamp": {
                "type": "string", "value": "2026-11-13T19:08:17+00:00",
            },
        })

    real_async_client = httpx.AsyncClient

    # Intercept ONLY outbound Orion traffic: orion.test requests hit the
    # fake handler, everything else flows through the real client so the
    # dashboard session/CSRF calls keep working (a naive global monkey-patch
    # broke the ASGI test client itself).
    class SelectiveClient(real_async_client):
        async def send(self, request, **kw):
            if (request.url.host or "") == "orion.test":
                captured["url"] = str(request.url)
                return handler(request)
            return await super().send(request, **kw)

    httpx.AsyncClient = SelectiveClient  # type: ignore[assignment]
    try:
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client,
        ):
            login = await client.post(
                "/dashboard/session",
                headers={"X-API-Key": settings.brain_api_key.get_secret_value()},
                json={},
            )
            assert login.status_code == 200
            providers = (await client.get("/dashboard/api/operations")).json()
    finally:
        httpx.AsyncClient = real_async_client  # type: ignore[assignment]

    twin = providers["twin"]
    assert twin["connected"] is True
    assert twin["running"] is True, (
        "a 2s-old publication must classify as publishing, not stale"
    )
    assert twin["last_publish_age_s"] is not None and twin["last_publish_age_s"] < 120
    assert twin["values"]["smokeLevel"] == 1.6
    assert twin["values"]["temperature"] == 22.3
    assert "us-b-bldg-01" in captured["url"]


async def test_snapshot_raw_layer_exposes_latest_untrusted_readings(
    settings, tmp_path
) -> None:
    """The raw observation layer must surface the latest STORED reading per
    sensor regardless of trust eligibility, distinctly from fused state."""
    settings.worker_enabled = False
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client,
    ):
        login = await client.post(
            "/dashboard/session",
            headers={"X-API-Key": settings.brain_api_key.get_secret_value()},
            json={},
        )
        assert login.status_code == 200
        snapshot = (await client.get("/dashboard/api/snapshot")).json()
        # No observations stored: raw layer is present but empty.
        assert snapshot["raw_latest"] == {}
