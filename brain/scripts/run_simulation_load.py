import argparse
import asyncio
import json
import secrets
import tempfile
import tracemalloc
from pathlib import Path

import httpx

from app.core.config import Settings
from app.main import create_app


async def measure(sensor_count: int, ticks: int) -> dict:
    with tempfile.TemporaryDirectory(prefix="aegiscity-load-") as directory:
        database = Path(directory) / "load.db"
        settings = Settings(
            _env_file=None,
            database_url=f"sqlite:///{database}",
            brain_api_key=secrets.token_urlsafe(48),
            twin_api_key=secrets.token_urlsafe(48),
            guardian_api_key=secrets.token_urlsafe(48),
            brain_base_url="http://brain",
            worker_enabled=False,
            simulation_interval_seconds=0.05,
            simulation_max_ticks=max(10, ticks + 1),
        )
        app = create_app(settings)
        tracemalloc.start()
        before = database.stat().st_size if database.exists() else 0
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://load"
            ) as client,
        ):
            login = await client.post(
                "/dashboard/session",
                headers={"X-API-Key": settings.brain_api_key.get_secret_value()},
                json={},
            )
            headers = {"X-Dashboard-CSRF": login.json()["csrf"]}
            started = await client.post(
                "/dashboard/api/scenarios/normal_city/start",
                headers=headers,
                json={"sensor_count": sensor_count, "seed": 2026},
            )
            started.raise_for_status()
            execution_id = started.json()["execution_id"]
            metrics = []
            for _ in range(1200):
                run = (
                    await client.get(
                        f"/dashboard/api/scenarios/executions/{execution_id}"
                    )
                ).json()
                metrics = [
                    item["detail"]
                    for item in run["timeline"]
                    if item["stage"] == "PERFORMANCE"
                ]
                if len(metrics) >= ticks or run["status"] == "FAILED":
                    break
                await asyncio.sleep(0.05)
            await client.post(
                f"/dashboard/api/scenarios/executions/{execution_id}/control",
                headers=headers,
                json={"action": "stop"},
            )
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        if len(metrics) < ticks:
            raise RuntimeError(f"load run failed: {run}")
        return {
            "sensor_count": sensor_count,
            "ticks": len(metrics),
            "events": sum(item["sensor_count"] for item in metrics),
            "throughput_events_per_second": round(
                sum(item["events_per_second"] for item in metrics) / len(metrics), 2
            ),
            "processing_capacity_events_per_second": round(
                sum(item["processing_capacity_events_per_second"] for item in metrics)
                / len(metrics),
                2,
            ),
            "latency_p50_ms": round(
                sum(item["latency_p50_ms"] for item in metrics) / len(metrics), 2
            ),
            "latency_p95_ms": max(item["latency_p95_ms"] for item in metrics),
            "guardian_accepted": sum(item["guardian_accepted"] for item in metrics),
            "guardian_rejected": sum(item["guardian_rejected"] for item in metrics),
            "backlog_max": max(item["backlog"] for item in metrics),
            "errors": sum(item["errors"] for item in metrics),
            "memory_peak_bytes": peak,
            "database_growth_bytes": database.stat().st_size - before,
        }


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ticks", type=int, default=3)
    args = parser.parse_args()
    results = [await measure(size, args.ticks) for size in (10, 50, 100)]
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
