import argparse
import asyncio
import json
from time import monotonic

import httpx

from app.core.config import Settings


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--speed", type=float, choices=[1, 2, 5], default=1)
    args = parser.parse_args()
    settings = Settings()
    async with httpx.AsyncClient(base_url=args.url, timeout=15) as client:
        login = await client.post(
            "/dashboard/session",
            headers={"X-API-Key": settings.brain_api_key.get_secret_value()},
            json={},
        )
        login.raise_for_status()
        headers = {"X-Dashboard-CSRF": login.json()["csrf"]}
        started_at = monotonic()
        started = await client.post(
            "/dashboard/api/scenarios/city_under_pressure/start",
            headers=headers,
            json={"sensor_count": 10, "seed": 2026},
        )
        started.raise_for_status()
        execution_id = started.json()["execution_id"]
        if args.speed != 1:
            speed = await client.post(
                f"/dashboard/api/scenarios/executions/{execution_id}/control",
                headers=headers,
                json={"action": "speed", "speed": args.speed},
            )
            speed.raise_for_status()
        paused_verified = False
        run = started.json()
        while monotonic() - started_at < args.timeout:
            run = (
                await client.get(
                    f"/dashboard/api/scenarios/executions/{execution_id}"
                )
            ).json()
            elapsed = monotonic() - started_at
            if not paused_verified and elapsed >= 20:
                paused = await client.post(
                    f"/dashboard/api/scenarios/executions/{execution_id}/control",
                    headers=headers,
                    json={"action": "pause"},
                )
                paused.raise_for_status()
                count = len(paused.json()["timeline"])
                await asyncio.sleep(2)
                held = (
                    await client.get(
                        f"/dashboard/api/scenarios/executions/{execution_id}"
                    )
                ).json()
                paused_verified = len(held["timeline"]) <= count + 4
                resumed = await client.post(
                    f"/dashboard/api/scenarios/executions/{execution_id}/control",
                    headers=headers,
                    json={"action": "resume"},
                )
                resumed.raise_for_status()
            if run["status"] not in {"RUNNING", "PAUSED"}:
                break
            await asyncio.sleep(1)
        performance = [
            item["detail"] for item in run["timeline"] if item["stage"] == "PERFORMANCE"
        ]
        stages = [item["stage"] for item in run["timeline"]]
        result = {
            "execution_id": execution_id,
            "status": run["status"],
            "wall_seconds": round(monotonic() - started_at, 2),
            "sensor_ticks": len(performance),
            "events": sum(item["sensor_count"] for item in performance),
            "guardian_accepted": sum(item["guardian_accepted"] for item in performance),
            "guardian_rejected": sum(item["guardian_rejected"] for item in performance),
            "incidents": sum(item == "INCIDENT" for item in stages),
            "decision": "DECISION" in stages,
            "approval": "APPROVAL" in stages,
            "command": "ACTUATOR_COMMAND" in stages,
            "feedback": "EXECUTION_FEEDBACK" in stages,
            "pause_resume": paused_verified,
            "actual": run.get("actual"),
        }
        print(json.dumps(result, indent=2))
        if run["status"] != "PASSED":
            raise RuntimeError("live demonstration did not pass")


if __name__ == "__main__":
    asyncio.run(main())
