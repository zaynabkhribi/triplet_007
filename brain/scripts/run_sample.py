import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx

from app.core.config import Settings
from app.integration.http import client_context
from app.schemas.actuator import ActuatorCommand
from app.schemas.sensor import SensorReading


async def main() -> None:
    settings = Settings()
    if not all((settings.brain_base_url, settings.twin_base_url, settings.guardian_base_url)):
        raise SystemExit("Configure all three service URLs")
    if settings.brain_api_key is None:
        raise SystemExit("Configure BRAIN_API_KEY")
    headers = {"X-API-Key": settings.brain_api_key.get_secret_value()}
    now = datetime.now(UTC)
    reading = SensorReading(
        event_id=uuid4(),
        correlation_id=uuid4(),
        occurred_at=now,
        sensor_id="traffic-001",
        sensor_type="traffic_flow",
        value=12.5,
        unit="vehicles/min",
    )
    command = ActuatorCommand(
        command_id=uuid4(),
        decision_id=uuid4(),
        correlation_id=reading.correlation_id,
        issued_at=now,
        expires_at=now + timedelta(seconds=60),
        actuator_id="mock-light",
        action="set_phase",
        parameters={"phase": "green"},
    )
    async with httpx.AsyncClient(
        verify=client_context(settings),
        timeout=10,
        trust_env=False,
    ) as client:
        for base, path, event in (
            (settings.twin_base_url, "/readings", reading),
            (settings.guardian_base_url, "/evaluate", reading),
            (settings.twin_base_url, "/commands", command),
        ):
            response = await client.post(
                str(base).rstrip("/") + path,
                headers=headers,
                json=event.model_dump(mode="json"),
            )
            response.raise_for_status()
        for _ in range(100):
            response = await client.get(
                str(settings.brain_base_url).rstrip("/") + f"/events/{reading.event_id}",
                headers=headers,
            )
            response.raise_for_status()
            if response.json()["eligible"]:
                break
            await asyncio.sleep(0.1)
        else:
            raise RuntimeError("Reading did not become trusted")
        state = await client.get(
            str(settings.brain_base_url).rstrip("/") + "/state/trusted",
            headers=headers,
        )
        state.raise_for_status()
        if state.json()["sensors"].get(reading.sensor_id, {}).get("event_id") != str(
            reading.event_id
        ):
            raise RuntimeError("Trusted operational state does not contain the reading")
        for base, path, event in (
            (settings.brain_base_url, "/readings", reading),
            (settings.twin_base_url, "/commands", command),
            (settings.guardian_base_url, "/evaluate", reading),
        ):
            response = await client.post(
                str(base).rstrip("/") + path,
                json=event.model_dump(mode="json"),
            )
            if response.status_code != 401:
                raise RuntimeError("Unauthenticated request was not rejected")


if __name__ == "__main__":
    asyncio.run(main())
