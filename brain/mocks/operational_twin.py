
import asyncio
import random
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx
import yaml

from app.core.config import Settings
from app.schemas.sensor import SensorReading
from app.state.registry import Registry


class OperationalTwin:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.registry = self._load_registry(settings.city_registry_file)
        self.random = random.Random(settings.mock_simulation_seed)
        self.running = False
        self.tick = 0
        self.generated = 0
        self.accepted_batches = 0
        self.errors = 0
        self.last_error: str | None = None
        self.last_sent_at: str | None = None
        self.injections: dict[str, float] = {}
        self.recovering: set[str] = set()
        self.actuators: dict[str, dict] = {}
        self._stop = asyncio.Event()

    @staticmethod
    def _load_registry(path: str | None) -> Registry:
        if not path:
            return Registry()
        return Registry.model_validate(
            yaml.safe_load(
                Path(path).read_text(encoding="utf-8")
            )
        )

    async def run(self) -> None:
        if self.settings.mock_simulation_auto_start:
            self.running = True

        while not self._stop.is_set():
            if self.running:
                await self.emit()

            with suppress(TimeoutError):
                await asyncio.wait_for(
                    self._stop.wait(),
                    self.settings.mock_simulation_interval_seconds,
                )

    def stop_worker(self) -> None:
        self._stop.set()

    def control(self, action: str, injection: str | None = None) -> None:
        if action == "start":
            self.running = True

        elif action == "stop":
            self.running = False

        elif action == "reset":
            self.injections.clear()
            self.recovering.clear()
            self.tick = 0

        elif action == "inject" and injection in {"traffic", "fire", "water"}:
            self.injections[injection] = 0.0
            self.recovering.discard(injection)

        elif action == "clear":
            self.recovering.update(self.injections)

        else:
            raise ValueError("invalid operational control")

    def command_executed(
        self,
        action: str,
        actuator_id: str,
        parameters: dict,
    ) -> None:
        mapping = {
            "demo_signal_optimize": "traffic",
            "demo_fire_alarm": "fire",
            "demo_flood_response": "water",
        }

        if target := mapping.get(action):
            self.recovering.add(target)

        self.actuators[actuator_id] = {
            "action": action,
            "parameters": parameters,
            "status": "executed",
            "at": datetime.now(UTC).isoformat(),
        }

    async def emit(self) -> None:
        readings = self._readings()

        if not readings:
            self.last_error = "operational registry is empty"
            self.errors += 1
            print(f"[Mock Twin] {self.last_error}", flush=True)
            return

        payload = [
            item.model_dump(mode="json")
            for item in readings
        ]

        stage = "Brain POST /readings/batch"

        try:
            async with httpx.AsyncClient(
                timeout=10,
                trust_env=False,
            ) as client:

                # Step 1: Send readings to Brain
                brain = await client.post(
                    str(self.settings.brain_base_url).rstrip("/")
                    + "/readings/batch",
                    headers={
                        "X-API-Key": self.settings.twin_api_key.get_secret_value()
                    },
                    json=payload,
                )

                brain.raise_for_status()

                # Step 2: Ask Guardian to evaluate same readings
                stage = "Guardian POST /evaluate-batch"

                guardian = await client.post(
                    str(self.settings.guardian_base_url).rstrip("/")
                    + "/evaluate-batch",
                    headers={
                        "X-API-Key": self.settings.brain_api_key.get_secret_value()
                    },
                    json=payload,
                )

                guardian.raise_for_status()

        except httpx.HTTPStatusError as exc:
            self.errors += 1
            response = exc.response

            detail = response.text[:250].replace("\n", " ")

            self.last_error = (
                f"{stage}: HTTP {response.status_code}"
                + (f" - {detail}" if detail else "")
            )

            print(
                f"[Mock Twin] {self.last_error}",
                flush=True,
            )
            return

        except (httpx.HTTPError, AttributeError) as exc:
            self.errors += 1
            self.last_error = (
                f"{stage}: {type(exc).__name__}"
            )

            print(
                f"[Mock Twin] {self.last_error}",
                flush=True,
            )
            return

        # Batch successfully accepted by both services
        self.generated += len(readings)
        self.accepted_batches += 1
        self.last_error = None
        self.last_sent_at = datetime.now(UTC).isoformat()
        self.tick += 1

        self._advance_injections()

    def _advance_injections(self) -> None:
        for name in list(self.injections):
            change = (
                -0.16 if name in self.recovering else 0.1
            )

            self.injections[name] = max(
                0.0,
                min(
                    1.0,
                    self.injections[name] + change,
                ),
            )

            if (
                name in self.recovering
                and self.injections[name] == 0
            ):
                self.injections.pop(name)
                self.recovering.discard(name)

    def _readings(self) -> list[SensorReading]:
        now = datetime.now(UTC)
        correlation_id = uuid4()

        return [
            SensorReading(
                event_id=uuid4(),
                correlation_id=correlation_id,
                occurred_at=now,
                sensor_id=sensor.sensor_id,
                sensor_type=sensor.measurement,
                unit=sensor.unit,
                value=round(
                    self._value(sensor.measurement),
                    3,
                ),
                attributes={
                    "zone_id": sensor.zone_id,
                    "mock_data": True,
                    "active_injections": sorted(self.injections),
                    **(
                        {"simulation_trust": "spoofed"}
                        if (
                            self.tick > 0
                            and self.tick % 30 == 0
                            and sensor.sensor_id == "traffic-central-03"
                        )
                        else {}
                    ),
                },
            )
            for sensor in self.registry.sensors
        ]

    def _value(self, measurement: str) -> float:
        traffic = self.injections.get("traffic", 0)
        fire = self.injections.get("fire", 0)
        water = self.injections.get("water", 0)

        values = {
            "traffic": (
                53 - 45 * traffic
                + self.random.uniform(-1.2, 1.2)
            ),
            "smoke": max(
                0,
                0.2 + 24 * fire
                + self.random.uniform(-0.08, 0.08),
            ),
            "temperature": (
                22 + 43 * fire
                + self.random.uniform(-0.4, 0.4)
            ),
            "water_level": (
                1 + 7 * water
                + self.random.uniform(-0.02, 0.02)
            ),
        }

        return values.get(measurement, 0)

    def status(self) -> dict:
        return {
            "running": self.running,
            "mock_data": True,
            "sensor_count": len(self.registry.sensors),
            "tick": self.tick,
            "generated": self.generated,
            "accepted_batches": self.accepted_batches,
            "errors": self.errors,
            "last_error": self.last_error,
            "last_sent_at": self.last_sent_at,
            "injections": self.injections,
            "recovering": sorted(self.recovering),
            "actuators": self.actuators,
        }
