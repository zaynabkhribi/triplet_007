import asyncio
import math
import statistics
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4, uuid5

import httpx
from sqlalchemy import func, select

from app.core.config import Settings
from app.database.models import (
    ActuatorCommandRecord,
    AuditEvent,
    CityRegistryRecord,
    DecisionRecord,
    EventLifecycle,
    IncidentRecord,
    ScenarioExecution,
    ScenarioLog,
)
from app.database.session import Database
from app.decision.config import DecisionPolicies, digest
from app.execution.actuator_manager import MockTwinAdapter
from app.intelligence.incident_rules import IncidentRules
from app.schemas.actuator import ActuatorCommand
from app.schemas.guardian import QuarantineNotification
from app.schemas.sensor import SensorReading
from app.state.registry import Registry
from mocks.mock_guardian import create_app as create_guardian
from mocks.mock_twin import create_app as create_twin
from mocks.simulation import TwinTimeSeries

SCENARIOS = {
    "traffic_congestion": "Traffic congestion produces an approved simulated response.",
    "building_fire": "Smoke evidence produces a critical simulated fire response.",
    "rapid_water_rise": "A trusted water-level trend produces a simulated response.",
    "power_overload": "Persistent power overload produces a simulated response.",
    "untrusted_sensor": "Mock Guardian rejection keeps spoofed evidence out of city state.",
    "sensor_quarantine": "Guardian quarantine removes a failed sensor from trusted state.",
    "unauthorized_actuator": "Unauthorized and unsupported actuator requests are rejected.",
    "communication_failure": "Uncertain delivery becomes UNKNOWN without an unsafe retry.",
    "restart_recovery": "An interrupted idempotent dispatch returns safely to PENDING.",
}
LIVE_SCENARIOS = {
    "normal_city": "Continuous normal city operation without a forced incident.",
    "city_under_pressure": "Concurrent traffic, fire, water, and power pressure.",
}

SPECS = {
    "traffic_congestion": (
        "traffic",
        "METR-LA_native_speed",
        "traffic_congestion",
        "below",
        [15, 10],
        20,
        "simulation_traffic_response",
    ),
    "building_fire": (
        "smoke",
        "ppm",
        "smoke_alert",
        "above",
        [20, 25],
        10,
        "simulation_fire_response",
    ),
    "rapid_water_rise": (
        "water_level",
        "ft",
        "rapid_water_rise",
        "rise",
        [1, 6, 12],
        0.5,
        "simulation_water_response",
    ),
    "power_overload": (
        "power_load",
        "kW",
        "power_overload",
        "above",
        [20, 25],
        10,
        "simulation_power_response",
    ),
}


class ScenarioRunner:
    def __init__(self, database: Database, settings: Settings) -> None:
        self.database, self.settings = database, settings
        self._tasks: set[asyncio.Task] = set()
        self._controls: dict[UUID, dict] = {}

    async def run(self, scenario_id: str) -> dict:
        execution_id, started = self._create(scenario_id)
        return await self._run(execution_id, scenario_id, started)

    def start(self, scenario_id: str) -> dict:
        execution_id, started = self._create(scenario_id)
        task = asyncio.create_task(self._run(execution_id, scenario_id, started))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return self.get(execution_id)

    def start_live(
        self,
        scenario_id: str,
        sensor_count: int = 10,
        seed: int | None = None,
    ) -> dict:
        if any(not task.done() for task in self._tasks):
            raise ValueError("simulation_already_running")
        if sensor_count not in {10, 50, 100}:
            raise ValueError("invalid_sensor_count")
        execution_id, started = self._create(scenario_id)
        gate = asyncio.Event()
        gate.set()
        self._controls[execution_id] = {
            "gate": gate,
            "stop": False,
            "speed": 1.0,
            "sensor_count": sensor_count,
            "seed": self.settings.simulation_seed if seed is None else seed,
            "started_monotonic": time.perf_counter(),
            "next_tick": time.perf_counter(),
            "emitted": 0,
        }
        with self.database.transaction() as session:
            row = session.get(ScenarioExecution, execution_id)
            row.payload = row.payload | {
                "sensor_count": sensor_count,
                "simulation_seed": self._controls[execution_id]["seed"],
                "synthetic": True,
            }
        task = asyncio.create_task(self._run(execution_id, scenario_id, started, dynamic=True))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return self.get(execution_id)

    def control(self, execution_id: UUID, action: str, speed: float | None = None) -> dict:
        control = self._controls.get(execution_id)
        if control is None:
            raise LookupError("active_simulation_not_found")
        if speed is not None:
            if speed not in {1.0, 2.0, 5.0}:
                raise ValueError("invalid_simulation_speed")
            control["speed"] = speed
        if action == "pause":
            control["gate"].clear()
            self._set_status(execution_id, "PAUSED")
        elif action == "resume":
            control["next_tick"] = time.perf_counter()
            control["gate"].set()
            self._set_status(execution_id, "RUNNING")
        elif action == "stop":
            control["stop"] = True
            control["gate"].set()
        elif action != "speed":
            raise ValueError("invalid_simulation_control")
        return self.get(execution_id)

    def _set_status(self, execution_id: UUID, status: str) -> None:
        with self.database.transaction() as session:
            row = session.get(ScenarioExecution, execution_id)
            if row is not None and row.status in {"RUNNING", "PAUSED"}:
                row.status = status

    def _create(self, scenario_id: str) -> tuple[UUID, datetime]:
        if scenario_id not in SCENARIOS and scenario_id not in LIVE_SCENARIOS:
            raise ValueError("unknown_scenario")
        execution_id, correlation_id, started = uuid4(), uuid4(), datetime.now(UTC)
        with self.database.transaction() as session:
            session.add(
                ScenarioExecution(
                    id=execution_id,
                    correlation_id=correlation_id,
                    occurred_at=started,
                    scenario_id=scenario_id,
                    status="RUNNING",
                    payload={
                        "expected": (SCENARIOS | LIVE_SCENARIOS)[scenario_id],
                        "log_location": (f"database:scenario_logs:{execution_id}"),
                    },
                )
            )
        return execution_id, started

    async def _run(
        self,
        execution_id: UUID,
        scenario_id: str,
        started: datetime,
        dynamic: bool = False,
    ) -> dict:
        try:
            actual = await self._execute(scenario_id, execution_id, dynamic)
            passed = actual.pop("passed")
            status = actual.pop("terminal_status", None) or ("PASSED" if passed else "FAILED")
        except Exception as exc:
            actual = {"error": type(exc).__name__, "reason": str(exc)[:256]}
            passed, status = False, "FAILED"
        finished = datetime.now(UTC)
        with self.database.transaction() as session:
            row = session.get(ScenarioExecution, execution_id)
            row.status = status
            row.payload = row.payload | {
                "actual": actual,
                "passed": passed,
                "finished_at": finished.isoformat(),
            }
            session.add(
                ScenarioLog(
                    execution_id=execution_id,
                    occurred_at=finished,
                    stage="SCENARIO_RESULT",
                    status=status,
                    detail=actual,
                )
            )
        self._controls.pop(execution_id, None)
        return self.get(execution_id)

    def recover(self) -> None:
        now = datetime.now(UTC)
        with self.database.transaction() as session:
            rows = session.scalars(
                select(ScenarioExecution).where(ScenarioExecution.status == "RUNNING")
            ).all()
            for row in rows:
                row.status = "FAILED"
                row.payload = row.payload | {
                    "actual": {"reason": "brain_restarted_during_scenario"},
                    "passed": False,
                    "finished_at": now.isoformat(),
                }
                session.add(
                    ScenarioLog(
                        execution_id=row.id,
                        occurred_at=now,
                        stage="SCENARIO_RESULT",
                        status="FAILED",
                        detail={"reason": "brain_restarted_during_scenario"},
                    )
                )

    async def shutdown(self) -> None:
        for control in self._controls.values():
            control["stop"] = True
            control["gate"].set()
        if self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)

    def _log(self, execution_id: UUID, stage: str, status: str, detail: dict) -> None:
        with self.database.transaction() as session:
            session.add(
                ScenarioLog(
                    execution_id=execution_id,
                    occurred_at=datetime.now(UTC),
                    stage=stage,
                    status=status,
                    detail=detail,
                )
            )

    def get(self, execution_id: UUID) -> dict:
        with self.database.transaction() as session:
            row = session.get(ScenarioExecution, execution_id)
            if row is None:
                raise LookupError("scenario_execution_not_found")
            logs = session.scalars(
                select(ScenarioLog)
                .where(
                    ScenarioLog.execution_id == execution_id,
                )
                .order_by(ScenarioLog.occurred_at, ScenarioLog.id)
            ).all()
            return {
                "execution_id": str(row.id),
                "scenario_id": row.scenario_id,
                "started_at": row.occurred_at,
                "status": row.status,
                **row.payload,
                "timeline": [
                    {
                        "at": item.occurred_at,
                        "stage": item.stage,
                        "status": item.status,
                        "detail": item.detail,
                    }
                    for item in logs
                ],
            }

    def list_executions(self, limit: int = 100) -> list[dict]:
        with self.database.transaction() as session:
            rows = session.scalars(
                select(ScenarioExecution)
                .order_by(
                    ScenarioExecution.occurred_at.desc(),
                    ScenarioExecution.id,
                )
                .limit(limit)
            ).all()
            return [
                {
                    "execution_id": str(row.id),
                    "scenario_id": row.scenario_id,
                    "started_at": row.occurred_at,
                    "status": row.status,
                    **row.payload,
                }
                for row in rows
            ]

    def reset(self) -> dict:
        execution_id, now = uuid4(), datetime.now(UTC)
        detail = {
            "strategy": "isolated_fresh_database_per_run",
            "expected": "No simulation state is reused by the next run.",
            "actual": (
                "Scenario runtime state was already isolated; persistent evidence was retained."
            ),
            "passed": True,
        }
        with self.database.transaction() as session:
            session.add(
                ScenarioExecution(
                    id=execution_id,
                    correlation_id=uuid4(),
                    occurred_at=now,
                    scenario_id="reset",
                    status="PASSED",
                    payload=detail
                    | {
                        "log_location": f"database:scenario_logs:{execution_id}",
                        "finished_at": now.isoformat(),
                    },
                )
            )
            session.add(
                ScenarioLog(
                    execution_id=execution_id,
                    occurred_at=now,
                    stage="SCENARIO_RESET",
                    status="PASSED",
                    detail=detail,
                )
            )
        return self.get(execution_id)

    async def _execute(self, scenario_id: str, execution_id: UUID, dynamic: bool = False) -> dict:
        with tempfile.TemporaryDirectory(prefix="city-scenario-") as directory:
            settings = self._settings(Path(directory), scenario_id)
            from app.main import create_app

            brain = create_app(settings)
            twin, guardian = create_twin(settings), create_guardian(settings)
            twin.state.transport = guardian.state.transport = httpx.ASGITransport(brain)
            async with (
                brain.router.lifespan_context(brain),
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(brain), base_url="http://brain"
                ) as bc,
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(twin), base_url="http://twin"
                ) as tc,
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(guardian), base_url="http://guardian"
                ) as gc,
            ):
                context = self._configure(brain, settings, scenario_id)
                if dynamic:
                    control = self._controls[execution_id]
                    self._configure_dynamic_registry(
                        brain,
                        context,
                        scenario_id,
                        control["sensor_count"],
                    )
                brain.state.actuator_manager.adapter = MockTwinAdapter(
                    settings,
                    httpx.ASGITransport(twin),
                )
                headers = {"X-API-Key": settings.brain_api_key.get_secret_value()}
                flow = self._flow_dynamic if dynamic else self._flow
                return await flow(
                    scenario_id,
                    execution_id,
                    brain,
                    twin,
                    bc,
                    tc,
                    gc,
                    headers,
                    context,
                )

    def _settings(self, directory: Path, scenario_id: str) -> Settings:
        data = self.settings.model_dump()
        data.update(
            {
                "environment": "development",
                "database_url": f"sqlite:///{directory / 'scenario.db'}",
                "brain_base_url": "http://brain",
                "twin_base_url": "http://twin",
                "guardian_base_url": "http://guardian",
                "worker_enabled": False,
                # Isolated scenario apps dispatch only to an in-process Mock
                # Twin via ASGITransport (never a real network actuator), so
                # execution is explicitly enabled here to exercise delivery
                # through the same gated tick() boundary used in production.
                "actuator_execution_enabled": True,
                "actuator_transport": "mock_twin",
                "traffic_model_dir": None,
                "water_model_path": None,
                "city_registry_file": None,
                "incident_rules_file": None,
                "decision_policy_file": None,
                "mock_guardian_default_status": "rejected"
                if scenario_id == "untrusted_sensor"
                else "trusted",
            }
        )
        return Settings(_env_file=None, **data)

    def _configure(self, brain, settings: Settings, scenario_id: str) -> dict:
        spec = SPECS.get(scenario_id, SPECS["building_fire"])
        measurement, unit, incident_type, mode, values, threshold, action_type = spec
        sensor_id, zone_id, actuator_id = "scenario-sensor", "scenario-zone", "scenario-actuator"
        registry = Registry.model_validate(
            {
                "zones": [zone_id],
                "window_seconds": 300,
                "sensors": [
                    {
                        "sensor_id": sensor_id,
                        "zone_id": zone_id,
                        "measurement": measurement,
                        "unit": unit,
                        "freshness_seconds": 300,
                    }
                ],
            }
        )
        rule = {
            "id": "scenario-rule",
            "incident_type": incident_type,
            "measurement": measurement,
            "unit": unit,
            "mode": mode,
            "thresholds": {"high": threshold},
            "persistence_seconds": 5,
            "min_samples": 2,
            "recovery_seconds": 5,
            "recovery_samples": 2,
        }
        rules = IncidentRules.model_validate(
            {
                "version": "1.0.0",
                "simulation_only": True,
                "rules": [rule],
            }
        )
        now = datetime.now(UTC)
        available = {
            "available": True,
            "observed_at": now - timedelta(minutes=1),
            "valid_until": now + timedelta(minutes=10),
        }
        policy = DecisionPolicies.model_validate(
            {
                "version": "1.0.0",
                "simulation_only": True,
                "approved": True,
                "approval_reference": "scenario-only-authorization",
                "approved_incident_config_sha256": digest(rules.model_dump()),
                "resources": {
                    "scenario-resource": {**available, "capacity": 1, "zones": [zone_id]}
                },
                "actuators": {
                    actuator_id: {
                        **available,
                        "zone": zone_id,
                        "capabilities": {action_type: {"level": {"minimum": 0, "maximum": 1}}},
                    }
                },
                "actions": [
                    {
                        "id": "scenario-action",
                        "incident_types": [incident_type],
                        "zones": [zone_id],
                        "minimum_severity": "high",
                        "action_type": action_type,
                        "actuator_id": actuator_id,
                        "parameters": {"level": 1},
                        "resources": {"scenario-resource": 1},
                        "cost": 1,
                        "benefit": 2,
                        "safety_critical": True,
                        "requires_approval": True,
                        "idempotent": scenario_id == "restart_recovery",
                    }
                ],
                "optimization": {
                    "max_actions": 1,
                    "severity_weights": {"high": 10},
                    "urgency_weights": {incident_type: 1},
                    "zone_weights": {zone_id: 1},
                },
            }
        )
        with brain.state.database.transaction() as session:
            session.merge(CityRegistryRecord(id=1, payload=registry.model_dump()))
        brain.state.city_engine.incidents.rules = rules
        brain.state.city_engine.decisions.incident_rules = rules
        brain.state.city_engine.decisions.policy = policy
        brain.state.city_engine.decisions.error = None
        settings.mock_twin_allowed_actions = action_type
        return {
            "spec": spec,
            "values": values,
            "sensor_id": sensor_id,
            "zone_id": zone_id,
            "actuator_id": actuator_id,
        }

    def _configure_dynamic_registry(
        self, brain, context: dict, scenario_id: str, sensor_count: int
    ) -> None:
        primary_measurement, primary_unit = context["spec"][:2]
        definitions = [
            ("traffic", "METR-LA_native_speed"),
            ("smoke", "ppm"),
            ("temperature", "degC"),
            ("water_level", "ft"),
            ("power_load", "kW"),
            ("air_quality", "ug/m3"),
        ]
        sensors = []
        for index in range(sensor_count):
            measurement, unit = definitions[index % len(definitions)]
            sensor_id = (
                context["sensor_id"]
                if index == 0
                else f"sim-{measurement.replace('_', '-')}-{index:03d}"
            )
            if index == 0:
                measurement, unit = primary_measurement, primary_unit
            sensors.append(
                {
                    "sensor_id": sensor_id,
                    "zone_id": context["zone_id"],
                    "measurement": measurement,
                    "unit": unit,
                    "freshness_seconds": 300,
                }
            )
        registry = Registry.model_validate(
            {"zones": [context["zone_id"]], "window_seconds": 300, "sensors": sensors}
        )
        rules = brain.state.city_engine.incidents.rules.model_copy(deep=True)
        if scenario_id == "normal_city":
            rules.rules = []
        elif scenario_id == "city_under_pressure":
            rules = IncidentRules.model_validate(
                {
                    "version": "1.0.0",
                    "simulation_only": True,
                    "rules": [
                        {
                            "id": "pressure-traffic",
                            "incident_type": "traffic_congestion",
                            "measurement": "traffic",
                            "unit": "METR-LA_native_speed",
                            "mode": "below",
                            "thresholds": {"high": 20},
                            "persistence_seconds": 0,
                            "recovery_seconds": 0,
                            "min_samples": 2,
                            "recovery_samples": 2,
                        },
                        {
                            "id": "pressure-fire",
                            "incident_type": "smoke_alert",
                            "measurement": "smoke",
                            "unit": "ppm",
                            "mode": "above",
                            "thresholds": {"high": 10},
                            "persistence_seconds": 0,
                            "recovery_seconds": 0,
                            "min_samples": 2,
                            "recovery_samples": 2,
                        },
                        {
                            "id": "pressure-power",
                            "incident_type": "power_overload",
                            "measurement": "power_load",
                            "unit": "kW",
                            "mode": "above",
                            "thresholds": {"high": 15},
                            "persistence_seconds": 0,
                            "recovery_seconds": 0,
                            "min_samples": 2,
                            "recovery_samples": 2,
                        },
                    ],
                }
            )
        for rule in rules.rules:
            rule.persistence_seconds = 0
            rule.recovery_seconds = 0
        with brain.state.database.transaction() as session:
            session.merge(CityRegistryRecord(id=1, payload=registry.model_dump()))
        brain.state.city_engine.incidents.rules = rules
        brain.state.city_engine.decisions.incident_rules = rules
        policy = brain.state.city_engine.decisions.policy.model_copy(deep=True)
        policy.approved_incident_config_sha256 = digest(rules.model_dump())
        brain.state.city_engine.decisions.policy = policy
        context["sensors"] = sensors
        context["scenario_id"] = scenario_id
        context["sensor_count"] = sensor_count

    async def _wait_live(self, execution_id: UUID) -> bool:
        control = self._controls[execution_id]
        await control["gate"].wait()
        if control["stop"]:
            return False
        control["next_tick"] += self.settings.simulation_interval_seconds / control["speed"]
        delay = control["next_tick"] - time.perf_counter()
        if delay > 0:
            await asyncio.sleep(delay)
        return not control["stop"]

    async def _emit_live_tick(
        self,
        execution_id: UUID,
        tick: int,
        primary: float,
        phase: str,
        brain,
        tc,
        gc,
        headers: dict,
        context: dict,
        simulator: TwinTimeSeries,
    ) -> dict:
        started = time.perf_counter()
        baseline = simulator.measurements(context["spec"][0], primary)
        events, event_started = [], []
        correlation_id = uuid5(execution_id, "live-correlation")
        for sensor_index, sensor in enumerate(context["sensors"]):
            measurement = sensor["measurement"]
            attributes = {"zone_id": context["zone_id"], "simulation_only": True, "phase": phase}
            if (
                context["scenario_id"] == "city_under_pressure"
                and phase == "security"
                and sensor_index == len(context["sensors"]) - 1
            ):
                attributes["simulation_trust"] = "spoofed"
            if measurement == "traffic":
                attributes |= {
                    "vehicle_count": round(max(2, 62 - baseline[measurement]), 2),
                    "occupancy_percent": round(min(98, 100 - baseline[measurement]), 2),
                }
            if measurement == "power_load":
                attributes["capacity_utilization_percent"] = round(
                    min(100, baseline[measurement] / 28 * 100), 2
                )
            event = SensorReading(
                event_id=uuid5(execution_id, f"live-{tick}-{sensor['sensor_id']}"),
                correlation_id=correlation_id,
                occurred_at=datetime.now(UTC),
                sensor_id=sensor["sensor_id"],
                sensor_type=measurement,
                unit=sensor["unit"],
                value=round(baseline[measurement], 3),
                attributes=attributes,
            )
            event_started.append(time.perf_counter())
            events.append(event)
        readings = [event.model_dump(mode="json") for event in events]
        ingestion = await tc.post("/readings/batch", headers=headers, json=readings)
        ingestion.raise_for_status()
        verdict_response = await gc.post("/evaluate-batch", headers=headers, json=readings)
        verdict_response.raise_for_status()
        verdicts = verdict_response.json()
        await brain.state.processor.tick(datetime.now(UTC))
        completed = time.perf_counter()
        elapsed = completed - started
        control = self._controls[execution_id]
        control["emitted"] += len(readings)
        run_elapsed = completed - control["started_monotonic"]
        latencies = sorted((completed - value) * 1000 for value in event_started)
        state = brain.state.city_engine.snapshot()
        self._log(
            execution_id,
            "SENSOR_READING",
            phase.upper(),
            {
                "tick": tick,
                "phase": phase,
                "zone_id": context["zone_id"],
                "sensor_id": context["sensor_id"],
                "measurement": context["spec"][0],
                "unit": context["spec"][1],
                "readings": readings,
            },
        )
        self._log(
            execution_id,
            "GUARDIAN_VERDICT",
            verdicts[-1]["status"].upper(),
            {"tick": tick, "verdicts": verdicts},
        )
        self._log(
            execution_id,
            "TRUSTED_CITY_STATE",
            phase.upper(),
            {
                "tick": tick,
                "zone_id": context["zone_id"],
                "sensors": state["sensors"],
                "sensor": state["sensors"].get(context["sensor_id"]),
                "simulation_only": True,
            },
        )
        accepted = sum(item["status"] == "trusted" for item in verdicts)
        with brain.state.database.transaction() as session:
            backlog = session.scalar(
                select(func.count())
                .select_from(EventLifecycle)
                .where(EventLifecycle.processing != "acknowledged")
            )
        self._log(
            execution_id,
            "PERFORMANCE",
            "MEASURED",
            {
                "tick": tick,
                "sensor_count": len(readings),
                "elapsed_seconds": round(elapsed, 4),
                "events_per_second": round(control["emitted"] / run_elapsed, 2),
                "processing_capacity_events_per_second": (
                    round(len(readings) / elapsed, 2) if elapsed else 0
                ),
                "latency_p50_ms": round(statistics.median(latencies), 2),
                "latency_p95_ms": round(
                    latencies[max(0, math.ceil(len(latencies) * 0.95) - 1)], 2
                ),
                "guardian_accepted": accepted,
                "guardian_rejected": len(verdicts) - accepted,
                "backlog": backlog or 0,
                "errors": 0,
            },
        )
        return state

    async def _flow_dynamic(
        self, scenario_id, execution_id, brain, twin, bc, tc, gc, headers, context
    ) -> dict:
        simulator = TwinTimeSeries(scenario_id, self._controls[execution_id]["seed"])
        values = simulator.primary_values(self.settings.simulation_max_ticks)
        incidents: dict[str, dict] = {}
        incident_signatures: dict[str, tuple[str, str]] = {}
        for tick, value in enumerate(values):
            if scenario_id == "communication_failure" and tick in {3, 4}:
                self._log(
                    execution_id,
                    "SENSOR_GAP",
                    "MISSING",
                    {"tick": tick, "reason": "simulated_twin_communication_loss"},
                )
                if not await self._wait_live(execution_id):
                    return {
                        "passed": True,
                        "terminal_status": "STOPPED",
                        "stopped_at_tick": tick,
                    }
                continue
            if scenario_id == "sensor_quarantine" and tick > 2:
                value = values[2]
            phase = "normal" if tick < 3 else "developing"
            if scenario_id == "city_under_pressure":
                phase = "normal" if tick < 25 else ("developing" if tick < 60 else "security")
            await self._emit_live_tick(
                execution_id,
                tick,
                value,
                phase,
                brain,
                tc,
                gc,
                headers,
                context,
                simulator,
            )
            active = (await bc.get("/v1/incidents/active", headers=headers)).json()
            for incident in active:
                incidents[incident["incident_id"]] = incident
                signature = (incident["status"], incident["severity"])
                if signature != incident_signatures.get(incident["incident_id"]):
                    self._log(
                        execution_id,
                        "INCIDENT",
                        incident["status"],
                        {
                            "incident_id": incident["incident_id"],
                            "incident_type": incident["incident_type"],
                            "severity": incident["severity"],
                            "zone_id": incident["zone_id"],
                        },
                    )
                    incident_signatures[incident["incident_id"]] = signature
            if scenario_id == "sensor_quarantine" and tick == 3:
                notice = QuarantineNotification(
                    notification_id=uuid5(execution_id, "live-quarantine"),
                    correlation_id=uuid5(execution_id, "live-correlation"),
                    guardian_id=brain.state.settings.guardian_identity,
                    issued_at=datetime.now(UTC),
                    target_type="sensor",
                    target_id=context["sensor_id"],
                    action="quarantine",
                    revision=1,
                    reason_code="simulated_sensor_failure",
                )
                response = await gc.post(
                    "/quarantines", headers=headers, json=notice.model_dump(mode="json")
                )
                response.raise_for_status()
            if not await self._wait_live(execution_id):
                return {"passed": True, "terminal_status": "STOPPED", "stopped_at_tick": tick}
        if scenario_id == "normal_city":
            return {"passed": True, "terminal_status": "STOPPED", "reason": "tick_limit"}
        if scenario_id in {"untrusted_sensor", "sensor_quarantine"}:
            state = brain.state.city_engine.snapshot()["sensors"][context["sensor_id"]]
            return {
                "passed": state["value"] is None,
                "trusted_value": state["value"],
                "sensor_availability": state["availability"],
            }
        if scenario_id == "city_under_pressure":
            await self._emit_live_tick(
                execution_id,
                len(values),
                values[-1],
                "stabilizing",
                brain,
                tc,
                gc,
                headers,
                context,
                simulator,
            )
        active = (await bc.get("/v1/incidents/active", headers=headers)).json()
        if not active and not incidents:
            return {"passed": False, "reason": "incident_not_detected"}
        incident = active[0] if active else next(iter(incidents.values()))
        decision_response = await bc.post("/v1/decisions/evaluate", headers=headers, json={})
        decision_response.raise_for_status()
        decision = decision_response.json()
        self._log(
            execution_id,
            "DECISION",
            decision["status"],
            {
                "decision_id": decision["decision_id"],
                "outcome": decision["outcome"],
                "reason": decision.get("reason"),
                "selected_actions": decision.get("selected_actions", []),
            },
        )
        for _ in range(5):
            approval = {
                "approval": {
                    "decision_id": decision["decision_id"],
                    "reason": "explicit continuous simulation authorization",
                }
            }
            approval_response = await bc.post(
                "/v1/decisions/evaluate", headers=headers, json=approval
            )
            if approval_response.status_code != 409:
                approval_response.raise_for_status()
                decision = approval_response.json()
                break
            reevaluation = await bc.post("/v1/decisions/evaluate", headers=headers, json={})
            reevaluation.raise_for_status()
            decision = reevaluation.json()
        else:
            approval_response.raise_for_status()
        self._log(
            execution_id,
            "APPROVAL",
            decision["status"],
            {
                "decision_id": decision["decision_id"],
                "safety_check": "passed" if decision["status"] == "APPROVED" else "failed",
                "approved_actions": decision.get("approved_actions", []),
            },
        )
        if scenario_id == "unauthorized_actuator":
            denied = await bc.post(
                "/v1/actions/execute",
                headers={"X-API-Key": brain.state.settings.twin_api_key.get_secret_value()},
                json={"decision_id": decision["decision_id"]},
            )
            self._log(
                execution_id,
                "ACTUATOR_REJECTION",
                "REJECTED",
                {"unauthorized_http": denied.status_code, "actuator_id": context["actuator_id"]},
            )
            return {"passed": denied.status_code == 403, "unauthorized_http": denied.status_code}
        for _ in range(5):
            execution = await bc.post(
                "/v1/actions/execute",
                headers=headers,
                json={"decision_id": decision["decision_id"]},
            )
            if execution.status_code != 403:
                break
            reevaluation = await bc.post("/v1/decisions/evaluate", headers=headers, json={})
            reevaluation.raise_for_status()
            decision = reevaluation.json()
            for _ in range(5):
                approval_response = await bc.post(
                    "/v1/decisions/evaluate",
                    headers=headers,
                    json={
                        "approval": {
                            "decision_id": decision["decision_id"],
                            "reason": "explicit continuous simulation authorization",
                        }
                    },
                )
                if approval_response.status_code != 409:
                    approval_response.raise_for_status()
                    decision = approval_response.json()
                    break
                reevaluation = await bc.post(
                    "/v1/decisions/evaluate", headers=headers, json={}
                )
                reevaluation.raise_for_status()
                decision = reevaluation.json()
            else:
                approval_response.raise_for_status()
        execution.raise_for_status()
        command = execution.json()["commands"][0]
        self._log(
            execution_id,
            "ACTUATOR_COMMAND",
            command["status"],
            {
                "command_id": command["command_id"],
                "actuator_id": command["actuator_id"],
                "action": command["command"]["action"],
                "parameters": command["command"]["parameters"],
                "before": {"status": "idle"},
            },
        )
        if scenario_id == "communication_failure":
            brain.state.actuator_manager.adapter = MockTwinAdapter(
                brain.state.settings,
                httpx.MockTransport(
                    lambda _: (_ for _ in ()).throw(httpx.ConnectError("simulated"))
                ),
            )
        if scenario_id == "restart_recovery":
            with brain.state.database.transaction() as session:
                row = session.get(ActuatorCommandRecord, UUID(command["command_id"]))
                brain.state.actuator_manager.transition(
                    session,
                    row,
                    "DISPATCHING",
                    "simulated_process_interruption",
                    datetime.now(UTC),
                )
            brain.state.actuator_manager.recover_startup()
        else:
            await brain.state.actuator_manager.tick()
        with brain.state.database.transaction() as session:
            command_status = session.get(ActuatorCommandRecord, UUID(command["command_id"])).status
        actuator_state = twin.state.actuators.get(context["actuator_id"])
        self._log(
            execution_id,
            "EXECUTION_FEEDBACK",
            command_status,
            {
                "command_id": command["command_id"],
                "actuator_id": context["actuator_id"],
                "after": actuator_state or {"status": command_status.lower()},
            },
        )
        recovery_status = None
        if command_status == "EXECUTED":
            recovery = list(reversed(values[:5]))
            recovery_start = len(values) + (scenario_id == "city_under_pressure")
            for offset, value in enumerate(recovery, start=recovery_start):
                await self._emit_live_tick(
                    execution_id,
                    offset,
                    value,
                    "recovery",
                    brain,
                    tc,
                    gc,
                    headers,
                    context,
                    simulator,
                )
                if not await self._wait_live(execution_id):
                    return {
                        "passed": True,
                        "terminal_status": "STOPPED",
                        "command_status": command_status,
                    }
            recovery_incident_id = decision["approved_actions"][0]["incident_id"]
            recovered = (
                await bc.get(f"/v1/incidents/{recovery_incident_id}", headers=headers)
            ).json()
            recovery_status = recovered["status"]
            self._log(
                execution_id,
                "INCIDENT",
                recovered["status"],
                {
                    "incident_id": recovered["incident_id"],
                    "incident_type": recovered["incident_type"],
                    "severity": recovered["severity"],
                    "zone_id": recovered["zone_id"],
                    "phase": "recovery",
                },
            )
        expected = (
            "UNKNOWN"
            if scenario_id == "communication_failure"
            else ("PENDING" if scenario_id == "restart_recovery" else "EXECUTED")
        )
        return {
            "passed": command_status == expected,
            "incident_type": incident["incident_type"],
            "incident_count": len(incidents),
            "decision_status": decision["status"],
            "command_status": command_status,
            "recovery": recovery_status == "RESOLVED",
        }

    async def _flow(self, scenario_id, execution_id, brain, twin, bc, tc, gc, headers, context):
        events = []
        now = datetime.now(UTC)
        for index, value in enumerate(context["values"]):
            event = SensorReading(
                event_id=uuid5(execution_id, f"reading-{index}"),
                correlation_id=uuid5(execution_id, "correlation"),
                occurred_at=now - timedelta(seconds=5 * (len(context["values"]) - index - 1)),
                sensor_id=context["sensor_id"],
                sensor_type=context["spec"][0],
                unit=context["spec"][1],
                value=value,
                attributes={"zone_id": context["zone_id"]},
            )
            response = await tc.post(
                "/readings", headers=headers, json=event.model_dump(mode="json")
            )
            response.raise_for_status()
            verdict = await gc.post(
                "/evaluate", headers=headers, json=event.model_dump(mode="json")
            )
            verdict.raise_for_status()
            events.append((event, verdict.json()))
        await brain.state.processor.tick(datetime.now(UTC))
        self._log(
            execution_id,
            "SENSOR_READING",
            "RECEIVED",
            {
                "sensor_id": context["sensor_id"],
                "zone_id": context["zone_id"],
                "measurement": context["spec"][0],
                "unit": context["spec"][1],
                "readings": [
                    {
                        "event_id": str(item[0].event_id),
                        "occurred_at": item[0].occurred_at.isoformat(),
                        "value": item[0].value,
                    }
                    for item in events
                ],
            },
        )
        self._log(
            execution_id,
            "GUARDIAN_VERDICT",
            events[-1][1]["status"].upper(),
            {
                "guardian_id": brain.state.settings.guardian_identity,
                "verdicts": [
                    {
                        "verdict_id": item[1]["verdict_id"],
                        "event_id": str(item[0].event_id),
                        "status": item[1]["status"],
                    }
                    for item in events
                ],
            },
        )
        if scenario_id == "sensor_quarantine":
            notice = QuarantineNotification(
                notification_id=uuid5(execution_id, "quarantine"),
                correlation_id=events[-1][0].correlation_id,
                guardian_id=brain.state.settings.guardian_identity,
                issued_at=now,
                target_type="sensor",
                target_id=context["sensor_id"],
                action="quarantine",
                revision=1,
                reason_code="simulated_sensor_failure",
            )
            response = await gc.post(
                "/quarantines", headers=headers, json=notice.model_dump(mode="json")
            )
            response.raise_for_status()
            await brain.state.processor.tick(datetime.now(UTC))
            sensor = brain.state.city_engine.snapshot()["sensors"][context["sensor_id"]]
            await brain.state.processor.tick(now + timedelta(milliseconds=1))
        state = brain.state.city_engine.snapshot()
        sensor = state["sensors"][context["sensor_id"]]
        self._log(
            execution_id,
            "TRUSTED_CITY_STATE",
            sensor["availability"].upper(),
            {
                "zone_id": context["zone_id"],
                "sensor": sensor,
                "simulation_only": True,
            },
        )
        if scenario_id in {"untrusted_sensor", "sensor_quarantine"}:
            expected = sensor["value"] is None and not self._counts(brain)["incidents"]
            return {
                "passed": expected,
                "sensor_availability": sensor["availability"],
                "trusted_value": sensor["value"],
                "incident_count": self._counts(brain)["incidents"],
            }
        incident = (await bc.get("/v1/incidents/active", headers=headers)).json()[0]
        self._log(
            execution_id,
            "INCIDENT",
            incident["status"],
            {
                "incident_id": incident["incident_id"],
                "incident_type": incident["incident_type"],
                "severity": incident["severity"],
                "zone_id": incident["zone_id"],
                "evidence": incident.get("evidence", []),
            },
        )
        decision = (await bc.post("/v1/decisions/evaluate", headers=headers, json={})).json()
        self._log(
            execution_id,
            "DECISION",
            decision["status"],
            {
                "decision_id": decision["decision_id"],
                "outcome": decision["outcome"],
                "reason": decision.get("reason"),
                "selected_actions": decision.get("selected_actions", []),
                "rejected_alternatives": decision.get("rejected_alternatives", []),
            },
        )
        approval = {
            "approval": {
                "decision_id": decision["decision_id"],
                "reason": "explicit scenario-only authorization",
            }
        }
        decision = (await bc.post("/v1/decisions/evaluate", headers=headers, json=approval)).json()
        self._log(
            execution_id,
            "APPROVAL",
            decision["status"],
            {
                "decision_id": decision["decision_id"],
                "safety_check": "passed" if decision["status"] == "APPROVED" else "failed",
                "approved_actions": decision.get("approved_actions", []),
            },
        )
        if scenario_id == "unauthorized_actuator":
            twin_headers = {"X-API-Key": brain.state.settings.twin_api_key.get_secret_value()}
            denied = await bc.post(
                "/v1/actions/execute",
                headers=twin_headers,
                json={"decision_id": decision["decision_id"]},
            )
            command = ActuatorCommand(
                command_id=uuid5(execution_id, "invalid-command"),
                decision_id=UUID(decision["decision_id"]),
                correlation_id=events[-1][0].correlation_id,
                issued_at=datetime.now(UTC),
                actuator_id=context["actuator_id"],
                action="unsupported_operation",
                expires_at=datetime.now(UTC) + timedelta(minutes=1),
            )
            invalid = await tc.post(
                "/commands", headers=headers, json=command.model_dump(mode="json")
            )
            self._log(
                execution_id,
                "ACTUATOR_REJECTION",
                "REJECTED",
                {
                    "actuator_id": context["actuator_id"],
                    "unauthorized_http": denied.status_code,
                    "invalid_operation_http": invalid.status_code,
                },
            )
            return {
                "passed": denied.status_code == 403 and invalid.status_code == 422,
                "unauthorized_http": denied.status_code,
                "invalid_operation_http": invalid.status_code,
            }
        execution = await bc.post(
            "/v1/actions/execute", headers=headers, json={"decision_id": decision["decision_id"]}
        )
        execution.raise_for_status()
        command = execution.json()["commands"][0]
        self._log(
            execution_id,
            "ACTUATOR_COMMAND",
            command["status"],
            {
                "command_id": command["command_id"],
                "actuator_id": command["actuator_id"],
                "action": command["command"]["action"],
                "parameters": command["command"]["parameters"],
                "before": {"status": "idle"},
            },
        )
        if scenario_id == "communication_failure":
            brain.state.actuator_manager.adapter = MockTwinAdapter(
                brain.state.settings,
                httpx.MockTransport(
                    lambda _: (_ for _ in ()).throw(httpx.ConnectError("simulated"))
                ),
            )
        if scenario_id == "restart_recovery":
            with brain.state.database.transaction() as session:
                row = session.get(ActuatorCommandRecord, UUID(command["command_id"]))
                brain.state.actuator_manager.transition(
                    session,
                    row,
                    "DISPATCHING",
                    "simulated_process_interruption",
                    datetime.now(UTC),
                )
            brain.state.actuator_manager.recover_startup()
        else:
            await brain.state.actuator_manager.tick()
        with brain.state.database.transaction() as session:
            row = session.get(ActuatorCommandRecord, UUID(command["command_id"]))
            command_status = row.status
        actuator_state = getattr(twin.state, "actuators", {}).get(context["actuator_id"])
        self._log(
            execution_id,
            "EXECUTION_FEEDBACK",
            command_status,
            {
                "command_id": command["command_id"],
                "actuator_id": context["actuator_id"],
                "after": actuator_state or {"status": command_status.lower()},
            },
        )
        expected = (
            "UNKNOWN"
            if scenario_id == "communication_failure"
            else ("PENDING" if scenario_id == "restart_recovery" else "EXECUTED")
        )
        return {
            "passed": command_status == expected,
            "incident_type": incident["incident_type"],
            "decision_status": decision["status"],
            "command_status": command_status,
            "expected_command_status": expected,
        }

    @staticmethod
    def _counts(brain) -> dict:
        with brain.state.database.transaction() as session:
            return {
                "incidents": len(
                    session.scalars(
                        select(IncidentRecord).where(
                            IncidentRecord.payload["status"]
                            .as_string()
                            .in_(
                                ["DETECTED", "ACTIVE", "ESCALATED"],
                            ),
                        )
                    ).all()
                ),
                "decisions": len(session.scalars(select(DecisionRecord)).all()),
                "audit": len(session.scalars(select(AuditEvent)).all()),
            }
