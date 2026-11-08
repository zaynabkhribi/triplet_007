import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx

from app.decision.config import digest, load_policy
from app.intelligence.incident_rules import load_rules


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    ports = []
    reservations = []
    for _ in range(3):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        ports.append(sock.getsockname()[1])
        reservations.append(sock)
    urls = [f"http://127.0.0.1:{port}" for port in ports]
    sensor_id, zone_id = str(uuid4()), str(uuid4())
    with tempfile.TemporaryDirectory(prefix="city-flow-") as directory:
        registry = Path(directory) / "registry.json"
        registry.write_text(
            json.dumps(
                {
                    "zones": [zone_id],
                    "sensors": [
                        {
                            "sensor_id": sensor_id,
                            "zone_id": zone_id,
                            "measurement": "temperature",
                            "unit": "degC",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        env = os.environ | {
            "INCIDENT_RULES_FILE": str(Path(directory) / "simulation-incidents.json"),
            "ENVIRONMENT": "development",
            "DATABASE_URL": f"sqlite:///{Path(directory) / 'city.db'}",
            "CITY_REGISTRY_FILE": str(registry),
            "WORKER_ENABLED": "true",
            "ACTUATOR_EXECUTION_ENABLED": "true",
            "ACTUATOR_TRANSPORT": "mock_twin",
            "MOCK_TWIN_ALLOWED_ACTIONS": "simulation_fire_response",
            "GUARDIAN_IDENTITY": str(uuid4()),
            "TLS_CA_FILE": "",
            "TLS_CERT_FILE": "",
            "TLS_KEY_FILE": "",
            **{
                f"{name}_BASE_URL": url
                for name, url in zip(
                    ("BRAIN", "TWIN", "GUARDIAN"),
                    urls,
                    strict=True,
                )
            },
            **{
                f"{name}_API_KEY": secrets.token_urlsafe(48)
                for name in ("BRAIN", "TWIN", "GUARDIAN")
            },
        }
        processes = []
        Path(env["INCIDENT_RULES_FILE"]).write_text(
            json.dumps(
                {
                    "version": "1.0.0",
                    "simulation_only": True,
                    "rules": [
                        {
                            "id": "simulation-temperature",
                            "incident_type": "abnormal_temperature",
                            "measurement": "temperature",
                            "unit": "degC",
                            "thresholds": {"medium": 10},
                            "min_samples": 1,
                            "persistence_seconds": 0,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        for sock in reservations:
            sock.close()
        policy, error = load_policy(str(root / "config/policies.simulation.yaml"))
        assert error is None and policy is not None
        policy.approved = True
        policy.approval_reference = "synthetic-standalone-review"
        policy.approved_incident_config_sha256 = digest(
            load_rules(env["INCIDENT_RULES_FILE"], "development").model_dump(),
        )
        policy.actions = [a for a in policy.actions if "abnormal_temperature" in a.incident_types]
        for action in policy.actions:
            action.zones = [zone_id]
        for actuator in policy.actuators.values():
            actuator.zone = zone_id
        for resource in policy.resources.values():
            resource.zones = [zone_id]
        for availability in [*policy.actuators.values(), *policy.resources.values()]:
            availability.available = True
            availability.observed_at = datetime.now(UTC)
            availability.valid_until = datetime.now(UTC) + timedelta(minutes=5)
        policy.optimization.zone_weights = {zone_id: 1}
        env["DECISION_POLICY_FILE"] = str(Path(directory) / "simulation-policies.json")
        Path(env["DECISION_POLICY_FILE"]).write_text(policy.model_dump_json(), encoding="utf-8")
        try:
            for module, port in zip(
                ("app.main:app", "mocks.mock_twin:app", "mocks.mock_guardian:app"),
                ports,
                strict=True,
            ):
                processes.append(
                    subprocess.Popen(
                        [
                            sys.executable,
                            "-m",
                            "uvicorn",
                            module,
                            "--host",
                            "127.0.0.1",
                            "--port",
                            str(port),
                        ],
                        cwd=root,
                        env=env,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                    )
                )
            with httpx.Client(timeout=3, trust_env=False) as client:
                for base, path in zip(urls, ("/health/ready", "/health", "/health"), strict=True):
                    for _ in range(100):
                        try:
                            if client.get(base + path).status_code == 200:
                                break
                        except httpx.HTTPError:
                            pass
                        time.sleep(0.1)
                    else:
                        raise RuntimeError("standalone service startup failed")
                headers = {"X-API-Key": env["BRAIN_API_KEY"]}
                event = {
                    "event_id": str(uuid4()),
                    "correlation_id": str(uuid4()),
                    "occurred_at": datetime.now(UTC).isoformat(),
                    "sensor_id": sensor_id,
                    "sensor_type": "temperature",
                    "unit": "degC",
                    "value": 21.5,
                }
                for base, path in ((urls[1], "/readings"), (urls[2], "/evaluate")):
                    client.post(base + path, headers=headers, json=event).raise_for_status()
                for _ in range(100):
                    response = client.get(urls[0] + "/v1/city/state", headers=headers)
                    response.raise_for_status()
                    result = response.json()["sensors"][sensor_id]
                    if result["value"] is not None:
                        assert result["value"] == 21.5
                        assert result["trust_status"] == "trusted"
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError("city state did not receive trusted evidence")
                assert client.get(urls[0] + "/v1/city/state").status_code == 401
                history = client.get(urls[0] + "/v1/city/history", headers=headers)
                history.raise_for_status()
                assert history.json()
                incidents = client.get(urls[0] + "/v1/incidents/active", headers=headers)
                incidents.raise_for_status()
                assert len(incidents.json()) == 1
                assert incidents.json()[0]["status"] == "ACTIVE"
                assert incidents.json()[0]["incident_type"] == "abnormal_temperature"
                assert client.get(urls[0] + "/v1/incidents/active").status_code == 401
                endpoint = urls[0] + "/v1/decisions/evaluate"
                response = client.post(endpoint, headers=headers, json={})
                response.raise_for_status()
                decision = response.json()
                assert decision["status"] == "EVALUATED"
                assert not decision["approved_actions"]
                approval = {
                    "approval": {
                        "decision_id": decision["decision_id"],
                        "reason": "synthetic standalone approval",
                    }
                }
                assert (
                    client.post(
                        endpoint,
                        json=approval,
                        headers={
                            "X-API-Key": env["TWIN_API_KEY"],
                        },
                    ).status_code
                    == 403
                )
                response = client.post(endpoint, headers=headers, json=approval)
                response.raise_for_status()
                assert response.json()["status"] == "APPROVED"
                assert response.json()["execution_enabled"] is False
                assert client.post(endpoint, json={}).status_code == 401
                execution = client.post(
                    urls[0] + "/v1/actions/execute",
                    headers=headers,
                    json={"decision_id": decision["decision_id"]},
                )
                execution.raise_for_status()
                command_id = execution.json()["commands"][0]["command_id"]
                for _ in range(100):
                    action = client.get(
                        urls[0] + f"/v1/actions/{command_id}",
                        headers=headers,
                    )
                    action.raise_for_status()
                    if action.json()["status"] == "EXECUTED":
                        assert action.json()["execution"]["feedback_status"] == "executed"
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError("simulated actuator execution was not confirmed")
                assert (
                    client.post(
                        urls[0] + "/v1/actions/execute",
                        json={"decision_id": decision["decision_id"]},
                    ).status_code
                    == 401
                )
        finally:
            for process in processes:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                else:
                    process.terminate()
            for process in processes:
                process.wait(timeout=10)


if __name__ == "__main__":
    main()
