"""Verify the running isolated mock stack through the dashboard operator APIs."""

import json
import time

import httpx
from mock_runtime import load

BASE = "http://127.0.0.1:8001"


def wait_for(client, predicate, timeout=45):
    deadline = time.monotonic() + timeout
    latest = None
    while time.monotonic() < deadline:
        latest = client.get("/dashboard/api/snapshot").json()
        if predicate(latest):
            return latest
        time.sleep(0.5)
    raise RuntimeError("mock pipeline state timeout")


def main() -> None:
    key = load()["keys"]["brain"]
    with httpx.Client(base_url=BASE, timeout=10, trust_env=False) as client:
        login = client.post("/dashboard/session", headers={"X-API-Key": key}, json={})
        login.raise_for_status()
        operator = {"X-Dashboard-CSRF": login.json()["csrf"]}
        client.post("/dashboard/api/operations/reset", headers=operator, json={}).raise_for_status()
        client.post("/dashboard/api/operations/start", headers=operator, json={}).raise_for_status()
        normal = wait_for(
            client,
            lambda state: state["metrics"]["eligible_sensors"] >= 8
            and state["metrics"]["active_incidents"] == 0,
            timeout=60,
        )
        client.post(
            "/dashboard/api/operations/inject",
            headers=operator,
            json={"injection": "fire"},
        ).raise_for_status()
        incident = wait_for(
            client,
            lambda state: any(
                item["incident_type"] == "smoke_alert"
                and item["status"] in {"ACTIVE", "ESCALATED"}
                for item in state["incidents"]
            ),
        )
        incident_id = next(
            item["id"]
            for item in incident["incidents"]
            if item["incident_type"] == "smoke_alert"
            and item["status"] in {"ACTIVE", "ESCALATED"}
        )
        # Freeze observations so the explicitly approved decision fingerprint
        # remains stable through the separate enqueue request. This preserves
        # Safety Shield revalidation instead of weakening it for a demo.
        client.post(
            "/dashboard/api/operations/stop", headers=operator, json={}
        ).raise_for_status()
        # Let any already-started publication finish before fingerprinting.
        time.sleep(2)
        evaluated = client.post(
            "/dashboard/api/decisions/evaluate", headers=operator, json={}
        )
        evaluated.raise_for_status()
        decision = evaluated.json()
        if decision["status"] != "EVALUATED" or decision["reason"] != "optimal_verified":
            raise RuntimeError("optimizer did not return an evaluated optimal decision")
        approved = client.post(
            f"/dashboard/api/decisions/{decision['decision_id']}/approve",
            headers=operator,
            json={"reason": "Approved isolated mock pipeline verification"},
        )
        approved.raise_for_status()
        if approved.json()["status"] != "APPROVED":
            raise RuntimeError("explicit mock approval failed")
        execution = client.post(
            f"/dashboard/api/decisions/{decision['decision_id']}/execute",
            headers=operator,
            json={},
        )
        execution.raise_for_status()
        command_id = execution.json()["commands"][0]["command_id"]
        executed = wait_for(
            client,
            lambda state: any(
                item["command_id"] == command_id and item["status"] == "EXECUTED"
                for item in state["actions"]
            ),
        )
        client.post(
            "/dashboard/api/operations/start", headers=operator, json={}
        ).raise_for_status()
        recovered = wait_for(
            client,
            lambda state: any(
                item["id"] == incident_id and item["status"] == "RESOLVED"
                for item in state["incidents"]
            ),
            timeout=60,
        )
        client.post(
            "/dashboard/api/operations/stop", headers=operator, json={}
        ).raise_for_status()
    result = {
        "mode": executed["security"]["mode"],
        "normal_eligible_sensors": normal["metrics"]["eligible_sensors"],
        "incident": next(
            item["status"]
            for item in incident["incidents"]
            if item["incident_type"] == "smoke_alert"
        ),
        "decision": decision["reason"],
        "approval": approved.json()["status"],
        "command_id": command_id,
        "execution": "EXECUTED",
        "recovery": next(
            item["status"]
            for item in recovered["incidents"]
            if item["id"] == incident_id
        ),
        "trusted_readings": executed["metrics"]["trusted_readings"],
        "dashboard_executed_commands": executed["metrics"]["executed_commands"],
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
