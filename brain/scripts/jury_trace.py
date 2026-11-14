"""Read-only jury trace for a persisted mock incident-to-execution lifecycle."""

import argparse
import json
import sqlite3
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]


def stored(identifier: str) -> str:
    return UUID(identifier).hex


def row_json(row, field="payload"):
    return json.loads(row[field]) if row and row[field] else {}


def add(stages, stage, status, at=None, **identifiers):
    stages.append(
        {
            "stage": stage,
            "status": status,
            "timestamp": at,
            **{key: value for key, value in identifiers.items() if value is not None},
        }
    )


def build_trace(database: Path) -> dict:
    uri = f"file:{database.as_posix()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    commands = connection.execute(
        "SELECT * FROM actuator_commands WHERE status='EXECUTED' "
        "ORDER BY occurred_at DESC"
    ).fetchall()
    selected = incident = None
    for command in commands:
        payload = row_json(command)
        incident_id = payload.get("candidate", {}).get("incident_id")
        if not incident_id:
            continue
        candidate = connection.execute(
            "SELECT * FROM incidents WHERE id=?", (stored(incident_id),)
        ).fetchone()
        if candidate is None or not row_json(candidate).get("simulation_only"):
            continue
        recovery = connection.execute(
            "SELECT * FROM incident_revisions WHERE incident_id=? "
            "AND json_extract(payload, '$.status')='RESOLVED' "
            "ORDER BY created_at DESC LIMIT 1",
            (stored(incident_id),),
        ).fetchone()
        if recovery is not None:
            selected, incident = command, candidate
            break
    if selected is None or incident is None:
        raise RuntimeError("no completed mock pipeline with incident recovery was found")

    command_payload = row_json(selected)
    command = command_payload["command"]
    incident_payload = row_json(incident)
    decision_id = command["decision_id"]
    incident_id = command_payload["candidate"]["incident_id"]
    command_id = command["command_id"]
    stages = []

    incident_revisions = connection.execute(
        "SELECT * FROM incident_revisions WHERE incident_id=? ORDER BY created_at",
        (stored(incident_id),),
    ).fetchall()
    detected = next(
        (
            row
            for row in incident_revisions
            if row_json(row).get("status") in {"DETECTED", "ACTIVE"}
        ),
        None,
    )
    detection_payload = row_json(detected)
    evidence = [
        reference
        for signal in detection_payload.get("signals", [])
        for reference in signal.get("evidence", [])
    ]
    event_id = evidence[-1]["event_id"] if evidence else None
    event = (
        connection.execute("SELECT * FROM sensor_events WHERE id=?", (stored(event_id),)).fetchone()
        if event_id
        else None
    )
    event_payload = row_json(event).get("event", {}) if event else {}
    add(
        stages,
        "observation_received",
        "confirmed" if event else "missing",
        event["occurred_at"] if event else None,
        event_id=event_id,
        correlation_id=event_payload.get("correlation_id"),
        sensor_id=event_payload.get("sensor_id"),
    )

    verdict = (
        connection.execute(
            "SELECT * FROM guardian_verdicts WHERE event_id=? "
            "ORDER BY occurred_at DESC LIMIT 1",
            (stored(event_id),),
        ).fetchone()
        if event_id
        else None
    )
    verdict_payload = row_json(verdict).get("event", {}) if verdict else {}
    add(
        stages,
        "guardian_evidence",
        verdict_payload.get("status", "missing"),
        verdict["occurred_at"] if verdict else None,
        event_id=event_id,
        verdict_id=verdict_payload.get("verdict_id"),
    )

    trust_audit = (
        connection.execute(
            "SELECT * FROM audit_events WHERE action='event_acknowledged' "
            "AND json_extract(payload, '$.event_id')=? "
            "AND json_extract(payload, '$.state')='TRUSTED' "
            "ORDER BY occurred_at LIMIT 1",
            (event_id,),
        ).fetchone()
        if event_id
        else None
    )
    add(
        stages,
        "trusted_city_state",
        "TRUSTED" if trust_audit else "missing",
        trust_audit["occurred_at"] if trust_audit else None,
        event_id=event_id,
        verdict_id=verdict_payload.get("verdict_id"),
    )

    add(
        stages,
        "incident_detected",
        row_json(detected).get("status", "missing"),
        detected["created_at"] if detected else None,
        incident_id=incident_id,
        zone_id=incident_payload.get("zone_id"),
        severity=incident_payload.get("severity"),
    )

    revisions = connection.execute(
        "SELECT * FROM decision_revisions WHERE decision_id=? ORDER BY created_at",
        (stored(decision_id),),
    ).fetchall()
    evaluated = next(
        (row for row in revisions if row_json(row).get("status") == "EVALUATED"), None
    )
    evaluated_payload = row_json(evaluated)
    add(
        stages,
        "or_tools_decision",
        evaluated_payload.get("reason", "missing"),
        evaluated["created_at"] if evaluated else None,
        decision_id=decision_id,
        incident_id=incident_id,
    )
    add(
        stages,
        "safety_shield",
        "validated" if evaluated_payload.get("reason") == "optimal_verified" else "missing",
        evaluated["created_at"] if evaluated else None,
        decision_id=decision_id,
    )
    approved = next(
        (row for row in revisions if row_json(row).get("status") == "APPROVED"), None
    )
    approved_payload = row_json(approved)
    add(
        stages,
        "human_approval",
        "recorded" if approved_payload.get("approval") else "missing",
        approved["created_at"] if approved else None,
        decision_id=decision_id,
        actor=approved_payload.get("approval", {}).get("actor"),
    )

    command_revisions = connection.execute(
        "SELECT * FROM command_revisions WHERE command_id=? ORDER BY created_at",
        (stored(command_id),),
    ).fetchall()
    for status, stage in (
        ("PENDING", "command_enqueued"),
        ("DISPATCHING", "command_delivered"),
    ):
        revision = next(
            (row for row in command_revisions if row_json(row).get("status") == status), None
        )
        add(
            stages,
            stage,
            "confirmed" if revision else "missing",
            revision["created_at"] if revision else None,
            command_id=command_id,
            actuator_id=command.get("actuator_id"),
        )

    feedback = connection.execute(
        "SELECT * FROM actuator_feedback WHERE command_id=? "
        "ORDER BY occurred_at DESC LIMIT 1",
        (stored(command_id),),
    ).fetchone()
    feedback_payload = row_json(feedback).get("event", {}) if feedback else {}
    add(
        stages,
        "mock_twin_feedback",
        feedback_payload.get("status", "missing"),
        feedback["occurred_at"] if feedback else None,
        command_id=command_id,
        feedback_id=feedback_payload.get("feedback_id"),
    )
    executed = next(
        (
            row
            for row in command_revisions
            if row_json(row).get("status") == "EXECUTED"
        ),
        None,
    )
    add(
        stages,
        "execution_confirmed",
        "confirmed" if executed else "missing",
        executed["created_at"] if executed else None,
        command_id=command_id,
        actuator_id=command.get("actuator_id"),
    )

    recovery = next(
        (row for row in reversed(incident_revisions) if row_json(row).get("status") == "RESOLVED"),
        None,
    )
    add(
        stages,
        "incident_recovery",
        "confirmed" if recovery else "missing",
        recovery["created_at"] if recovery else None,
        incident_id=incident_id,
        resolution=row_json(recovery).get("resolution") if recovery else None,
    )
    connection.close()
    return {
        "execution_mode": "mock",
        "database": database.name,
        "incident_id": incident_id,
        "decision_id": decision_id,
        "command_id": command_id,
        "stages": stages,
        "complete": all(stage["status"] != "missing" for stage in stages),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["mock"], required=True)
    parser.add_argument("--latest", action="store_true", required=True)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--database", type=Path, default=ROOT / "mock_integration.db")
    args = parser.parse_args()
    trace = build_trace(args.database.resolve())
    if args.json:
        print(json.dumps(trace, indent=2))
        return
    print("AEGISCITY JURY TRACE - persisted MOCK execution")
    print(f"Incident {trace['incident_id']}")
    print(f"Decision {trace['decision_id']}")
    print(f"Command  {trace['command_id']}")
    print()
    for index, stage in enumerate(trace["stages"], 1):
        timestamp = stage.get("timestamp") or "timestamp unavailable"
        identifiers = " ".join(
            f"{key}={value}"
            for key, value in stage.items()
            if key not in {"stage", "status", "timestamp"}
        )
        print(
            f"{index:02d}. {stage['stage']:<24} {stage['status']:<12} "
            f"{timestamp} {identifiers}".rstrip()
        )
    print(f"\nTrace complete: {'YES' if trace['complete'] else 'NO'}")


if __name__ == "__main__":
    main()
