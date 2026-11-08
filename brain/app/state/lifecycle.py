from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, literal_column, select
from sqlalchemy.orm import Session

from app.database.models import AuditEvent, EventLifecycle

FINAL_STATES = {"TRUSTED", "UNTRUSTED", "UNCERTAIN", "EXPIRED"}


def utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def audit(
    session: Session,
    event_id: UUID,
    correlation_id: UUID,
    action: str,
    detail: dict,
    now: datetime,
    actor: str = "trust-engine",
) -> None:
    if session.bind is not None and session.bind.dialect.name == "sqlite":
        # SQLite only matches the ix_audit_events_event_id_json expression index
        # when the JSON path is a literal in the SQL text, not a bound parameter.
        event_id_expr = func.json_extract(
            AuditEvent.payload,
            literal_column("'$.\"event_id\"'"),
        )
    else:
        # Portable JSON accessor (works on PostgreSQL and other dialects).
        event_id_expr = AuditEvent.payload["event_id"].as_string()
    sequence = (
        session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(event_id_expr == str(event_id))
        )
        + 1
    )
    session.add(
        AuditEvent(
            correlation_id=correlation_id,
            occurred_at=now,
            actor=actor,
            action=action,
            payload={"event_id": str(event_id), "sequence": sequence, **detail},
        )
    )


def transition(
    session: Session,
    row: EventLifecycle,
    correlation_id: UUID,
    target: str,
    reason: str,
    now: datetime,
) -> None:
    previous = row.state
    if target == previous:
        row.reason = reason
        return
    allowed = (
        (previous == "RECEIVED" and target == "VALIDATED")
        or (previous == "VALIDATED" and target == "PENDING_VERDICT")
        or (previous == "PENDING_VERDICT" and target in FINAL_STATES)
        or (previous in FINAL_STATES and target == "PENDING_VERDICT")
    )
    if not allowed:
        raise ValueError(f"invalid lifecycle transition: {previous} -> {target}")
    row.state, row.reason = target, reason
    audit(
        session,
        row.event_id,
        correlation_id,
        "state_transition",
        {"from": previous, "to": target, "reason": reason},
        now,
    )


def enqueue(
    session: Session,
    row: EventLifecycle,
    correlation_id: UUID,
    now: datetime,
) -> None:
    row.eligible = False
    row.eligible_until = None
    row.processing, row.available_at, row.attempts = "queued", now, 0
    row.acknowledged_at = None
    if row.state in FINAL_STATES:
        transition(session, row, correlation_id, "PENDING_VERDICT", "evidence_changed", now)
