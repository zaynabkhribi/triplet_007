from datetime import UTC, datetime
from uuid import UUID

from fastapi import HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.database.base import Base
from app.database.models import (
    CityRegistryRecord,
    EventLifecycle,
    GuardianVerdictRecord,
    QuarantineRecord,
    SensorEvent,
)
from app.schemas.guardian import GuardianVerdict, QuarantineNotification
from app.schemas.sensor import SensorReading
from app.security.event_hash import event_hash
from app.security.validation import require_reasonable_timestamp
from app.state.lifecycle import audit, enqueue


def persist(
    request: Request,
    event: BaseModel,
    record_type: type[Base],
    record_id: UUID,
    timestamp: datetime,
    **fields: object,
) -> dict[str, str]:
    require_reasonable_timestamp(timestamp, request.app.state.settings.replay_window_seconds)
    digest = event_hash(event)
    now = datetime.now(UTC)
    settings = request.app.state.settings
    if (
        isinstance(event, (GuardianVerdict, QuarantineNotification))
        and event.guardian_id != settings.guardian_identity
    ):
        raise HTTPException(403, "Guardian identity does not match authenticated service")
    if isinstance(event, QuarantineNotification) and event.issued_at > now:
        raise HTTPException(422, "quarantine notifications cannot be future dated")
    with request.app.state.database.transaction() as session:
        if record_type is SensorEvent:
            registry = session.get(CityRegistryRecord, 1)
            definitions = registry.payload["sensors"] if registry else []
            configured = next(
                (item for item in definitions if item["sensor_id"] == event.sensor_id), None
            )
            if configured is not None and (
                event.sensor_type != configured["measurement"]
                or event.unit != configured["unit"]
                or event.attributes.get("zone_id", configured["zone_id"]) != configured["zone_id"]
            ):
                raise HTTPException(422, "reading does not match registered sensor metadata")
        if session.get(record_type, record_id) is not None:
            raise HTTPException(409, "duplicate event ID")
        if isinstance(event, GuardianVerdict):
            reading = session.get(SensorEvent, event.event_id)
            if reading is not None and (
                reading.correlation_id != event.correlation_id
                or reading.payload["sha256"] != event.event_hash
            ):
                raise HTTPException(409, "verdict does not match sensor event")
        session.add(
            record_type(
                id=record_id,
                correlation_id=event.correlation_id,
                occurred_at=timestamp,
                payload={"event": event.model_dump(mode="json"), "sha256": digest},
                **fields,
            )
        )
        try:
            session.flush()
        except IntegrityError as exc:
            raise HTTPException(409, "conflicting event") from exc
        if record_type is SensorEvent:
            session.add(
                EventLifecycle(
                    event_id=record_id,
                    received_at=now,
                    available_at=now,
                    state="RECEIVED",
                    processing="queued",
                    eligible=False,
                    attempts=0,
                )
            )
        elif record_type is GuardianVerdictRecord:
            row = session.get(EventLifecycle, event.event_id)
            if row is not None:
                enqueue(session, row, event.correlation_id, now)
        elif record_type is QuarantineRecord and event.target_type == "sensor":
            rows = session.execute(
                select(EventLifecycle, SensorEvent)
                .join(
                    SensorEvent,
                    EventLifecycle.event_id == SensorEvent.id,
                )
                .where(SensorEvent.sensor_id == event.target_id)
            ).all()
            for row, reading in rows:
                enqueue(session, row, reading.correlation_id, now)
        actor = (
            "guardian" if isinstance(event, (GuardianVerdict, QuarantineNotification)) else "twin"
        )
        audit(
            session,
            event.event_id if isinstance(event, GuardianVerdict) else record_id,
            event.correlation_id,
            "event_received",
            {
                "record_type": record_type.__tablename__,
                "record_id": str(record_id),
                "sha256": digest,
            },
            now,
            actor,
        )
    return {"status": "stored", "event_id": str(record_id), "sha256": digest}


def persist_batch(
    request: Request,
    events: list[SensorReading] | list[GuardianVerdict],
) -> list[dict[str, str]]:
    if not events:
        raise HTTPException(422, "event batch cannot be empty")
    if len(events) > request.app.state.settings.worker_batch_size:
        raise HTTPException(422, "event batch exceeds worker capacity")
    now = datetime.now(UTC)
    settings = request.app.state.settings
    results = []
    with request.app.state.database.transaction() as session:
        registry = session.get(CityRegistryRecord, 1)
        definitions = registry.payload["sensors"] if registry else []
        for event in events:
            timestamp = event.occurred_at if isinstance(event, SensorReading) else event.issued_at
            require_reasonable_timestamp(timestamp, settings.replay_window_seconds)
            record_type = SensorEvent if isinstance(event, SensorReading) else GuardianVerdictRecord
            record_id = event.event_id if isinstance(event, SensorReading) else event.verdict_id
            if session.get(record_type, record_id) is not None:
                raise HTTPException(409, "duplicate event ID")
            if isinstance(event, SensorReading):
                configured = next(
                    (item for item in definitions if item["sensor_id"] == event.sensor_id), None
                )
                if configured is not None and (
                    event.sensor_type != configured["measurement"]
                    or event.unit != configured["unit"]
                    or event.attributes.get("zone_id", configured["zone_id"])
                    != configured["zone_id"]
                ):
                    raise HTTPException(422, "reading does not match registered sensor metadata")
                fields = {"sensor_id": event.sensor_id}
            else:
                if event.guardian_id != settings.guardian_identity:
                    raise HTTPException(
                        403, "Guardian identity does not match authenticated service"
                    )
                reading = session.get(SensorEvent, event.event_id)
                if reading is not None and (
                    reading.correlation_id != event.correlation_id
                    or reading.payload["sha256"] != event.event_hash
                ):
                    raise HTTPException(409, "verdict does not match sensor event")
                fields = {"event_id": event.event_id, "status": event.status.value}
            digest = event_hash(event)
            session.add(
                record_type(
                    id=record_id,
                    correlation_id=event.correlation_id,
                    occurred_at=timestamp,
                    payload={"event": event.model_dump(mode="json"), "sha256": digest},
                    **fields,
                )
            )
            session.flush()
            if isinstance(event, SensorReading):
                session.add(
                    EventLifecycle(
                        event_id=record_id,
                        received_at=now,
                        available_at=now,
                        state="RECEIVED",
                        processing="queued",
                        eligible=False,
                        attempts=0,
                    )
                )
                actor = "twin"
            else:
                row = session.get(EventLifecycle, event.event_id)
                if row is not None:
                    enqueue(session, row, event.correlation_id, now)
                actor = "guardian"
            audit(
                session,
                event.event_id,
                event.correlation_id,
                "event_received",
                {
                    "record_type": record_type.__tablename__,
                    "record_id": str(record_id),
                    "sha256": digest,
                },
                now,
                actor,
            )
            results.append({"status": "stored", "event_id": str(record_id), "sha256": digest})
    return results
