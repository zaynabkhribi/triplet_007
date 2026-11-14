from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class EventRecord:
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    correlation_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class SensorEvent(EventRecord, Base):
    __tablename__ = "sensor_events"
    __table_args__ = (
        Index("ix_sensor_events_sensor_time_id", "sensor_id", "occurred_at", "id"),
    )

    sensor_id: Mapped[str] = mapped_column(String(128), index=True)


class GuardianVerdictRecord(EventRecord, Base):
    __tablename__ = "guardian_verdicts"

    event_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    status: Mapped[str] = mapped_column(String(32))


class CityStateRecord(EventRecord, Base):
    __tablename__ = "city_states"


class IncidentRecord(EventRecord, Base):
    __tablename__ = "incidents"

    severity: Mapped[str] = mapped_column(String(32), index=True)


class DecisionRecord(EventRecord, Base):
    __tablename__ = "decisions"

    status: Mapped[str] = mapped_column(String(32), index=True)


class ActuatorCommandRecord(EventRecord, Base):
    __tablename__ = "actuator_commands"

    actuator_id: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")


class ActuatorFeedbackRecord(EventRecord, Base):
    __tablename__ = "actuator_feedback"

    command_id: Mapped[UUID] = mapped_column(Uuid, index=True)
    status: Mapped[str] = mapped_column(String(32))


class AuditEvent(EventRecord, Base):
    __tablename__ = "audit_events"

    actor: Mapped[str] = mapped_column(String(128), index=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    detail: Mapped[str] = mapped_column(Text, default="")


class EventLifecycle(Base):
    __tablename__ = "event_lifecycle"

    event_id: Mapped[UUID] = mapped_column(ForeignKey("sensor_events.id"), primary_key=True)
    state: Mapped[str] = mapped_column(String(32), default="RECEIVED")
    processing: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    available_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    eligible: Mapped[bool] = mapped_column(Boolean, default=False)
    eligible_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verdict_id: Mapped[UUID | None] = mapped_column(Uuid)
    reason: Mapped[str] = mapped_column(String(128), default="received")
    last_error: Mapped[str | None] = mapped_column(String(128))


class QuarantineRecord(EventRecord, Base):
    __tablename__ = "quarantine_notifications"

    target_type: Mapped[str] = mapped_column(String(32), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)


class CityRegistryRecord(Base):
    __tablename__ = "city_registry"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class CitySnapshot(Base):
    __tablename__ = "city_snapshots"
    version: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class ForecastRecord(EventRecord, Base):
    __tablename__ = "forecasts"
    family: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)


class IncidentRevision(Base):
    __tablename__ = "incident_revisions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[UUID] = mapped_column(ForeignKey("incidents.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class DecisionRevision(Base):
    __tablename__ = "decision_revisions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    decision_id: Mapped[UUID] = mapped_column(ForeignKey("decisions.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class CommandRevision(Base):
    __tablename__ = "command_revisions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    command_id: Mapped[UUID] = mapped_column(ForeignKey("actuator_commands.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class ScenarioExecution(EventRecord, Base):
    __tablename__ = "scenario_executions"
    scenario_id: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)


class ScenarioLog(Base):
    __tablename__ = "scenario_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    execution_id: Mapped[UUID] = mapped_column(ForeignKey("scenario_executions.id"), index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    stage: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON)
