from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.models import EventLifecycle, GuardianVerdictRecord, QuarantineRecord, SensorEvent
from app.schemas.guardian import GuardianVerdict
from app.schemas.sensor import SensorReading
from app.security.event_hash import event_hash
from app.state.lifecycle import utc


@dataclass(frozen=True)
class TrustResult:
    state: str
    reason: str
    deadline: datetime | None = None
    verdict_id: UUID | None = None


def quarantined(session: Session, target_type: str, target_id: str) -> bool:
    records = session.scalars(
        select(QuarantineRecord).where(
            QuarantineRecord.target_type == target_type,
            QuarantineRecord.target_id == target_id,
        )
    ).all()
    if not records:
        return False

    def rank(record: QuarantineRecord) -> tuple[int, datetime]:
        return record.payload["event"]["revision"], utc(record.occurred_at)

    latest = max(rank(record) for record in records)
    return any(
        record.payload["event"]["action"] == "quarantine"
        for record in records
        if rank(record) == latest
    )


class TrustEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def evaluate(
        self,
        session: Session,
        reading: SensorEvent,
        row: EventLifecycle,
        now: datetime,
        verdict_records: list[GuardianVerdictRecord] | None = None,
        sensor_quarantined: bool | None = None,
    ) -> TrustResult:
        event = SensorReading.model_validate(reading.payload["event"])
        digest = event_hash(event)
        if digest != reading.payload["sha256"]:
            return TrustResult("UNCERTAIN", "stored_hash_mismatch")
        deadline = event.occurred_at + timedelta(seconds=self.settings.event_freshness_seconds)
        if now >= deadline:
            return TrustResult("EXPIRED", "event_expired")
        if event.occurred_at > now:
            return TrustResult("UNCERTAIN", "event_not_yet_valid", event.occurred_at)
        if (
            sensor_quarantined
            if sensor_quarantined is not None
            else quarantined(
                session,
                "sensor",
                event.sensor_id,
            )
        ):
            return TrustResult("UNTRUSTED", "sensor_quarantined", deadline)
        records = (
            verdict_records
            if verdict_records is not None
            else session.scalars(
                select(GuardianVerdictRecord).where(
                    GuardianVerdictRecord.event_id == event.event_id,
                )
            ).all()
        )
        if not records:
            wait_until = min(
                deadline,
                utc(row.received_at)
                + timedelta(
                    seconds=self.settings.verdict_timeout_seconds,
                ),
            )
            if now >= wait_until:
                return TrustResult("EXPIRED", "verdict_missing")
            return TrustResult("PENDING_VERDICT", "awaiting_guardian", wait_until)
        verdicts = [GuardianVerdict.model_validate(record.payload["event"]) for record in records]

        def rank(verdict: GuardianVerdict) -> tuple[int, datetime]:
            return verdict.revision, verdict.issued_at

        latest_rank = max(rank(verdict) for verdict in verdicts)
        latest = [verdict for verdict in verdicts if rank(verdict) == latest_rank]
        if len(latest) != 1:
            return TrustResult("UNCERTAIN", "conflicting_verdicts", deadline)
        verdict = latest[0]
        if (
            verdict.event_hash != digest
            or verdict.correlation_id != event.correlation_id
            or verdict.guardian_id != self.settings.guardian_identity
        ):
            return TrustResult(
                "UNCERTAIN", "verdict_binding_mismatch", deadline, verdict.verdict_id
            )
        if verdict.issued_at > now:
            return TrustResult(
                "UNCERTAIN",
                "verdict_not_yet_valid",
                min(deadline, verdict.issued_at),
                verdict.verdict_id,
            )
        if verdict.status.value == "revoked":
            return TrustResult("UNTRUSTED", "verdict_revoked", deadline, verdict.verdict_id)
        deadline = min(
            deadline,
            verdict.expires_at
            or (verdict.issued_at + timedelta(seconds=self.settings.verdict_ttl_seconds)),
        )
        if now >= deadline:
            return TrustResult("EXPIRED", "verdict_expired", verdict_id=verdict.verdict_id)
        state = {"trusted": "TRUSTED", "rejected": "UNTRUSTED", "unknown": "UNCERTAIN"}
        return TrustResult(
            state[verdict.status.value], "guardian_verdict", deadline, verdict.verdict_id
        )
