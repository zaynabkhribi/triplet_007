from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.models import SensorEvent
from app.intelligence.incident_detector import forecast_signals
from app.intelligence.incident_rules import IncidentRule
from app.intelligence.inference import currently_eligible
from app.state.lifecycle import utc


def eligible_incident(
    session: Session,
    settings: Settings,
    incident: dict,
    state: dict,
    now: datetime,
    passport_eligibility=None,
) -> bool:
    if incident["status"] not in {"ACTIVE", "ESCALATED"} or not incident["evidence_eligible"]:
        return False
    evidence = {
        item["event_id"]: item for signal in incident["signals"] for item in signal["evidence"]
    }
    registry = state["registry"]
    if incident["classification"] == "early_warning":
        rule = IncidentRule.model_validate(incident["rule"])
        current = forecast_signals(session, settings, state, rule, now)
        forecast_ids = {identifier for signal in current for identifier in signal["forecast_ids"]}
        if any(
            identifier not in forecast_ids
            for signal in incident["signals"]
            for identifier in signal["forecast_ids"]
        ):
            return False
    else:
        cutoff = now - timedelta(
            seconds=min(registry["window_seconds"], incident["rule"]["window_seconds"])
        )
        for identifier in evidence:
            event = session.get(SensorEvent, UUID(identifier))
            if event is None or utc(event.occurred_at) < cutoff:
                return False
    return currently_eligible(
        session,
        settings,
        {
            "evidence": list(evidence.values()),
            "sensor_mappings": registry["sensors"],
        },
        now,
        passport_eligibility=passport_eligibility,
    )
