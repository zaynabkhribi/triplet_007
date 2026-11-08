from app.decision.config import ActionPolicy, Optimization
from app.schemas.incident import CityIncident, IncidentSeverity


class PriorityEngine:
    _rank = {
        IncidentSeverity.LOW: 0,
        IncidentSeverity.MEDIUM: 1,
        IncidentSeverity.HIGH: 2,
        IncidentSeverity.CRITICAL: 3,
    }

    def order(self, incidents: list[CityIncident]) -> list[CityIncident]:
        return sorted(incidents, key=lambda item: self._rank[item.severity], reverse=True)


def priority(action: ActionPolicy, incident: dict, config: Optimization) -> int | None:
    severity = config.severity_weights.get(incident["severity"])
    urgency = config.urgency_weights.get(incident["incident_type"])
    zone = config.zone_weights.get(incident["zone_id"])
    if severity is None or urgency is None or zone is None:
        return None
    return severity + urgency + zone + action.benefit - action.cost * config.cost_weight
