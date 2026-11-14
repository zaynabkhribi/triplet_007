from datetime import datetime

from app.decision.config import DecisionPolicies
from app.decision.priority_engine import priority
from app.intelligence.incident_rules import SEVERITIES


def candidates(
    incidents: list[dict],
    policy: DecisionPolicies,
    quarantines: set[str],
    now: datetime,
) -> tuple[list[dict], list[dict]]:
    accepted, rejected = [], []
    for incident in incidents:
        for action in policy.actions:
            if incident["incident_type"] not in action.incident_types:
                continue
            reason = None
            actuator = policy.actuators[action.actuator_id]
            capability = actuator.capabilities.get(action.action_type)
            score = priority(action, incident, policy.optimization)
            if incident["zone_id"] not in action.zones or actuator.zone != incident["zone_id"]:
                reason = "zone_restriction"
            elif SEVERITIES.index(incident["severity"]) < SEVERITIES.index(action.minimum_severity):
                reason = "severity_below_policy"
            elif (
                incident["classification"] == "early_warning" and not action.allow_forecast_warning
            ):
                reason = "forecast_response_not_authorized"
            elif action.actuator_id in quarantines:
                reason = "actuator_quarantined"
            elif not actuator.current(now):
                reason = "actuator_availability_unverified"
            elif (
                capability is None
                or set(capability) != set(action.parameters)
                or any(
                    not capability[name].accepts(value)
                    for name, value in action.parameters.items()
                )
            ):
                reason = "actuator_capability_violation"
            elif any(
                not policy.resources[name].current(now)
                or incident["zone_id"] not in policy.resources[name].zones
                or amount > policy.resources[name].capacity
                for name, amount in action.resources.items()
            ):
                reason = "resource_unavailable"
            elif score is None or score <= 0:
                reason = "priority_missing_or_nonpositive"
            candidate = {
                **action.model_dump(),
                "incident_id": incident["incident_id"],
                "zone_id": incident["zone_id"],
                "score": score,
                "candidate_id": f"{incident['incident_id']}:{action.id}",
            }
            if reason:
                rejected.append({"candidate": candidate, "reason": reason})
            else:
                accepted.append(candidate)
    return sorted(accepted, key=lambda item: item["candidate_id"]), rejected
