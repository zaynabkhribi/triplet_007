from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.models import DecisionRecord, DecisionRevision, IncidentRecord
from app.decision.config import digest, load_policy
from app.decision.optimizer import optimize, verify
from app.decision.policy_engine import candidates
from app.decision.safety_shield import eligible_incident
from app.intelligence.incident_rules import IncidentRules
from app.security.trust_engine import quarantined
from app.state.lifecycle import audit, utc


def serialize(row: DecisionRecord) -> dict:
    return {
        "decision_id": str(row.id),
        "correlation_id": str(row.correlation_id),
        "created_at": utc(row.occurred_at).isoformat(),
        "status": row.status,
        **row.payload,
    }


class DecisionEngine:
    def __init__(self, settings: Settings, incident_rules: IncidentRules) -> None:
        self.settings, self.incident_rules = settings, incident_rules
        self.policy, self.error = load_policy(settings.decision_policy_file)
        # Task 7.3G-7: optional passport eligibility index, injected by
        # CityEngine (disabled by default; None means durable-verdict mode).
        self.passport_eligibility = None  # injected by CityEngine

    def context(self, session: Session, state: dict, now: datetime) -> dict:
        incidents = [
            {"incident_id": str(row.id), **row.payload}
            for row in session.scalars(
                select(IncidentRecord)
                .where(
                    IncidentRecord.payload["status"].as_string().in_(["ACTIVE", "ESCALATED"]),
                )
                .order_by(IncidentRecord.id)
            )
        ]
        eligible = [
            incident
            for incident in incidents
            if eligible_incident(
                session,
                self.settings,
                incident,
                state,
                now,
                passport_eligibility=getattr(self, "passport_eligibility", None),
            )
        ]
        policy = self.policy
        rule_hash = digest(self.incident_rules.model_dump())
        blocked = self.error
        if policy:
            if not policy.approved or not policy.approval_reference.strip():
                blocked = "policy_not_approved"
            elif (
                policy.approved_incident_config_sha256 != rule_hash or not self.incident_rules.rules
            ):
                blocked = "incident_thresholds_not_approved"
            elif policy.simulation_only and self.settings.environment.lower() == "production":
                blocked = "simulation_policy_in_production"
            elif self.incident_rules.simulation_only and not policy.simulation_only:
                blocked = "simulation_incidents_require_simulation_policy"
        quarantines = (
            sorted(sid for sid in policy.actuators if quarantined(session, "actuator", sid))
            if policy
            else []
        )
        availability = (
            {
                "resources": {key: value.current(now) for key, value in policy.resources.items()},
                "actuators": {key: value.current(now) for key, value in policy.actuators.items()},
            }
            if policy
            else {}
        )
        inputs = {
            "city_version": state["version"],
            "incidents": eligible,
            "excluded_incident_ids": [i["incident_id"] for i in incidents if i not in eligible],
            "policy": policy.model_dump(mode="json") if policy else None,
            "incident_config_sha256": rule_hash,
            "blocked": blocked,
            "quarantined_actuators": quarantines,
            "availability": availability,
        }
        decision_inputs = {key: value for key, value in inputs.items() if key != "city_version"}
        return inputs | {"fingerprint": digest(decision_inputs)}

    def invalidate(self, session: Session, state: dict, now: datetime) -> None:
        rows = session.scalars(
            select(DecisionRecord).where(
                DecisionRecord.status.in_(["PROPOSED", "EVALUATED", "APPROVED"]),
            )
        ).all()
        if not rows:
            return
        current = self.context(session, state, now)
        for row in rows:
            if row.payload.get("fingerprint") != current["fingerprint"]:
                self._transition(
                    session,
                    row,
                    "CANCELLED",
                    {
                        "outcome": "NO_ACTION",
                        "approved_actions": [],
                        "reason": "inputs_or_authorization_changed",
                    },
                    now,
                )

    def evaluate(
        self,
        session: Session,
        state: dict,
        correlation_id: UUID,
        approval_id: UUID | None = None,
        approval_reason: str | None = None,
    ) -> tuple[int, dict]:
        now = datetime.now(UTC)
        context = self.context(session, state, now)
        existing = session.scalar(
            select(DecisionRecord)
            .where(
                DecisionRecord.payload["fingerprint"].as_string() == context["fingerprint"],
                DecisionRecord.status != "CANCELLED",
            )
            .order_by(DecisionRecord.occurred_at.desc())
            .limit(1)
        )
        if approval_id is not None:
            if not approval_reason or not approval_reason.strip():
                return 409, {"reason": "approval_reason_required"}
            if (
                existing is not None
                and existing.id == approval_id
                and existing.status == "APPROVED"
                and existing.payload.get("approval")
            ):
                return 200, serialize(existing)
            if existing is None or existing.id != approval_id or existing.status != "EVALUATED":
                return 409, {"reason": "approval_requires_current_evaluated_decision"}
            if not self._verify_current(
                session, state, existing.payload["selected_actions"], context
            ):
                self._transition(
                    session,
                    existing,
                    "CANCELLED",
                    {
                        "outcome": "NO_ACTION",
                        "approved_actions": [],
                        "reason": "safety_recheck_failed",
                    },
                    datetime.now(UTC),
                )
                return 409, serialize(existing)
            self._transition(
                session,
                existing,
                "APPROVED",
                {
                    "approved_actions": existing.payload["selected_actions"],
                    "approval": {
                        "actor": "brain",
                        "reason": approval_reason,
                        "at": datetime.now(UTC).isoformat(),
                    },
                    "reason": "explicit_service_approval",
                },
                datetime.now(UTC),
            )
            return 200, serialize(existing)
        if existing is not None:
            return 200, serialize(existing)
        row = DecisionRecord(
            id=uuid4(),
            correlation_id=correlation_id,
            occurred_at=now,
            status="PROPOSED",
            payload={},
        )
        session.add(row)
        self._transition(
            session,
            row,
            "PROPOSED",
            {
                "fingerprint": context["fingerprint"],
                "inputs": context,
                "policy_version": self.policy.version if self.policy else None,
                "simulation_only": self.policy.simulation_only if self.policy else True,
                "execution_enabled": False,
                "approved_actions": [],
                "selected_actions": [],
                "outcome": "NO_ACTION",
                "reason": "evaluation_requested",
                "incident_ids": [item["incident_id"] for item in context["incidents"]],
            },
            now,
        )
        available, rejected = [], []
        if context["blocked"]:
            selected, reason = [], context["blocked"]
        else:
            available, rejected = candidates(
                context["incidents"],
                self.policy,
                set(context["quarantined_actuators"]),
                now,
            )
            selected, reason = optimize(available, self.policy)
        if selected and not self._verify_current(session, state, selected, context):
            selected, reason = [], "safety_recheck_failed"
        rejected.extend(
            {"candidate": item, "reason": "not_selected_by_constraints_or_objective"}
            for item in available
            if item not in selected
        )
        self._transition(
            session,
            row,
            "EVALUATED",
            {
                "selected_actions": selected,
                "rejected_alternatives": rejected,
                "reason": reason,
                "outcome": "ACTION_PLAN" if selected else "NO_ACTION",
                "objective_value": sum(item["score"] for item in selected),
                "constraints": self.policy.optimization.model_dump() if self.policy else {},
            },
            datetime.now(UTC),
        )
        if not selected:
            self._transition(session, row, "REJECTED", {}, datetime.now(UTC))
        elif not any(item["requires_approval"] for item in selected):
            self._transition(
                session,
                row,
                "APPROVED",
                {
                    "approved_actions": selected,
                    "reason": "reviewed_policy_authorization",
                },
                datetime.now(UTC),
            )
        return 200, serialize(row)

    def _verify_current(
        self, session: Session, state: dict, selected: list[dict], original: dict
    ) -> bool:
        now = datetime.now(UTC)
        current = self.context(session, state, now)
        if current["blocked"] or current["fingerprint"] != original["fingerprint"]:
            return False
        available, _ = candidates(
            current["incidents"], self.policy, set(current["quarantined_actuators"]), now
        )
        return verify(selected, available, self.policy)

    @staticmethod
    def _transition(
        session: Session,
        row: DecisionRecord,
        status: str,
        changes: dict,
        now: datetime,
    ) -> None:
        allowed = {
            "PROPOSED": {"PROPOSED", "EVALUATED", "CANCELLED"},
            "EVALUATED": {"APPROVED", "REJECTED", "CANCELLED"},
            "APPROVED": {"CANCELLED"},
        }
        if status not in allowed.get(row.status, set()):
            raise ValueError("invalid decision transition")
        row.status = status
        row.payload = row.payload | changes | {"updated_at": now.isoformat()}
        session.add(
            DecisionRevision(
                decision_id=row.id, created_at=now, payload={"status": status, **row.payload}
            )
        )
        audit(
            session,
            row.id,
            row.correlation_id,
            "decision_transition",
            {"status": status, **row.payload},
            now,
            actor="decision-engine",
        )
        session.flush()
