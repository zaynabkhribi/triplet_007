import json
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.models import ForecastRecord, IncidentRecord, IncidentRevision, SensorEvent
from app.intelligence.incident_rules import SEVERITIES, IncidentRule, IncidentRules
from app.intelligence.inference import currently_eligible
from app.state.lifecycle import audit, utc


def observation_signal(
    session: Session,
    sensor: dict,
    rule: IncidentRule,
    now: datetime,
) -> dict | None:
    if sensor["availability"] != "available":
        return None
    points = []
    for reference in sensor["evidence"]:
        event = session.get(SensorEvent, UUID(reference["event_id"]))
        if event is not None and utc(event.occurred_at) >= now - timedelta(
            seconds=rule.window_seconds
        ):
            points.append((utc(event.occurred_at), event.payload["event"]["value"], reference))
    points.sort(key=lambda item: item[0])
    metrics = []
    for index, (stamp, value, reference) in enumerate(points):
        evidence = [reference]
        if rule.mode in {"rise", "fall"}:
            if index == 0:
                continue
            previous, old_value, old_reference = points[index - 1]
            gap = (stamp - previous).total_seconds()
            if not 0 < gap <= rule.max_gap_seconds:
                continue
            value = (value - old_value) / gap * (-1 if rule.mode == "fall" else 1)
            evidence.insert(0, old_reference)
        metrics.append((stamp, rule.severity(value), evidence))
    if not metrics or metrics[-1][0] != points[-1][0]:
        return None
    tail = [metrics[-1]]
    breached = metrics[-1][1] is not None
    for item in reversed(metrics[:-1]):
        if (item[1] is not None) != breached:
            break
        if (tail[-1][0] - item[0]).total_seconds() > rule.max_gap_seconds:
            break
        tail.append(item)
    duration = (tail[0][0] - tail[-1][0]).total_seconds()
    references = {r["event_id"]: r for item in tail for r in item[2]}
    return {
        "sensor_id": sensor["sensor_id"],
        "at": tail[0][0].isoformat(),
        "breached": breached,
        "confirmed": len(tail) >= rule.min_samples and duration >= rule.persistence_seconds,
        "recovered": len(tail) >= rule.recovery_samples and duration >= rule.recovery_seconds,
        "severity": tail[0][1],
        "samples": len(tail),
        "duration_seconds": duration,
        "evidence": sorted(references.values(), key=lambda item: item["event_id"]),
        "forecast_ids": [],
    }


def forecast_signals(
    session: Session,
    settings: Settings,
    state: dict,
    rule: IncidentRule,
    now: datetime,
) -> list[dict]:
    family = "traffic" if rule.measurement == "traffic" else "water"
    records = session.scalars(
        select(ForecastRecord)
        .where(
            ForecastRecord.family == family,
            ForecastRecord.occurred_at >= now - timedelta(seconds=rule.forecast_max_age_seconds),
            ForecastRecord.occurred_at <= now,
        )
        .order_by(ForecastRecord.occurred_at.desc(), ForecastRecord.id.desc())
    ).all()
    signals, seen = [], set()
    for record in records:
        payload = record.payload
        sid = payload.get("request", {}).get("sensor_id")
        if sid in seen:
            continue
        seen.add(sid)
        sensor = state["sensors"].get(sid)
        if (
            record.status != "succeeded"
            or sensor is None
            or sensor["availability"] != "available"
            or sensor["unit"] != rule.unit
            or sensor["measurement"] != rule.measurement
            or not currently_eligible(session, settings, payload, now)
        ):
            continue
        severities = []
        for prediction in payload.get("predictions", []):
            if (
                prediction["unit"] != rule.unit
                or prediction["horizon_minutes"] > rule.forecast_max_horizon_minutes
                or utc(datetime.fromisoformat(prediction["forecast_at"])) <= now
            ):
                continue
            if severity := rule.severity(prediction["value"]):
                severities.append(severity)
        if severities:
            signals.append(
                {
                    "sensor_id": sid,
                    "at": utc(record.occurred_at).isoformat(),
                    "breached": True,
                    "confirmed": True,
                    "recovered": False,
                    "severity": max(severities, key=SEVERITIES.index),
                    "samples": 1,
                    "duration_seconds": 0,
                    "evidence": payload["evidence"],
                    "forecast_ids": [str(record.id)],
                }
            )
    return signals


class IncidentDetector:
    def __init__(self, settings: Settings, rules: IncidentRules) -> None:
        self.settings, self.rules = settings, rules

    def evaluate(self, session: Session, state: dict, now: datetime) -> None:
        records = session.scalars(
            select(IncidentRecord).order_by(
                IncidentRecord.occurred_at,
                IncidentRecord.id,
            )
        ).all()
        latest = {row.payload.get("key"): row for row in records}
        configured = set()
        for rule in self.rules.rules:
            forecasts = (
                forecast_signals(session, self.settings, state, rule, now)
                if rule.source == "forecast"
                else []
            )
            for zone in state["zones"]:
                if rule.zones and zone not in rule.zones:
                    continue
                key = json.dumps([rule.id, zone])
                configured.add(key)
                sensors = [
                    s
                    for s in state["sensors"].values()
                    if (
                        s["zone_id"] == zone
                        and s["measurement"] == rule.measurement
                        and s["unit"] == rule.unit
                    )
                ]
                if rule.source == "forecast":
                    ids = {s["sensor_id"] for s in sensors}
                    signals = [s for s in forecasts if s["sensor_id"] in ids]
                else:
                    signals = [
                        signal
                        for sensor in sensors
                        if (signal := observation_signal(session, sensor, rule, now)) is not None
                    ]
                eligible = {
                    (r["event_id"], r["verdict_id"])
                    for sensor in sensors
                    for r in sensor["evidence"]
                }
                self._evaluate_rule(
                    session,
                    rule,
                    zone,
                    key,
                    signals,
                    latest.get(key),
                    now,
                    eligible,
                )
        for key, row in latest.items():
            if key is not None and key not in configured and row.payload["status"] != "RESOLVED":
                self._save(
                    session,
                    row,
                    row.payload
                    | {
                        "status": "RESOLVED",
                        "resolution": "rule_or_zone_removed",
                        "evidence_eligible": False,
                    },
                    now,
                )

    def _evaluate_rule(
        self,
        session: Session,
        rule: IncidentRule,
        zone: str,
        key: str,
        signals: list[dict],
        row: IncidentRecord | None,
        now: datetime,
        eligible: set[tuple[str, str]],
    ) -> None:
        breached = [signal for signal in signals if signal["breached"]]
        if breached:
            newest = max(datetime.fromisoformat(signal["at"]) for signal in breached)
            breached = [
                s
                for s in breached
                if (newest - datetime.fromisoformat(s["at"])).total_seconds()
                <= rule.correlation_seconds
            ]
        candidate = len(breached) >= rule.min_sensors
        if not candidate:
            if row is None or row.payload["status"] == "RESOLVED":
                return
            recovered = sum(not s["breached"] and s["recovered"] for s in signals)
            prior_ids = {s["sensor_id"] for s in row.payload["signals"]}
            current_ids = {s["sensor_id"] for s in signals}
            references = {
                (r["event_id"], r["verdict_id"])
                for signal in row.payload["signals"]
                for r in signal["evidence"]
            }
            invalid = (
                not prior_ids <= current_ids
                or rule.source == "forecast"
                or not references <= eligible
                or sum(s["breached"] for s in signals) >= rule.min_sensors
            )
            if recovered >= rule.min_sensors or invalid:
                self._save(
                    session,
                    row,
                    row.payload
                    | {
                        "status": "RESOLVED",
                        "signals": signals,
                        "resolution": "evidence_invalidated" if invalid else "observed_recovery",
                        "evidence_eligible": not invalid,
                    },
                    now,
                )
            return
        confirmed_signals = [s for s in breached if s["confirmed"]]
        confirmed = len(confirmed_signals) >= rule.min_sensors
        severity = max(
            (s["severity"] for s in (confirmed_signals if confirmed else breached)),
            key=SEVERITIES.index,
        )
        if row is not None and row.payload["status"] == "RESOLVED":
            if (
                now - datetime.fromisoformat(row.payload["updated_at"])
            ).total_seconds() < rule.cooldown_seconds:
                return
            row = None
        detail = {
            "key": key,
            "rule_id": rule.id,
            "rule_version": self.rules.version,
            "rule": rule.model_dump(),
            "simulation_only": self.rules.simulation_only,
            "zone_id": zone,
            "incident_type": rule.incident_type,
            "classification": "early_warning" if rule.source == "forecast" else "observed",
            "severity": severity,
            "signals": breached,
            "evidence_eligible": True,
            "confidence": "corroborated"
            if len(confirmed_signals) > 1
            else ("rule_confirmed" if confirmed else "provisional"),
            "confidence_basis": "explicit_threshold_persistence_and_sensor_count",
            "evidence_quality": {"sensor_count": len(breached), "persistence_met": confirmed},
            "resolution": None,
        }
        if row is None:
            row = IncidentRecord(
                id=uuid4(), correlation_id=uuid4(), occurred_at=now, severity=severity, payload={}
            )
            session.add(row)
            self._save(session, row, detail | {"status": "DETECTED"}, now)
        status = row.payload["status"]
        if confirmed:
            status = "ACTIVE" if status == "DETECTED" else status
            if row.payload["status"] != "DETECTED" and (
                SEVERITIES.index(severity) > SEVERITIES.index(row.severity)
            ):
                status = "ESCALATED"
        elif status != "DETECTED":
            self._save(
                session,
                row,
                row.payload
                | {
                    "status": "RESOLVED",
                    "resolution": "confirmation_lost",
                    "evidence_eligible": False,
                },
                now,
            )
            return
        self._save(session, row, detail | {"status": status}, now)

    @staticmethod
    def _save(session: Session, row: IncidentRecord, detail: dict, now: datetime) -> None:
        previous = {k: v for k, v in row.payload.items() if k != "updated_at"}
        detail = {k: v for k, v in detail.items() if k != "updated_at"}
        if previous == detail:
            return
        row.payload = detail | {"updated_at": now.isoformat()}
        row.severity = detail["severity"]
        session.add(IncidentRevision(incident_id=row.id, created_at=now, payload=row.payload))
        audit(
            session,
            row.id,
            row.correlation_id,
            "incident_updated",
            row.payload,
            now,
            actor="incident-engine",
        )
        session.flush()
