
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.models import (
    CityRegistryRecord,
    CitySnapshot,
    EventLifecycle,
    SensorEvent,
)
from app.database.session import Database
from app.decision.engine import DecisionEngine
from app.intelligence.incident_detector import IncidentDetector
from app.intelligence.incident_rules import load_rules
from app.security.trust_engine import TrustEngine, quarantined
from app.state.fusion import correlation, statistics
from app.state.lifecycle import utc
from app.state.registry import Registry


class CityEngine:
    def __init__(self, database: Database, settings: Settings) -> None:
        self.database, self.trust = database, TrustEngine(settings)

        self.incidents = IncidentDetector(
            settings,
            load_rules(settings.incident_rules_file, settings.environment),
        )

        self.decisions = DecisionEngine(settings, self.incidents.rules)

    def rebuild(self, session: Session, now: datetime) -> dict:
        record = session.get(CityRegistryRecord, 1)
        registry = Registry.model_validate(
            record.payload if record else {}
        )

        zones = {
            zone: {"sensors": [], "measurements": {}}
            for zone in registry.zones
        }

        sensors, series = {}, {}

        # Process each registered sensor independently
        for definition in registry.sensors:
            cutoff = now - timedelta(
                seconds=min(
                    registry.window_seconds,
                    definition.freshness_seconds,
                )
            )

            # Preserve missing vs stale sensor distinction
            has_history = session.scalar(
                select(SensorEvent.id)
                .where(
                    SensorEvent.sensor_id == definition.sensor_id
                )
                .limit(1)
            ) is not None

            # Query only the relevant recent measurements
            candidates = session.execute(
                select(SensorEvent, EventLifecycle)
                .outerjoin(
                    EventLifecycle,
                    SensorEvent.id == EventLifecycle.event_id,
                )
                .where(
                    SensorEvent.sensor_id == definition.sensor_id,
                    SensorEvent.occurred_at >= cutoff,
                    SensorEvent.occurred_at <= now,
                )
                .order_by(
                    SensorEvent.occurred_at,
                    SensorEvent.id,
                )
            ).all()

            points, evidence = {}, []
            latest_eligible = None
            duplicates = {}

            # Detect duplicate observation timestamps
            for event, _ in candidates:
                timestamp = utc(event.occurred_at)
                duplicates[timestamp] = (
                    duplicates.get(timestamp, 0) + 1
                )

            # Validate every candidate through Guardian trust
            for event, lifecycle in candidates:
                timestamp = utc(event.occurred_at)
                payload = event.payload["event"]

                if (
                    not cutoff <= timestamp <= now
                    or duplicates[timestamp] != 1
                    or payload["sensor_type"] != definition.measurement
                    or payload["unit"] != definition.unit
                    or payload.get(
                        "attributes", {}
                    ).get(
                        "zone_id", definition.zone_id
                    ) != definition.zone_id
                    or lifecycle is None
                    or not lifecycle.eligible
                ):
                    continue

                trust = self.trust.evaluate(
                    session, event, lifecycle, now
                )

                if (
                    trust.state != "TRUSTED"
                    or trust.verdict_id != lifecycle.verdict_id
                ):
                    continue

                points[timestamp.timestamp()] = payload["value"]
                latest_eligible = event

                evidence.append(
                    {
                        "event_id": str(event.id),
                        "verdict_id": str(lifecycle.verdict_id),
                    }
                )

            # Determine current sensor availability
            available = (
                bool(points)
                and latest_eligible is not None
            )

            if not available:
                points, evidence = {}, []

            availability = (
                "available" if available else "unavailable"
            )

            if not has_history:
                availability = "missing"

            elif (
                latest_eligible is None
                or utc(latest_eligible.occurred_at) < cutoff
            ):
                availability = "stale"

            # Guardian quarantine overrides sensor availability
            if quarantined(
                session, "sensor", definition.sensor_id
            ):
                availability = "quarantined"
                points, evidence, available = {}, [], False

            # Store calculated state for this sensor
            sensors[definition.sensor_id] = {
                **definition.model_dump(),
                "availability": availability,
                "trust_status": (
                    "trusted" if available else "unverified"
                ),
                "last_observed_at": (
                    utc(latest_eligible.occurred_at).isoformat()
                    if latest_eligible
                    else None
                ),
                "value": (
                    list(points.values())[-1]
                    if points
                    else None
                ),
                "statistics": statistics(
                    list(points.items()),
                    registry.ema_alpha,
                ),
                "evidence": evidence,
            }

            series[definition.sensor_id] = points

            zones[definition.zone_id]["sensors"].append(
                definition.sensor_id
            )

        # Aggregate sensor measurements by zone
        for zone in zones.values():
            groups = {}

            for sensor_id in zone["sensors"]:
                sensor = sensors[sensor_id]
                key = (
                    sensor["measurement"]
                    + ":"
                    + sensor["unit"]
                )

                groups.setdefault(key, []).append(sensor_id)

            for key, ids in groups.items():
                usable = [
                    sid
                    for sid in ids
                    if sensors[sid]["value"] is not None
                ]

                weight = sum(
                    sensors[sid]["weight"]
                    for sid in usable
                )

                zone["measurements"][key] = {
                    "value": (
                        sum(
                            sensors[sid]["value"]
                            * sensors[sid]["weight"]
                            for sid in usable
                        ) / weight
                        if weight
                        else None
                    ),
                    "contributors": usable,
                    "missing": sorted(
                        set(ids) - set(usable)
                    ),
                    "correlations": [
                        {
                            "left": left,
                            "right": right,
                            "value": correlation(
                                series[left],
                                series[right],
                            ),
                        }
                        for index, left in enumerate(usable)
                        for right in usable[index + 1:]
                    ],
                }

        # Persist city state only when it changes
        payload = {
            "zones": zones,
            "sensors": sensors,
            "registry": registry.model_dump(),
        }

        previous = session.scalar(
            select(CitySnapshot)
            .order_by(CitySnapshot.version.desc())
            .limit(1)
        )

        if previous is None or previous.payload != payload:
            previous = CitySnapshot(
                created_at=now,
                payload=payload,
            )
            session.add(previous)
            session.flush()

        state = {
            "version": previous.version,
            "as_of": now.isoformat(),
            **payload,
        }

        # Preserve incident detection and decision invalidation
        self.incidents.evaluate(session, state, now)
        self.decisions.invalidate(session, state, now)

        return state

    def snapshot(self) -> dict:
        with self.database.transaction() as session:
            return self.rebuild(
                session,
                datetime.now(UTC),
            )
