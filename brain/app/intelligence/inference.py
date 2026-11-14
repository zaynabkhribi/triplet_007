from datetime import UTC, datetime, timedelta
from math import isfinite
from statistics import median
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.models import CityRegistryRecord, EventLifecycle, ForecastRecord, SensorEvent
from app.database.session import Database
from app.intelligence.artifacts import ArtifactRegistry
from app.intelligence.traffic_inference import predict_traffic
from app.intelligence.water_features import water_features
from app.security.trust_engine import TrustEngine
from app.state.lifecycle import audit, utc
from app.state.registry import Registry

if TYPE_CHECKING:
    from app.api.forecasts import ForecastRequest


def predict_water(
    session: Session,
    settings: Settings,
    artifacts: ArtifactRegistry,
    event: "ForecastRequest",
    now: datetime,
) -> dict:
    origin = event.origin or (now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1))
    if origin.utcoffset() != timedelta(0) or any(
        (origin.minute, origin.second, origin.microsecond)
    ):
        raise ValueError("origin_must_be_on_UTC_hour_grid")
    if origin + timedelta(hours=1) > now:
        raise ValueError("origin_hour_not_complete")
    record = session.get(CityRegistryRecord, 1)
    registry = Registry.model_validate(record.payload if record else {})
    sensor = next((item for item in registry.sensors if item.sensor_id == event.sensor_id), None)
    if sensor is None or (
        sensor.measurement != "water_level"
        or sensor.unit != "ft"
        or sensor.training_source != "USGS"
        or not sensor.training_compatible
        or not sensor.training_id
    ):
        raise ValueError("incompatible_USGS_stage_mapping")
    selected = [
        item
        for item in artifacts.artifacts
        if item.family == "water" and item.horizon_minutes in event.horizons_minutes
    ]
    if not selected or any(item.model is None or item.error for item in selected):
        raise ValueError("model_unavailable")
    metadata = selected[0].metadata
    if any(item.metadata != metadata for item in selected):
        raise ValueError("inconsistent_model_metadata")
    flows = [
        item
        for item in registry.sensors
        if item.measurement == "water_flow"
        and item.training_source == "USGS"
        and item.training_id == sensor.training_id
    ]
    if len(flows) > 1 or any(item.unit != "cfs" or not item.training_compatible for item in flows):
        raise ValueError("incompatible_USGS_flow_mapping")
    ids = [sensor.sensor_id] + [item.sensor_id for item in flows]
    start, end = origin - timedelta(hours=168), origin + timedelta(hours=1)
    rows = session.execute(
        select(SensorEvent, EventLifecycle)
        .outerjoin(
            EventLifecycle,
            SensorEvent.id == EventLifecycle.event_id,
        )
        .where(
            SensorEvent.sensor_id.in_(ids),
            SensorEvent.occurred_at >= start,
            SensorEvent.occurred_at < end,
        )
        .order_by(SensorEvent.occurred_at)
    ).all()
    trust = TrustEngine(settings)
    buckets = {identifier: {} for identifier in ids}
    evidence, seen = [], set()
    for reading, lifecycle in rows:
        payload = reading.payload["event"]
        definition = sensor if reading.sensor_id == sensor.sensor_id else flows[0]
        if payload["unit"] != definition.unit or payload["sensor_type"] != definition.measurement:
            raise ValueError("incompatible_observation_units")
        if payload.get("attributes", {}).get("zone_id", definition.zone_id) != definition.zone_id:
            raise ValueError("incompatible_zone")
        key = (reading.sensor_id, utc(reading.occurred_at))
        if key in seen:
            raise ValueError("ambiguous_duplicate_timestamp")
        seen.add(key)
        if (
            lifecycle is None
            or not lifecycle.eligible
            or (trust.evaluate(session, reading, lifecycle, now).state != "TRUSTED")
        ):
            raise ValueError("evidence_not_currently_trusted")
        stamp = utc(reading.occurred_at)
        if (now - stamp).total_seconds() > definition.freshness_seconds:
            raise ValueError("sensor_evidence_stale")
        hour = stamp.replace(minute=0, second=0, microsecond=0)
        buckets[reading.sensor_id].setdefault(hour, []).append(payload["value"])
        evidence.append(
            {
                "event_id": str(reading.id),
                "verdict_id": str(lifecycle.verdict_id),
                "event_hash": reading.payload["sha256"],
            }
        )
    hourly = {
        identifier: {hour: median(values) for hour, values in bins.items()}
        for identifier, bins in buckets.items()
    }
    stage = hourly[sensor.sensor_id]
    flow = hourly[flows[0].sensor_id] if flows else {}
    features = water_features(metadata, sensor.training_id, origin, stage, flow)
    predictions = []
    for artifact in selected:
        delta = float(artifact.model.predict(features, num_threads=1)[0])
        value = stage[origin] + delta * metadata["site_stats"][sensor.training_id]["stage_scale_ft"]
        if not isfinite(value):
            raise ValueError("nonfinite_model_output")
        predictions.append(
            {
                "horizon_minutes": artifact.horizon_minutes,
                "forecast_at": (origin + timedelta(minutes=artifact.horizon_minutes)).isoformat(),
                "value": value,
                "unit": "ft",
                "quantity": "station_gage_height",
                "model_version": f"sha256:{artifact.digest}",
            }
        )
    return {
        "origin": origin.isoformat(),
        "available_at": end.isoformat(),
        "station_id": sensor.training_id,
        "sensor_mappings": [item.model_dump() for item in [sensor, *flows]],
        "predictions": predictions,
        "evidence": evidence,
        "features": [float(value) if isfinite(value) else None for value in features[0]],
        "feature_order": metadata["feature_names"],
        "preprocessing_version": "usgs-v3-handoff-1",
    }


def run_inference(
    database: Database,
    settings: Settings,
    artifacts: ArtifactRegistry,
    family: str,
    event: "ForecastRequest",
) -> tuple[int, dict]:
    identifier, now = uuid4(), datetime.now(UTC)
    with database.transaction() as session:
        detail = {"request": event.model_dump(mode="json"), "predictions": []}
        code, status = 200, "succeeded"
        try:
            predictor = predict_water if family == "water" else predict_traffic
            detail.update(predictor(session, settings, artifacts, event, now))
        except (ValueError, KeyError) as exc:
            code, status = 503, "blocked"
            detail["reason"] = str(exc)
        except Exception as exc:
            code, status = 503, "failed"
            detail["reason"] = type(exc).__name__
        session.add(
            ForecastRecord(
                id=identifier,
                correlation_id=event.correlation_id,
                occurred_at=now,
                family=family,
                status=status,
                payload=detail,
            )
        )
        audit(session, identifier, event.correlation_id, f"forecast_{status}", detail, now)
    return code, {"forecast_id": str(identifier), "status": status, **detail}


def currently_eligible(
    session: Session,
    settings: Settings,
    payload: dict,
    now: datetime | None = None,
    passport_eligibility=None,
) -> bool:
    evidence = payload.get("evidence", [])
    if not evidence:
        return False
    registry = session.get(CityRegistryRecord, 1)
    current = Registry.model_validate(registry.payload if registry else {}).sensors
    mappings = {item.sensor_id: item.model_dump() for item in current}
    if any(mappings.get(item["sensor_id"]) != item for item in payload["sensor_mappings"]):
        return False
    trust, now = TrustEngine(settings), now or datetime.now(UTC)
    for item in evidence:
        reading = session.get(SensorEvent, UUID(item["event_id"]))
        lifecycle = session.get(EventLifecycle, UUID(item["event_id"]))
        if reading is None or lifecycle is None:
            return False
        result = trust.evaluate(session, reading, lifecycle, now)
        # Task 7.3G-7B: passport eligibility is consumed from the immutable
        # snapshot refreshed async by the caller before this sync stage.
        passport_ok = (
            passport_eligibility is not None
            and passport_eligibility.eligible_at(reading.id, now)
            and result.reason in {"awaiting_guardian", "verdict_missing"}
        )
        durable_ok = (
            result.state == "TRUSTED"
            and lifecycle.eligible
            and result.verdict_id == lifecycle.verdict_id
        )
        if not (durable_ok or passport_ok):
            return False
        if (
            durable_ok
            and str(lifecycle.verdict_id) != item["verdict_id"]
        ):
            return False
        if (now - utc(reading.occurred_at)).total_seconds() > mappings[reading.sensor_id][
            "freshness_seconds"
        ]:
            return False
    return True
