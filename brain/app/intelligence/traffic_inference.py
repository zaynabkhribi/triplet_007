from collections import defaultdict
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from zoneinfo import ZoneInfo

import numpy as np
import xgboost as xgb
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.models import (
    CityRegistryRecord,
    EventLifecycle,
    GuardianVerdictRecord,
    SensorEvent,
)
from app.intelligence.artifacts import ArtifactRegistry
from app.intelligence.traffic_features import TRAFFIC_FEATURES, traffic_features
from app.security.trust_engine import TrustEngine, quarantined
from app.state.lifecycle import utc
from app.state.registry import Registry

if TYPE_CHECKING:
    from app.api.forecasts import ForecastRequest


def predict_traffic(
    session: Session,
    settings: Settings,
    artifacts: ArtifactRegistry,
    event: "ForecastRequest",
    now: datetime,
) -> dict:
    selected = [
        item
        for item in artifacts.artifacts
        if item.family == "traffic" and item.horizon_minutes in event.horizons_minutes
    ]
    if not selected or any(
        item.model is None or item.error or item.preprocessing is None for item in selected
    ):
        raise ValueError("traffic_model_unavailable")
    artifact = selected[0]
    if any(
        item.metadata != artifact.metadata
        or item.preprocessing_digest != artifact.preprocessing_digest
        for item in selected
    ):
        raise ValueError("inconsistent_traffic_models")
    metadata, prep = artifact.metadata, artifact.preprocessing
    record = session.get(CityRegistryRecord, 1)
    registry = Registry.model_validate(record.payload if record else {})
    mapped = [sensor for sensor in registry.sensors if sensor.training_source == "METR-LA"]
    ids = metadata["sensor_ids"]
    if len(mapped) != 207 or {sensor.training_id for sensor in mapped} != set(ids):
        raise ValueError("full_207_sensor_mapping_required")
    definitions = {sensor.training_id: sensor for sensor in mapped}
    ordered = [definitions[identifier] for identifier in ids]
    if any(
        sensor.measurement != "traffic"
        or sensor.unit != "METR-LA_native_speed"
        or not sensor.training_compatible
        or not sensor.training_timezone
        for sensor in mapped
    ):
        raise ValueError("incompatible_traffic_mapping_or_units")
    if len({sensor.training_timezone for sensor in mapped}) != 1:
        raise ValueError("inconsistent_training_clock")
    target_index = next(
        (i for i, sensor in enumerate(ordered) if sensor.sensor_id == event.sensor_id), None
    )
    if target_index is None:
        raise ValueError("sensor_not_in_training")
    zone = ZoneInfo(ordered[0].training_timezone)
    origin = event.origin or now.replace(minute=now.minute // 5 * 5, second=0, microsecond=0)
    if origin.utcoffset() is None:
        raise ValueError("origin_requires_timezone")
    origin = utc(origin)
    if origin > now or origin.minute % 5 or origin.second or origin.microsecond:
        raise ValueError("invalid_traffic_origin_grid")
    start = origin - timedelta(minutes=5 * 288)
    stamps = [start + timedelta(minutes=5 * i) for i in range(289)]
    clock = [stamp.astimezone(zone).replace(tzinfo=None) for stamp in stamps]
    if any(
        right - left != timedelta(minutes=5) for left, right in zip(clock, clock[1:], strict=False)
    ):
        raise ValueError("ambiguous_training_clock_transition")
    sensor_ids = [sensor.sensor_id for sensor in ordered]
    conditions = (
        SensorEvent.sensor_id.in_(sensor_ids),
        SensorEvent.occurred_at >= start,
        SensorEvent.occurred_at <= origin,
    )
    rows = session.execute(
        select(SensorEvent, EventLifecycle)
        .outerjoin(
            EventLifecycle,
            SensorEvent.id == EventLifecycle.event_id,
        )
        .where(*conditions)
        .limit(207 * 289 + 1)
    ).all()
    if len(rows) != 207 * 289:
        raise ValueError("complete_289_by_207_history_required")
    verdicts = defaultdict(list)
    for record in session.scalars(
        select(GuardianVerdictRecord)
        .join(
            SensorEvent,
            GuardianVerdictRecord.event_id == SensorEvent.id,
        )
        .where(*conditions)
    ):
        verdicts[record.event_id].append(record)
    quarantines = {sid: quarantined(session, "sensor", sid) for sid in sensor_ids}
    if any(quarantines.values()):
        raise ValueError("sensor_quarantined")
    columns = {sensor.sensor_id: index for index, sensor in enumerate(ordered)}
    grid, seen, evidence = np.empty((289, 207), dtype=np.float64), set(), []
    trust = TrustEngine(settings)
    for reading, lifecycle in rows:
        col = columns[reading.sensor_id]
        sensor = ordered[col]
        stamp = utc(reading.occurred_at)
        offset = (stamp - start).total_seconds() / 300
        key = (int(offset), col)
        if not offset.is_integer() or key in seen:
            raise ValueError("duplicate_or_misaligned_traffic_sample")
        seen.add(key)
        payload = reading.payload["event"]
        if (
            payload["sensor_type"] != "traffic"
            or payload["unit"] != sensor.unit
            or (payload.get("attributes", {}).get("zone_id", sensor.zone_id) != sensor.zone_id)
        ):
            raise ValueError("incompatible_traffic_observation")
        if (now - stamp).total_seconds() >= sensor.freshness_seconds:
            raise ValueError("traffic_evidence_stale")
        if lifecycle is None or not lifecycle.eligible:
            raise ValueError("evidence_not_currently_trusted")
        result = trust.evaluate(session, reading, lifecycle, now, verdicts[reading.id], False)
        if result.state != "TRUSTED" or result.verdict_id != lifecycle.verdict_id:
            raise ValueError("evidence_not_currently_trusted")
        grid[key] = payload["value"]
        evidence.append(
            {
                "event_id": str(reading.id),
                "verdict_id": str(lifecycle.verdict_id),
                "event_hash": reading.payload["sha256"],
            }
        )
    predictions, feature_rows = [], {}
    for model in selected:
        features = traffic_features(grid, target_index, clock[-1], model.horizon_minutes, prep)
        best = int(model.model.attr("best_iteration"))
        value = float(
            model.model.predict(
                xgb.DMatrix(features),
                iteration_range=(0, best + 1),
            )[0]
        )
        if not np.isfinite(value):
            raise ValueError("nonfinite_model_output")
        predictions.append(
            {
                "horizon_minutes": model.horizon_minutes,
                "forecast_at": (origin + timedelta(minutes=model.horizon_minutes)).isoformat(),
                "value": value,
                "unit": "METR-LA_native_speed",
                "quantity": "absolute_speed",
                "model_version": f"sha256:{model.digest}",
                "best_iteration": best,
            }
        )
        feature_rows[str(model.horizon_minutes)] = [
            float(value) if np.isfinite(value) else None for value in features[0]
        ]
    return {
        "origin": origin.isoformat(),
        "predictions": predictions,
        "evidence": evidence,
        "features": feature_rows,
        "feature_order": TRAFFIC_FEATURES,
        "preprocessing_version": f"sha256:{artifact.preprocessing_digest}",
        "training_clock": ordered[0].training_timezone,
        "sensor_mappings": [sensor.model_dump() for sensor in ordered],
    }
