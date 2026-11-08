from datetime import datetime, timedelta
from math import cos, isfinite, log1p, pi, sin
from statistics import mean, stdev

import numpy as np

LAGS = (1, 2, 3, 6, 12, 24, 48, 72, 168)
WINDOWS = (3, 6, 12, 24, 72)
WATER_FEATURES = ["site_idx", "stage_norm"]
for lag in LAGS:
    WATER_FEATURES += [f"stage_lag_{lag}", f"stage_delta_{lag}"]
for window in WINDOWS:
    WATER_FEATURES += [f"stage_avg_{window}", f"stage_std_{window}"]
WATER_FEATURES += [
    "flow_log",
    "flow_lag_1",
    "flow_lag_3",
    "flow_lag_6",
    "flow_lag_24",
    "flow_known",
    "hour_sin",
    "hour_cos",
    "year_sin",
    "year_cos",
]


def water_features(
    metadata: dict,
    station: str,
    origin: datetime,
    stages: dict[datetime, float],
    flows: dict[datetime, float],
) -> np.ndarray:
    if metadata["feature_names"] != WATER_FEATURES:
        raise ValueError("feature_order_mismatch")
    if station not in metadata["site_index"]:
        raise ValueError("station_not_in_training")
    stat = metadata["site_stats"][station]
    median, scale = stat["stage_median_ft"], stat["stage_scale_ft"]
    if (
        not all(
            isfinite(stat[key])
            for key in (
                "stage_median_ft",
                "stage_scale_ft",
                "flow_log_median",
            )
        )
        or scale <= 0
    ):
        raise ValueError("invalid_training_statistics")
    if any(origin - timedelta(hours=lag) not in stages for lag in (0, 1, 2, 3, 6)):
        raise ValueError("insufficient_stage_history")
    current = stages[origin]
    values = [float(metadata["site_index"][station]), (current - median) / scale]
    for lag in LAGS:
        value = stages.get(origin - timedelta(hours=lag), float("nan"))
        values += [(value - median) / scale, (current - value) / scale]
    for window in WINDOWS:
        samples = [stages.get(origin - timedelta(hours=lag)) for lag in range(window)]
        if any(value is None for value in samples):
            values += [float("nan"), float("nan")]
        else:
            values += [(mean(samples) - median) / scale, stdev(samples) / scale]
    for lag in (0, 1, 3, 6, 24):
        value = flows.get(origin - timedelta(hours=lag))
        values.append(
            log1p(max(value, 0)) - stat["flow_log_median"] if value is not None else float("nan")
        )
    values += [
        float(origin in flows),
        sin(2 * pi * origin.hour / 24),
        cos(2 * pi * origin.hour / 24),
        sin(2 * pi * origin.timetuple().tm_yday / 365.25),
        cos(2 * pi * origin.timetuple().tm_yday / 365.25),
    ]
    return np.array([values], dtype=np.float64)
