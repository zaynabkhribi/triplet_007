from datetime import datetime, timedelta
from math import cos, pi, sin

import numpy as np

TRAFFIC_FEATURES = [
    "sensor_idx",
    "sensor_train_mean",
    "sensor_train_std",
    "hour_sin",
    "hour_cos",
    "day_sin",
    "day_cos",
    "network_speed",
    "speed_now",
    "lag_1",
    "lag_2",
    "lag_3",
    "lag_6",
    "lag_12",
    "lag_36",
    "mean_3",
    "mean_12",
    "std_12",
    "missing_12",
    "delta_3",
    "neighbor_1",
    "neighbor_2",
    "yesterday_same_target_time",
    "train_weekly_mean",
]


def traffic_features(
    grid: np.ndarray,
    sensor_index: int,
    origin: datetime,
    horizon: int,
    preprocessing: dict,
) -> np.ndarray:
    if grid.shape != (289, 207) or horizon not in (15, 30, 60):
        raise ValueError("incompatible_traffic_history")
    if not np.isfinite(grid).all():
        raise ValueError("missing_traffic_observations")
    speed = grid.astype(np.float64, copy=True)
    speed[speed == 0] = np.nan
    column = speed[:, sensor_index]
    if np.isnan(column[-1]):
        raise ValueError("missing_current_speed")
    target = origin + timedelta(minutes=horizon)
    minute = origin.hour * 60 + origin.minute
    slot = target.weekday() * 288 + (target.hour * 60 + target.minute) // 5
    neighbors = preprocessing["neighbor_ids"][sensor_index]
    yesterday = column[horizon // 5]
    if np.isnan(yesterday):
        yesterday = column[-1]
    short, window = column[-3:], column[-12:]
    count = np.count_nonzero(~np.isnan(window))
    weekly = preprocessing["train_weekly_mean"][slot, sensor_index]
    if np.isnan(weekly):
        weekly = preprocessing["sensor_train_mean"][sensor_index]
    values = [
        sensor_index,
        preprocessing["sensor_train_mean"][sensor_index],
        preprocessing["sensor_train_std"][sensor_index],
        sin(2 * pi * minute / 1440),
        cos(2 * pi * minute / 1440),
        sin(2 * pi * origin.weekday() / 7),
        cos(2 * pi * origin.weekday() / 7),
        np.nanmean(speed[-1]),
        column[-1],
        *[column[-1 - lag] for lag in (1, 2, 3, 6, 12, 36)],
        np.nanmean(short),
        np.nanmean(window) if count >= 3 else np.nan,
        np.nanstd(window, ddof=1) if count >= 3 else np.nan,
        12 - count,
        column[-1] - column[-4],
        speed[-1, neighbors[0]],
        speed[-1, neighbors[1]],
        yesterday,
        weekly,
    ]
    return np.asarray([values], dtype=np.float32)
