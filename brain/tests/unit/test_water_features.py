from datetime import UTC, datetime, timedelta
from math import isnan, log1p

import pytest

from app.intelligence.water_features import WATER_FEATURES, water_features


def test_handoff_feature_parity_and_missing_flow() -> None:
    origin = datetime(2026, 1, 10, tzinfo=UTC)
    metadata = {
        "feature_names": WATER_FEATURES,
        "site_index": {"fixture": 0},
        "site_stats": {
            "fixture": {
                "stage_median_ft": 2,
                "stage_scale_ft": 2,
                "flow_log_median": 1,
            }
        },
    }
    stages = {origin - timedelta(hours=i): float(10 - i) for i in range(7)}
    result = dict(
        zip(WATER_FEATURES, water_features(metadata, "fixture", origin, stages, {})[0], strict=True)
    )
    assert result["stage_norm"] == 4
    assert result["stage_lag_1"] == 3.5
    assert result["stage_delta_6"] == 3
    assert result["stage_avg_3"] == 3.5
    assert result["stage_std_3"] == 0.5
    assert isnan(result["stage_std_12"])
    assert isnan(result["flow_log"])
    assert result["flow_known"] == 0
    with pytest.raises(ValueError, match="insufficient"):
        water_features(metadata, "fixture", origin, {origin: 1}, {})
    result = dict(
        zip(
            WATER_FEATURES,
            water_features(
                metadata,
                "fixture",
                origin,
                stages,
                {origin: 3},
            )[0],
            strict=True,
        )
    )
    assert result["flow_log"] == log1p(3) - 1
    assert result["flow_known"] == 1
