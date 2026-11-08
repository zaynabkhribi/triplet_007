import argparse
from pathlib import Path

import numpy as np
import xgboost as xgb

from app.intelligence.artifacts import ArtifactRegistry


def verify(directory: str) -> int:
    registry = ArtifactRegistry(directory, None)
    count = 0
    for artifact in registry.artifacts:
        if artifact.family != "traffic":
            continue
        if artifact.error or artifact.model is None:
            raise ValueError(artifact.error)
        with np.load(
            Path(directory) / f"inference_reference_{artifact.horizon_minutes}min.npz",
            allow_pickle=False,
        ) as reference:
            assert reference["feature_names"].tolist() == artifact.features
            prediction = artifact.model.predict(
                xgb.DMatrix(reference["X"]),
                iteration_range=(0, int(artifact.model.attr("best_iteration")) + 1),
            )
            np.testing.assert_array_equal(prediction, reference["predicted_speed"])
            count += len(prediction)
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    print(f"Reference predictions matched exactly: {verify(parser.parse_args().directory)}")
