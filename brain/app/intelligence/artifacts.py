import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from zipfile import ZipFile

import numpy as np

from app.intelligence.traffic_features import TRAFFIC_FEATURES
from app.intelligence.water_features import WATER_FEATURES


@dataclass
class LoadedArtifact:
    family: str
    horizon_minutes: int
    model: Any | None = None
    digest: str | None = None
    features: list[str] | None = None
    metadata: dict | None = None
    error: str | None = None
    preprocessing: dict | None = None
    preprocessing_digest: str | None = None

    def status(self) -> dict:
        return {
            "family": self.family,
            "horizon_minutes": self.horizon_minutes,
            "loaded": self.model is not None,
            "artifact_sha256": self.digest,
            "feature_order": self.features,
            "inference_ready": self.model is not None and self.error is None,
            "reason": self.error,
            "preprocessing_sha256": self.preprocessing_digest,
        }


class ArtifactRegistry:
    def __init__(self, traffic_directory: str | None, water_path: str | None) -> None:
        self.artifacts: list[LoadedArtifact] = []
        for family, horizons in (("traffic", (15, 30, 60)), ("water", (60, 180, 360))):
            for horizon in horizons:
                artifact = LoadedArtifact(family, horizon)
                self.artifacts.append(artifact)
                try:
                    if family == "traffic":
                        self._traffic(artifact, traffic_directory)
                    else:
                        self._water(artifact, water_path)
                except Exception as exc:
                    artifact.model = None
                    artifact.error = type(exc).__name__

    @staticmethod
    def _traffic(artifact: LoadedArtifact, directory: str | None) -> None:
        if not directory:
            raise FileNotFoundError("traffic directory not configured")
        import xgboost as xgb

        path = Path(directory) / f"traffic_xgboost_{artifact.horizon_minutes}min.json"
        data = path.read_bytes()
        metadata = json.loads(data)
        if "learner" not in metadata:
            raise ValueError("not an XGBoost JSON model")
        model = xgb.Booster(params={"nthread": 1})
        model.load_model(bytearray(data))
        artifact.model = model
        artifact.digest = hashlib.sha256(data).hexdigest()
        artifact.features = model.feature_names or []
        artifact.metadata = {
            "feature_count": model.num_features(),
            "format_version": metadata["version"],
        }
        artifact.error = "traffic_training_metadata_missing"
        metadata_path = Path(directory) / "metadata.json"
        if metadata_path.exists():
            artifact.metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            artifact.features = artifact.metadata["features"]
            if len(artifact.features) != model.num_features():
                raise ValueError("traffic feature count mismatch")
            if artifact.metadata["sample_interval_minutes"] != 5:
                raise ValueError("traffic sampling mismatch")
            artifact.error = "traffic_preprocessing_v2_npz_missing"
            metadata = artifact.metadata
            if metadata["features"] != TRAFFIC_FEATURES or metadata["dataset"] != "METR-LA":
                raise ValueError("incompatible traffic metadata")
            root = Path(directory)
            checksums = json.loads((root / "checksums_sha256.json").read_text())
            for name in (path.name, "metadata.json", "traffic_preprocessing_v2.npz"):
                if hashlib.sha256((root / name).read_bytes()).hexdigest() != checksums[name]:
                    raise ValueError("traffic checksum mismatch")
            npz_path = root / "traffic_preprocessing_v2.npz"
            with np.load(npz_path, allow_pickle=False) as data:
                prep = {key: data[key].copy() for key in data.files}
            ids = metadata["sensor_ids"]
            if len(ids) != 207 or len(set(ids)) != 207 or prep["sensor_ids"].tolist() != ids:
                raise ValueError("traffic sensor mapping mismatch")
            shapes = {
                "sensor_train_mean": (207,),
                "sensor_train_std": (207,),
                "neighbor_ids": (207, 2),
                "train_weekly_mean": (2016, 207),
            }
            for key, shape in shapes.items():
                if prep[key].shape != shape or not np.isfinite(prep[key]).all():
                    raise ValueError("invalid traffic preprocessing")
            if not np.issubdtype(prep["neighbor_ids"].dtype, np.integer):
                raise ValueError("invalid neighbor indices")
            if np.any(prep["neighbor_ids"] < 0) or np.any(prep["neighbor_ids"] >= 207):
                raise ValueError("invalid neighbor indices")
            if np.any(prep["sensor_train_std"] < 0):
                raise ValueError("invalid training standard deviations")
            if any(
                [ids[int(j)] for j in prep["neighbor_ids"][i]]
                != metadata["neighbor_sensor_ids"][sid]
                for i, sid in enumerate(ids)
            ):
                raise ValueError("traffic neighbor mapping mismatch")
            entry = metadata["models"][f"{artifact.horizon_minutes}min"]
            best = int(model.attr("best_iteration"))
            if entry["file"] != path.name or entry["best_iteration"] != best:
                raise ValueError("traffic horizon or iteration mismatch")
            if not 0 <= best < model.num_boosted_rounds():
                raise ValueError("invalid best iteration")
            artifact.preprocessing_digest = hashlib.sha256(npz_path.read_bytes()).hexdigest()
            if artifact.preprocessing_digest != metadata["preprocessing_sha256"]:
                raise ValueError("preprocessing hash mismatch")
            for array in prep.values():
                array.flags.writeable = False
            artifact.preprocessing, artifact.error = prep, None

    @staticmethod
    def _water(artifact: LoadedArtifact, location: str | None) -> None:
        if not location:
            raise FileNotFoundError("water path not configured")
        import lightgbm as lgb

        path = Path(location)
        name = f"lgbm_delta_{artifact.horizon_minutes // 60}h.txt"
        if path.is_dir():
            data = (path / name).read_bytes()
            metadata = json.loads((path / "metadata.json").read_text(encoding="utf-8"))
        else:
            with ZipFile(path) as archive:
                for member in (name, "metadata.json"):
                    if archive.getinfo(member).file_size > 20_000_000:
                        raise ValueError("artifact too large")
                data = archive.read(name)
                metadata = json.loads(archive.read("metadata.json"))
        if artifact.horizon_minutes // 60 not in metadata["horizons_hours"]:
            raise ValueError("horizon not declared")
        if metadata["stage_unit"] != "ft" or metadata["frequency"] != "1h":
            raise ValueError("unsupported water metadata")
        model = lgb.Booster(model_str=data.decode("utf-8"))
        if model.feature_name() != metadata["feature_names"]:
            raise ValueError("feature order mismatch")
        if metadata["feature_names"] != WATER_FEATURES:
            raise ValueError("training feature order mismatch")
        artifact.model = model
        artifact.features = model.feature_name()
        artifact.digest = hashlib.sha256(data).hexdigest()
        artifact.metadata = metadata
        artifact.error = None

    def status(self) -> list[dict]:
        return [artifact.status() for artifact in self.artifacts]
