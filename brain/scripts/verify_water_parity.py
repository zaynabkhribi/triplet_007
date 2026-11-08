import argparse
import csv
import io
from datetime import datetime
from statistics import median
from zipfile import ZipFile

from app.intelligence.artifacts import ArtifactRegistry
from app.intelligence.water_features import water_features


def verify(path: str) -> int:
    registry = ArtifactRegistry(None, path)
    artifacts = [item for item in registry.artifacts if item.family == "water"]
    if not all(item.model is not None and item.error is None for item in artifacts):
        raise ValueError("water artifacts unavailable")
    metadata = artifacts[0].metadata
    station = metadata["stations"][0]
    with ZipFile(path) as archive:
        hourly = {}
        for code in ("00065", "00060"):
            buckets = {}
            for name in archive.namelist():
                if name.startswith(f"cache/{station}_{code}_"):
                    rows = csv.DictReader(io.StringIO(archive.read(name).decode()))
                    for row in rows:
                        stamp = datetime.fromisoformat(row["time"]).replace(
                            minute=0,
                            second=0,
                            microsecond=0,
                        )
                        try:
                            value = float(row["value"])
                        except ValueError:
                            continue
                        buckets.setdefault(stamp, []).append(value)
            hourly[code] = {stamp: median(values) for stamp, values in buckets.items()}
        checked = 0
        for artifact in artifacts:
            name = f"test_predictions_{artifact.horizon_minutes // 60}h.csv"
            rows = [
                row
                for row in csv.DictReader(io.StringIO(archive.read(name).decode()))
                if row["station"] == station
            ]
            for row in rows[200:203]:
                origin = datetime.fromisoformat(row["time"])
                features = water_features(
                    metadata, station, origin, hourly["00065"], hourly["00060"]
                )
                prediction = (
                    hourly["00065"][origin]
                    + float(artifact.model.predict(features, num_threads=1)[0])
                    * metadata["site_stats"][station]["stage_scale_ft"]
                )
                if abs(prediction - float(row["prediction_ft"])) > 1e-8:
                    raise AssertionError(f"reference mismatch: {name}, {origin}, {prediction}")
                checked += 1
        return checked


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    print(f"Reference predictions matched: {verify(parser.parse_args().archive)}")
