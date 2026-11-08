"""Pytest fixtures: isolated Guardian app with a temp audit log.

GUARDIAN_SHARED_DIR points at the canonical repo/shared contract so tests validate
against the real schemas (parity with `make demo`).
"""
import dataclasses
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[1]        # .../guardian (self-contained)
SHARED = REPO / "shared"
os.environ.setdefault("GUARDIAN_SHARED_DIR", str(SHARED))
# Tests are hermetic: the background Orion poller must never touch a live broker.
os.environ.setdefault("GUARDIAN_ORION_ENABLED", "false")

from guardian.api import create_app          # noqa: E402
from guardian.config import load_settings     # noqa: E402


@pytest.fixture()
def settings(tmp_path):
    s = load_settings()
    # isolate the audit log per test
    return dataclasses.replace(
        s, paths=dataclasses.replace(s.paths, audit_log=str(tmp_path / "audit.jsonl"))
    )


@pytest.fixture()
def client(settings):
    return TestClient(create_app(settings))


@pytest.fixture()
def secure_client(tmp_path):
    """Client with Stage-A signature verification ON — the production posture.

    S1 (drift_attack.json) ships valid HMACs, so it is designed to run here. The default
    `client` leaves verification off, because golden_clean.json carries placeholder
    signatures; an unverified frame is honestly scored at provenance 0.5.
    """
    s = load_settings()
    s = dataclasses.replace(
        s,
        auth=dataclasses.replace(s.auth, verify_signatures=True),
        paths=dataclasses.replace(s.paths, audit_log=str(tmp_path / "audit.jsonl")),
    )
    return TestClient(create_app(s))


@pytest.fixture()
def golden():
    import json
    with open(SHARED / "fixtures" / "golden_clean.json", "r", encoding="utf-8") as fh:
        return json.load(fh)["readings"]


@pytest.fixture()
def drift_attack():
    import json
    with open(SHARED / "fixtures" / "drift_attack.json", "r", encoding="utf-8") as fh:
        return json.load(fh)["readings"]
