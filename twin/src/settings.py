"""Paths, logger and small helpers shared by every module of the Twin."""
import logging
import os
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("TWIN_CONFIG", os.path.join(HERE, "..", "config.json"))
SECRETS_PATH = os.environ.get("TWIN_SECRETS", os.path.join(HERE, "..", "secrets.json"))
SCENARIOS_PATH = os.environ.get("TWIN_SCENARIOS", os.path.join(HERE, "..", "scenarios.json"))
LOG_DIR = os.environ.get("TWIN_LOG_DIR", os.path.join(HERE, "..", "..", "logs"))

log = logging.getLogger("twin")


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def rnd(x, n=1):
    return round(x, n)
