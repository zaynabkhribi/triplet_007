"""Inspect the running Brain without creating a scenario or approving an action."""

import argparse
import json
import os
import sys
from pathlib import Path

import httpx

BRAIN = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BRAIN))
os.environ.setdefault("ENV_FILE", str(BRAIN / ".env.real-readonly"))

from app.core.config import get_settings  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evaluate", action="store_true", help="Persist a decision evaluation only"
    )
    args = parser.parse_args()
    settings = get_settings()
    if settings.brain_api_key is None:
        raise RuntimeError("Brain service credential is unavailable")
    headers = {"X-API-Key": settings.brain_api_key.get_secret_value()}
    with httpx.Client(
        base_url="http://127.0.0.1:8000", headers=headers, timeout=30, trust_env=False
    ) as client:
        ready = client.get("/health/ready")
        ready.raise_for_status()
        city = client.get("/v1/city/state")
        city.raise_for_status()
        state = city.json()
        sensors = [
            {
                "sensor_id": name,
                "value": row["value"],
                "trust_status": row["trust_status"],
                "availability": row["availability"],
                "evidence_count": len(row["evidence"]),
                "last_observed_at": row["last_observed_at"],
                "trust_sources": sorted(
                    {e.get("trust_source", "guardian_verdict") for e in row["evidence"]}
                ),
            }
            for name, row in state["sensors"].items()
        ]
        incidents = client.get("/v1/incidents/active")
        incidents.raise_for_status()
        result = {
            "ready": ready.json(),
            "as_of": state["as_of"],
            "sensors": sensors,
            "active_incidents": [
                {
                    "incident_id": r["incident_id"],
                    "status": r["status"],
                    "severity": r["severity"],
                    "zone_id": r["zone_id"],
                }
                for r in incidents.json()
            ],
        }
        if args.evaluate:
            decision = client.post("/v1/decisions/evaluate", json={})
            decision.raise_for_status()
            row = decision.json()
            result["decision"] = {
                k: row.get(k)
                for k in (
                    "decision_id",
                    "status",
                    "outcome",
                    "reason",
                    "incident_ids",
                    "selected_actions",
                )
            }
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Live inspection failed ({type(exc).__name__}); details withheld", file=sys.stderr)
        sys.exit(1)
