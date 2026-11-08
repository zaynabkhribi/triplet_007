import argparse
import asyncio
import json

from app.core.config import Settings
from app.database.session import Database
from app.scenarios import SCENARIOS, ScenarioRunner


async def run(args: argparse.Namespace) -> int:
    settings = (
        Settings(database_url=args.database_url, actuator_execution_enabled=False)
        if args.database_url
        else Settings(actuator_execution_enabled=False)
    )
    database = Database(settings)
    database.initialize()
    runner = ScenarioRunner(database, settings)
    try:
        if args.reset:
            results = [runner.reset()]
        else:
            selected = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
            results = [await runner.run(item) for item in selected]
        print(json.dumps(results, default=str, indent=2))
        return 0 if all(item.get("status") in {"PASSED", "RESET"} for item in results) else 1
    finally:
        database.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", choices=[*SCENARIOS, "all"], nargs="?", default="all")
    parser.add_argument("--database-url")
    parser.add_argument("--reset", action="store_true")
    raise SystemExit(asyncio.run(run(parser.parse_args())))
