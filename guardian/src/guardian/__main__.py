"""`python -m guardian` entrypoint.

Usage:
    python -m guardian [--host H] [--port P] [--reload]
Host/port default to config.yaml; GUARDIAN_PORT env overrides the port.
"""
from __future__ import annotations

import argparse

from .api import create_app
from .config import load_settings


def main() -> None:
    parser = argparse.ArgumentParser(prog="guardian", description="AEGIS LOOP Guardian layer")
    parser.add_argument("--host", default=None, help="bind host (default: config service.host)")
    parser.add_argument("--port", type=int, default=None, help="bind port (default: config/GUARDIAN_PORT)")
    parser.add_argument("--reload", action="store_true", help="auto-reload (dev only)")
    args = parser.parse_args()

    import uvicorn

    settings = load_settings()
    host = args.host or settings.service.host
    port = args.port or settings.service.port
    uvicorn.run(create_app(settings), host=host, port=port, reload=args.reload,
                log_level=settings.service.log_level.lower())


if __name__ == "__main__":
    main()
