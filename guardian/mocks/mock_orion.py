"""`python -m mocks.mock_orion` — a FAKE Orion broker for the Guardian demo.

A tiny GB gate with the wire surface the layers use:
    GET /v2/entities/{id}                       -> the entity (attrs are dicts)
    GET  /v2/entities?served=nothing            -> 404, as Orion does for ids unknown

It serves `mocks.orion_world.World` state and accepts the step-file commands:

    POST /scenario {\"name\": \"g3\"}            -> reset the world into scenario name

so a scenario is triggered with one HTTP call, exactly like the Twin's run_mock
(the same idea, one directory over, for the twin side).

Data, not code: entity CONTENTS come orion_world.py (the twin's formulas).
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .orion_world import World, SCENARIOS

PORT_DEFAULT = 8025


class OrionWorldServer:
    """ThreadingHTTPServer bound to a World. Reused by mocks/run_mock.py and the tests."""

    def __init__(self, world: World, host: str = "127.0.0.1", port: int = 0) -> None:
        self.world = world
        self.httpd = ThreadingHTTPServer((host, port), _Handler)
        self.httpd.orion_world = world
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]

    def serve_forever(self) -> None:
        self.httpd.serve_forever()

    def shutdown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


class _Handler(BaseHTTPRequestHandler):
    log_message = lambda self, *a, **k: None      # noqa: E731  (server log => own logging)

    # the world is attached to the httpd instance
    @property
    def world(self) -> World:
        return self.server.orion_world            # type: ignore[attr-defined]

    def do_GET(self):
        device_id = self.path.rsplit("/", 1)[-1].split("?")[0]
        entity = self.world.entities().get(device_id)
        if entity is None:
            self._json(404, {"error": "NotFound", "description": f"no entity {device_id}"})
            return
        self._json(200, entity)

    def do_POST(self):
        if not self.path.startswith("/scenario"):
            self._json(404, {"error": "NoRoute"})
            return
        try:
            length = int(self.headers.get("content-length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            name = str(body.get("name", ""))
            if name not in SCENARIOS:
                self._json(422, {"error": "NoScenario", "known": sorted(SCENARIOS)})
                return
            self.server.orion_world = World()          # fresh city per scenario
            self._json(200, {"ok": True, "scenario": name,
                             "duration": SCENARIOS[name]["duration"]})
        except ValueError as exc:
            self._json(400, {"error": "BadJSON", "description": str(exc)})

    def _json(self, code: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(prog="mock-orion", description="A fake Orion broker for the triplet demo.")
    parser.add_argument("--port", type=int, default=PORT_DEFAULT)
    args = parser.parse_args()
    world = World()
    server = OrionWorldServer(world, port=args.port)
    print(f"mock-orion: {SCENARIOS and 'scenarios: ' + ', '.join(sorted(SCENARIOS))} "
          f"GET /v2/entities/<id> and POST /scenario on http://127.0.0.1:{server.port}/",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
