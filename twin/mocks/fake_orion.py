#!/usr/bin/env python3
"""
Fake Orion Broker Filter - lets the Twin run and be tested with NO access to the platform.

It keeps the device records in memory, checks K1/K2 like the real filter and refuses the
characters Orion refuses in text values. Use it with a config whose orion.base_url is
http://127.0.0.1:8099/orion-filter/orion-1

Run (from the twin/ folder):
    python mocks/fake_orion.py --secrets secrets.json      # keys taken from your secrets file
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

STORE, KEYS = {}, {}
BAD_CHARS = "<>\"'=;()"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _auth(self, q):
        dev = q.get("elementid", [""])[0]
        return KEYS.get(dev) == (q.get("k1", [""])[0], q.get("k2", [""])[0])

    def _send(self, code, body=None):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if body is not None:
            self.wfile.write(json.dumps(body).encode())

    def do_PATCH(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if not self._auth(q):
            return self._send(401, {"error": "not authorized"})
        dev = u.path.split("/")[-2]
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        if any(isinstance(a.get("value"), str) and any(c in a["value"] for c in BAD_CHARS)
               for a in body.values()):
            return self._send(400, {"error": "BadRequest", "description": "Invalid characters in attribute value"})
        STORE.setdefault(dev, {"id": dev}).update(body)
        self._send(204)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        dev = u.path.split("/")[-1]
        if not self._auth(q) and not PUBLIC:
            return self._send(401, {"error": "not authorized"})
        self._send(200, STORE.get(dev, {"id": dev}))

    def do_POST(self):
        if self.path == "/__keys":
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            KEYS.update({k: (v["k1"], v["k2"]) if isinstance(v, dict) else tuple(v) for k, v in body.items()})
            return self._send(200, {})
        self._send(404, {})


PUBLIC = True   # like your devices: public, readable without keys; writing always needs K1/K2

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--secrets", help="secrets.json with K1/K2 per device")
    args = ap.parse_args()
    if args.secrets:
        with open(args.secrets, encoding="utf-8") as fh:
            KEYS.update({k: (v["k1"], v["k2"]) for k, v in json.load(fh).items()})
    print(f"Fake Orion on http://127.0.0.1:{args.port}  ({len(KEYS)} devices with keys)  Ctrl+C to stop")
    try:
        ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
    except KeyboardInterrupt:
        pass
