"""Mock Twin — streams a fixture of readings to Guardian over REST.

Stands in for the Twin so the Guardian proves Rule R1 (it runs alone). It speaks
the real wire protocol: signed frames, provenance, monotonic sequence, and
`--rebase` to re-stamp phenomenon_time so the freshness gate is exercised live
rather than silently bypassed by a fixture written days ago.

Usage:
    python -m guardian.mock.mock_twin --base http://127.0.0.1:8080 \
        --fixture shared/fixtures/golden_clean.json [--delay 0.2]
"""
from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import List

from ..signing import compute_digest, hmac_signature, iso_from_epoch, parse_iso


def load_fixture(path: Path) -> List[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and "readings" in data:
        return data["readings"]
    if isinstance(data, list):
        return data
    raise ValueError("fixture must be a list or {'readings': [...]}")


def rebase_times(readings: List[dict], keyring: Path, lead_s: float = 0.5) -> List[dict]:
    """Re-stamp a fixture so its timestamps land just BEFORE now, re-signing it.

    Shipped fixtures are canonically dated so their digests/signatures are stable and
    reproducible in tests. That makes them arbitrarily old (or, for S1, arbitrarily in
    the future) relative to a live clock, where the age gate and the freshness factor
    would then reject or zero the verdict. For a live run, shift every timestamp by the
    same offset - preserving the scenario's relative timing and tick spacing - and
    recompute the digest and HMAC with the device's dev secret.

    The LAST frame is anchored to `now - lead_s` so the whole batch sits in the recent
    past and streams forward without tripping the age or future-timestamp gates.

    Falls back to a no-op (with a printed warning) if the keyring or timestamps cannot
    be read, so a demo never dies on a fixture problem.
    """
    if not readings:
        return readings
    if keyring is not None:
        keyring = Path(keyring)
        # Tests and live runs invoke from different cwds (repo root vs guardian/);
        # also try the path relative to this file's guardian/ home so re-signing
        # never silently degrades to unsigned frames.
        if not keyring.exists() and not keyring.is_absolute():
            alt = Path(__file__).resolve().parents[3] / keyring
            if alt.exists():
                keyring = alt
    secrets = {}
    if keyring is not None and keyring.exists():
        try:
            with open(keyring, "r", encoding="utf-8") as fh:
                secrets = {d["device_id"]: d.get("secret")
                           for d in json.load(fh).get("devices", [])}
        except Exception as exc:
            print(f"[mock_twin] could not read keyring {keyring}: {exc}")
            secrets = {}
    try:
        last = parse_iso(readings[-1]["phenomenon_time"])
    except Exception as exc:
        print(f"[mock_twin] could not parse fixture timestamps: {exc}")
        return readings
    offset = (time.time() - lead_s) - last
    out = []
    for r in readings:
        r = dict(r)
        try:
            r["phenomenon_time"] = iso_from_epoch(parse_iso(r["phenomenon_time"]) + offset)
        except Exception as exc:  # keep the original stamp rather than dropping the frame
            print(f"[mock_twin] could not re-stamp {r.get('reading_id')}: {exc}")
        secret = secrets.get(r.get("sensor_id"))
        if secret:
            # re-sign so a run with verify_signatures enabled still passes
            r["digest"] = compute_digest(r)
            r["signature"] = hmac_signature(secret, r["digest"])
        out.append(r)
    return out


def post_reading(base: str, reading: dict, timeout: float = 5.0):
    url = base.rstrip("/") + "/v1/readings"
    req = urllib.request.Request(
        url, data=json.dumps(reading).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode("utf-8"))
        except Exception:
            return exc.code, {"error": "HTTP_ERROR"}


def main() -> None:
    parser = argparse.ArgumentParser(prog="mock_twin", description="Stream a readings fixture to Guardian")
    parser.add_argument("--base", default="http://127.0.0.1:8080")
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--delay", type=float, default=0.2, help="seconds between readings")
    parser.add_argument("--rebase", action="store_true",
                        help="re-stamp fixture timestamps to now (and re-sign with the dev "
                             "keyring) so the age gate + freshness factor behave live")
    parser.add_argument("--keyring", default="keys/dev_keys.json",
                        help="dev keyring used to re-sign when --rebase is set")
    args = parser.parse_args()

    readings = load_fixture(Path(args.fixture))
    if args.rebase:
        readings = rebase_times(readings, Path(args.keyring))
        print("[mock_twin] re-stamped fixture timestamps to now")
    print(f"[mock_twin] streaming {len(readings)} readings -> {args.base}/v1/readings")
    accepted = 0
    for r in readings:
        status, body = post_reading(args.base, r)
        results = body.get("results", [{}]) if isinstance(body, dict) else [{}]
        code = results[0].get("code") if results else "?"
        ok = bool(results and results[0].get("accepted"))
        if ok:
            accepted += 1
        print(f"  [{status}] {r.get('sensor_id'):<14} {r.get('observed_property'):<16} -> {code}")
        if args.delay:
            time.sleep(args.delay)
    print(f"[mock_twin] done: {accepted}/{len(readings)} accepted. Timeline: {args.base}/ui/")


if __name__ == "__main__":
    main()
