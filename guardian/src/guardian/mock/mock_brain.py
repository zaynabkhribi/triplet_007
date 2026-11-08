"""Mock Brain — City Brain stand-in for standalone Guardian runs (R1).

Proves the Brain -> Guardian trust boundary BEFORE the real Brain exists:
it plans ONLY within the Evidence Passport's `allowed_actions`, refuses any
full-commit the passport does not authorize (with a recorded reason), and
emits `decision.*` / `action.*` audit events so the live timeline shows all
four lanes: reading -> verdict -> decision -> action.

Usage:
    python -m guardian.mock.mock_brain --base http://127.0.0.1:8080
        --sensor port-gauge-1 --request valve.full_open --target valve-1
"""
from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple


def _get(base: str, path: str, timeout: float = 5.0) -> dict:
    url = base.rstrip("/") + path
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            return {"_http": exc.code, **json.loads(exc.read().decode("utf-8"))}
        except Exception:
            return {"_http": exc.code}
    except Exception as exc:
        return {"_error": str(exc)}


def _post(base: str, path: str, payload: dict, timeout: float = 5.0) -> Tuple[int, dict]:
    url = base.rstrip("/") + path
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
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


def latest_verdict_for(base: str, sensor_id: str, since: int = 0,
                       timeout_s: float = 10.0,
                       reading_id: str = "") -> Optional[dict]:
    """Poll the audit tail until a verdict for `sensor_id` appears (R2).

    When `reading_id` is given, only that exact reading satisfies the wait —
    so the Brain acts on the ATTACK verdict, never on an earlier calibration
    frame from the same sensor. Otherwise the LATEST verdict wins: the runner
    streams the whole fixture first, so acting on a stale early frame would
    prove nothing.
    """
    deadline = time.time() + timeout_s
    best: Optional[dict] = None
    while time.time() < deadline:
        data = _get(base, f"/v1/verdict?since={since}")
        for ev in data.get("events", []):
            if ev.get("event") == "reading.accepted" and ev.get("sensor_id") == sensor_id:
                if ev.get("evidence_digest"):
                    if not reading_id or ev.get("reading_id") == reading_id:
                        best = ev
                        if reading_id:
                            return best
            if isinstance(ev.get("seq"), int) and ev["seq"] > since:
                since = ev["seq"]
        time.sleep(0.3)
    # No exact-reading target: the runner streams the whole fixture BEFORE the
    # Brain runs, so by the deadline `best` is the LATEST verdict — the one
    # that reflects the full attack, not the first healthy frame.
    return best


def decide(passport: dict, requested: str,
           fallback: Optional[str] = None) -> Dict[str, object]:
    """Pure decision rule (unit-tested, no I/O).

    Passports carry ALLOWED CLASSES (`full` / `reversible` / `precautionary`,
    policy.yaml §allowed_actions); the Brain requests CONCRETE actions
    (`valve.full_open`). `_class_of` maps concrete -> class; an UNKNOWN
    action maps to `full` (fail closed: novel actuation needs TRUSTED).

    A SUSPECT/RESTRICT/MALICIOUS passport physically cannot authorize a
    full-commit: `full` is absent from its `allowed_actions`, so the request
    is refused with a recorded reason and an optional precautionary fallback
    is proposed instead. Do-nothing (refuse with no fallback) is valid.
    """
    allowed: List[str] = list(passport.get("allowed_actions") or [])
    disp = str(passport.get("disposition", "UNKNOWN"))
    pid = str(passport.get("passport_id", "?"))
    wanted = _class_of(requested)
    if wanted in allowed or requested in allowed:
        return {"decision": "proposed", "action": requested,
                "reason": f"within passport {pid} ({disp}): "
                          f"{requested} is class {wanted!r}"}
    reason = (f"REFUSED {requested} (class {wanted!r}): not in passport "
              f"{pid} ({disp}) allowed_actions={allowed}")
    if fallback and (_class_of(fallback) in allowed or fallback in allowed):
        return {"decision": "refused", "action": requested, "reason": reason,
                "fallback": fallback,
                "fallback_reason": f"{fallback} remains permitted (class {_class_of(fallback)!r})"}
    return {"decision": "refused", "action": requested, "reason": reason,
            "fallback": None,
            "fallback_reason": "no permitted fallback; do-nothing is the safe action"}


# Concrete action -> authority class. Unknown actions fail closed to `full`.
_ACTION_CLASS = {
    "valve.full_open": "full", "valve.full_close": "full",
    "valve.open": "full", "valve.close": "full",
    "pump.on": "full", "grid.disconnect": "full",
    "signal.override": "full",
    "valve.partial_close": "reversible", "valve.partial_open": "reversible",
    "barrier.partial_close": "reversible", "signal.hold": "reversible",
    "route.priority": "reversible",
    "pump.standby": "precautionary", "barrier.hold": "precautionary",
}


def _class_of(action: str) -> str:
    if action in _ACTION_CLASS:
        return _ACTION_CLASS[action]
    a = action.lower()
    if "full" in a or a.endswith((".open", ".close", ".on", ".off")):
        return "full"          # fail closed: novel actuation needs TRUSTED
    if "partial" in a or "hold" in a or "standby" in a or "priority" in a:
        return "reversible"
    return "full"


def main() -> None:
    p = argparse.ArgumentParser(prog="mock_brain", description="Brain stand-in: plan within the passport")
    p.add_argument("--base", default="http://127.0.0.1:8080")
    p.add_argument("--sensor", default="port-gauge-1", help="sensor whose verdict to act on")
    p.add_argument("--reading", default="", help="exact reading_id to act on (attack frame, not calibration)")
    p.add_argument("--request", default="valve.full_open", help="desired full-commit action")
    p.add_argument("--target", default="valve-1")
    p.add_argument("--fallback", default="barrier.partial_close")
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--since", type=int, default=0,
                   help="audit cursor: ignore events at or before this seq (this run only)")
    args = p.parse_args()

    print(f"[mock_brain] waiting for verdict on {args.sensor} (since seq {args.since}) ...")
    verdict = latest_verdict_for(args.base, args.sensor, since=args.since,
                                 timeout_s=args.timeout,
                                 reading_id=args.reading)
    if not verdict:
        print(f"[mock_brain] no verdict for {args.sensor} within {args.timeout}s; do-nothing.")
        raise SystemExit(2)
    digest = verdict.get("evidence_digest", "")
    st, passport = _post(args.base, "/v1/passport", {"evidence_digest": digest})
    if st != 200 or "passport_id" not in passport:
        print(f"[mock_brain] passport failed [{st}]: {passport}")
        raise SystemExit(2)
    print(f"[mock_brain] passport {passport['passport_id']} "
          f"{passport.get('disposition')} T={passport.get('trust')} "
          f"allowed={passport.get('allowed_actions')}")

    d = decide(passport, args.request, args.fallback)
    print(f"[mock_brain] decision: {d['decision']} {d['action']}: {d['reason']}")
    _post(args.base, "/v1/decision", {
        "decision": d["decision"], "sensor_id": args.sensor,
        "zone": verdict.get("zone"), "passport_id": passport["passport_id"],
        "disposition": passport.get("disposition"), "trust": passport.get("trust"),
        "action": d["action"], "reason": d["reason"],
        "fallback": d.get("fallback"), "target": args.target,
    })
    acted = d["action"] if d["decision"] == "proposed" else d.get("fallback")
    if acted:
        st, body = _post(args.base, "/v1/action", {
            "action_id": f"a-{args.sensor}-1", "idempotency_key": f"a-{args.sensor}-1",
            "passport_id": passport["passport_id"], "evidence_digest": digest,
            "target": args.target, "target_version": "v3",
            "action": acted, "result": "requested",
        })
        print(f"[mock_brain] action.requested {acted} [{st}]: {body}")
    else:
        print("[mock_brain] do-nothing: no permitted action; refusal is logged.")


if __name__ == "__main__":
    main()
