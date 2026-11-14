"""Isolated Windows mock-stack lifecycle; secrets stay in current-user DPAPI."""

import argparse
import base64
import ctypes
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

import httpx
import psutil

ROOT = Path(__file__).resolve().parents[1]
STORE = Path(os.environ.get("LOCALAPPDATA", str(ROOT))) / "AEGISCITY" / "mock-runtime.dpapi"
SERVICES = {
    "brain": (8001, "app.main:app", "/health/ready"),
    "twin": (8101, "mocks.mock_twin:app", "/health"),
    "guardian": (8102, "mocks.mock_guardian:app", "/health"),
}


class Blob(ctypes.Structure):
    _fields_ = [("size", ctypes.c_ulong), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def crypt(data: bytes, decrypt: bool = False) -> bytes:
    buffer = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    target = Blob()
    function = (
        ctypes.windll.crypt32.CryptUnprotectData
        if decrypt
        else ctypes.windll.crypt32.CryptProtectData
    )
    if not function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target)):
        raise RuntimeError("DPAPI operation failed")
    try:
        return ctypes.string_at(target.data, target.size)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(target.data, ctypes.c_void_p))


def save(profile: dict) -> None:
    STORE.parent.mkdir(parents=True, exist_ok=True)
    STORE.write_bytes(crypt(json.dumps(profile).encode("utf-8")))


def load() -> dict:
    return json.loads(crypt(STORE.read_bytes(), decrypt=True))


def listener(port: int):
    matches = [
        psutil.Process(item.pid)
        for item in psutil.net_connections(kind="tcp")
        if item.status == "LISTEN" and item.laddr.port == port
    ]
    if len(matches) > 1:
        raise RuntimeError(f"multiple listeners found on mock port {port}")
    return matches[0] if matches else None


def wait_ready(name: str) -> None:
    port, _, path = SERVICES[name]
    with httpx.Client(timeout=2, trust_env=False) as client:
        for _ in range(40):
            try:
                if client.get(f"http://127.0.0.1:{port}{path}").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
    raise RuntimeError(f"mock {name} readiness timeout")


def start() -> None:
    occupied = [name for name, (port, _, _) in SERVICES.items() if listener(port)]
    if occupied:
        raise RuntimeError("mock port already occupied: " + ", ".join(occupied))
    keys = {name: base64.urlsafe_b64encode(secrets.token_bytes(36)).decode() for name in SERVICES}
    environment = os.environ.copy()
    environment.update(
        ENV_FILE=str(ROOT / ".env.mock"),
        BRAIN_API_KEY=keys["brain"],
        TWIN_API_KEY=keys["twin"],
        GUARDIAN_API_KEY=keys["guardian"],
        PYTHONUTF8="1",
    )
    logs = ROOT / "logs"
    logs.mkdir(exist_ok=True)
    processes = {}
    try:
        for name in ("guardian", "brain", "twin"):
            port, module, _ = SERVICES[name]
            out = (logs / f"mock-{name}.out.log").open("ab")
            err = (logs / f"mock-{name}.err.log").open("ab")
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    module,
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                ],
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            processes[name] = {
                "pid": process.pid,
                "created": psutil.Process(process.pid).create_time(),
            }
            wait_ready(name)
        save({"keys": keys, "processes": processes})
    except Exception:
        for item in processes.values():
            with psutil.Process(item["pid"]).oneshot():
                psutil.Process(item["pid"]).terminate()
        raise
    print("Mock Brain ready: http://127.0.0.1:8001/dashboard")
    print("Mock services: Brain 8001, Twin 8101, Guardian 8102")


def stop() -> None:
    profile = load()
    for name, item in profile["processes"].items():
        if not psutil.pid_exists(item["pid"]):
            continue
        process = psutil.Process(item["pid"])
        if process.create_time() != item["created"]:
            raise RuntimeError(f"PID identity changed for {name}; refusing")
        process.terminate()
    tracked = [
        psutil.Process(item["pid"])
        for item in profile["processes"].values()
        if psutil.pid_exists(item["pid"])
    ]
    _, alive = psutil.wait_procs(
        tracked,
        timeout=15,
    )
    for process in alive:
        process.kill()
    STORE.unlink(missing_ok=True)
    print("Mock stack stopped; real ports and database were not touched")


def status() -> None:
    for name, (port, _, path) in SERVICES.items():
        state = "down"
        try:
            response = httpx.get(f"http://127.0.0.1:{port}{path}", timeout=2, trust_env=False)
            state = "ready" if response.status_code == 200 else f"HTTP {response.status_code}"
        except httpx.HTTPError:
            pass
        print(f"{name}: {state} (127.0.0.1:{port})")


def reset() -> None:
    profile = load()
    key = profile["keys"]["brain"]
    with httpx.Client(timeout=5, trust_env=False) as client:
        response = client.post(
            "http://127.0.0.1:8101/operations/reset",
            headers={"X-API-Key": key},
            json={},
        )
        response.raise_for_status()
    print("Mock scenario reset; real services and databases were not touched")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["start", "stop", "status", "reset"])
    action = parser.parse_args().action
    {"start": start, "stop": stop, "status": status, "reset": reset}[action]()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Mock runtime failed: {type(exc).__name__}", file=sys.stderr)
        sys.exit(1)
