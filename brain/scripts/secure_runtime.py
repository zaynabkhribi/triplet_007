"""Windows-only controlled service provisioning; secrets stay in DPAPI storage.

Run from brain with the installed Python (psutil required). No Twin operations.
Encrypted profiles preserve the original process environment, argv and cwd.
"""

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

import psutil

BRAIN = Path(__file__).resolve().parents[1]
STORE = Path(os.environ.get("LOCALAPPDATA", str(BRAIN))) / "AEGISCITY" / "runtime"
PORTS = {"guardian": 8090, "brain": 8000}


class RuntimeFailure(RuntimeError):
    """Only fixed, non-secret operational diagnostics may use this type."""


class Blob(ctypes.Structure):
    _fields_ = [("size", ctypes.c_ulong), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def crypt(data, decrypt=False):
    buffer = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    target = Blob()
    function = (
        ctypes.windll.crypt32.CryptUnprotectData
        if decrypt
        else ctypes.windll.crypt32.CryptProtectData
    )
    if not function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target)):
        raise RuntimeFailure("DPAPI operation failed")
    try:
        return ctypes.string_at(target.data, target.size)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(target.data, ctypes.c_void_p))


def save(value):
    STORE.mkdir(parents=True, exist_ok=True)
    # Restrict inheritance before writing any encrypted profile.
    account = subprocess.check_output(["whoami"], text=True).strip()
    subprocess.run(
        ["icacls", str(STORE), "/inheritance:r", "/grant:r", f"{account}:(OI)(CI)F"],
        check=True,
        capture_output=True,
    )
    temporary = STORE / "profiles.pending"
    temporary.write_bytes(crypt(json.dumps(value).encode()))
    temporary.replace(STORE / "profiles.dpapi")


def load():
    return json.loads(crypt((STORE / "profiles.dpapi").read_bytes(), decrypt=True))


def listener(name):
    ids = {
        c.pid
        for c in psutil.net_connections(kind="tcp")
        if c.status == "LISTEN" and c.laddr.port == PORTS[name]
    }
    if len(ids) > 1:
        raise RuntimeFailure("Multiple listener processes; refusing")
    return psutil.Process(ids.pop()) if ids else None


def capture(name):
    process = listener(name)
    if process is None:
        raise RuntimeFailure(f"{name} listener missing")
    argv = process.cmdline()
    expected = ["-m", "guardian"] if name == "guardian" else ["-m", "uvicorn", "app.main:app"]
    if argv[1 : 1 + len(expected)] != expected:
        raise RuntimeFailure("Unexpected service command; refusing")
    return {
        "pid": process.pid,
        "created": process.create_time(),
        "exe": process.exe(),
        "argv": argv,
        "cwd": process.cwd(),
        "env": process.environ(),
    }


def signal_console(pid):
    """Runs in a disposable child. Never sends CTRL+C to a shared service console."""
    kernel = ctypes.windll.kernel32
    kernel.FreeConsole()
    if not kernel.AttachConsole(pid):
        raise RuntimeFailure("Cannot attach service console; operator Ctrl+C required")
    try:
        ids = (ctypes.c_ulong * 64)()
        count = kernel.GetConsoleProcessList(ids, 64)
        if count > 64 or count == 0:
            raise RuntimeFailure("Cannot establish console isolation")
        for other in ids[:count]:
            if other in {pid, os.getpid()}:
                continue
            if psutil.Process(other).name().lower() not in {
                "powershell.exe",
                "pwsh.exe",
                "cmd.exe",
            }:
                raise RuntimeFailure("Shared console; operator Ctrl+C required")
        kernel.SetConsoleCtrlHandler(None, True)
        if not kernel.GenerateConsoleCtrlEvent(0, 0):
            raise RuntimeFailure("Console signal failed")
        time.sleep(0.5)
    finally:
        kernel.FreeConsole()


def start(name, profiles, observe=False):
    profile = profiles[name]
    if listener(name):
        raise RuntimeFailure("Port occupied; refusing duplicate service")
    if psutil.pid_exists(profile["pid"]):
        previous = psutil.Process(profile["pid"])
        if previous.create_time() == profile["created"]:
            raise RuntimeFailure("Previous service is still draining; refusing duplicate process")
    env = profile["env"].copy()
    if name == "guardian":
        env["GUARDIAN_HMAC_KEY"] = profiles["key"]
    else:
        env.update(
            GUARDIAN_PASSPORT_HMAC_KEY=profiles["key"],
            ENV_FILE=str(BRAIN / ".env.real-readonly"),
            ACTUATOR_EXECUTION_ENABLED="false",
            OPERATIONAL_AUTO_APPROVE="false",
        )
        env["GUARDIAN_PASSPORT_ENABLED"] = "false"
        if observe:
            if time.time() - profiles.get("signature_verified_at", 0) > 600:
                raise RuntimeFailure(
                    "Fresh real signature verification required before observation mode"
                )
            env.update(
                GUARDIAN_PASSPORT_ENABLED="true",
                GUARDIAN_PASSPORT_MAX_EVIDENCE_AGE_SECONDS="30",
                INCIDENT_RULES_FILE="config/incidents.real-zoneb.candidate.yaml",
                DECISION_POLICY_FILE="config/policies.real-zoneb.candidate.yaml",
                ORION_ENTITY_PREFIX="",
                ORION_ACTUATOR_SECRETS_FILE=str(BRAIN.parent / "twin" / "secrets.json"),
            )
    logs = BRAIN / "logs"
    logs.mkdir(exist_ok=True)
    stamp = time.time_ns()
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    with (
        (logs / f"secure-{name}-{stamp}.out.log").open("wb") as out,
        (logs / f"secure-{name}-{stamp}.err.log").open("wb") as err,
    ):
        process = subprocess.Popen(
            profile["argv"],
            executable=profile["exe"],
            cwd=profile["cwd"],
            env=env,
            stdout=out,
            stderr=err,
            stdin=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            startupinfo=startup,
        )
    for _ in range(45):
        if process.poll() is not None:
            raise RuntimeFailure(f"{name} exited; inspect secure service log locally")
        current = listener(name)
        if current and current.pid == process.pid:
            print(
                f"{name} started PID={process.pid}; diagnostics: logs/secure-{name}-{stamp}.*.log"
            )
            return
        time.sleep(1)
    raise RuntimeFailure("Service listener timeout; no automatic fallback or key change")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["provision", "restart", "start", "verify", "signal"])
    parser.add_argument("service", nargs="?", choices=["guardian", "brain"])
    parser.add_argument("--pid", type=int)
    parser.add_argument("--observe", action="store_true")
    args = parser.parse_args()
    if args.action == "signal":
        signal_console(args.pid)
        return
    if args.action == "provision":
        if (STORE / "profiles.dpapi").exists():
            raise RuntimeFailure("Provisioned profile exists; refusing implicit rotation")
        profiles = {name: capture(name) for name in PORTS}
        profiles["key"] = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        save(profiles)
        print("256-bit key and original service environments protected with current-user DPAPI")
        return
    profiles = load()  # No missing-secret fallback.
    if args.action == "verify":
        env = profiles["brain"]["env"].copy()
        env.update(
            GUARDIAN_PASSPORT_HMAC_KEY=profiles["key"],
            GUARDIAN_PASSPORT_ENABLED="false",
            ACTUATOR_EXECUTION_ENABLED="false",
            OPERATIONAL_AUTO_APPROVE="false",
        )
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(BRAIN / "scripts" / "verify-real-passport.ps1"),
            ],
            cwd=BRAIN,
            env=env,
            capture_output=True,
            text=True,
        )
        print(result.stdout)
        verified = (
            result.returncode == 0
            and "SIGNATURE VERIFICATION: VALID" in result.stdout
            and "\nDEFAULT_KEY_NOT_MATCHED\n" in result.stdout
            and "digest match    = True" in result.stdout
            and "Passport disposition       : TRUSTED" in result.stdout
        )
        if verified:
            profiles["signature_verified_at"] = time.time()
            save(profiles)
        else:
            print("Live verification incomplete; observation mode remains gated")
        sys.exit(0 if verified else 1)
    if not args.service:
        raise RuntimeFailure("Service is required")
    if args.observe and (
        args.service != "brain" or time.time() - profiles.get("signature_verified_at", 0) > 600
    ):
        raise RuntimeFailure("Fresh verification required BEFORE stopping Brain")
    if args.action == "restart":
        current = capture(args.service)
        original = profiles[args.service]
        if any(current[k] != original[k] for k in ("exe", "argv", "cwd")):
            raise RuntimeFailure("Service identity changed; refusing restart")
        # Preserve latest settings, not stale captured settings, except explicit safety pins/key.
        profiles[args.service] = current
        save(profiles)
        subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "signal", "--pid", str(current["pid"])],
            check=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        psutil.Process(current["pid"]).wait(timeout=120)
    start(args.service, profiles, args.observe)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Never print arbitrary exception values or captured environments.
        if isinstance(exc, RuntimeFailure):
            print(str(exc), file=sys.stderr)
        print(
            f"secure-runtime FAILED ({type(exc).__name__}); no secret values displayed",
            file=sys.stderr,
        )
        sys.exit(1)
