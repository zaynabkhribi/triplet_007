# AEGIS LOOP — readiness and cross-layer data-flow checker (7.3E-5B revision).
#
# Verifies, in order (process health alone is NOT proof of integration):
#   1. Guardian /healthz responds.
#   2. Guardian Orion poller is alive and has cycled (GET /orion/status).
#   3. Orion actually contains us-b-bldg-01 with the two allowlisted attributes
#      (read-only NGSI-v2 GET).
#   4. Guardian /verdicts shows us-b-bldg-01 with per-property dispositions.
#   5. Brain /health/ready responds and the Brain's isolated DB has stored
#      real sensor events for us-b-bldg-01:* (SQL count, read-only).
#   6. Guardian audit-tail accepted events are available.
#   7. REAL reconciliation probe: runs Brain's actual matching code path
#      against live Guardian + persisted DB WITHOUT touching the worker's
#      cursor/pending files. Success requires at least one GENUINE exact
#      digest match; TRUSTED grants must be zero.
#
# Notes for maintainers:
#   * This file MUST be saved with CRLF line endings: Windows PowerShell 5.1
#     does not recognize here-string delimiters in LF-only scripts.
#   * Embedded Python uses SINGLE-QUOTED here-strings (@'...'@) with
#     __TOKEN__ placeholders, so no Python code is ever interpreted by
#     PowerShell.
#
# No writes to Orion, no writes to Guardian, no actuator commands.

[CmdletBinding()]
param(
    [string]$BrainUrl = "http://127.0.0.1:8000",
    [string]$GuardianUrl = "http://127.0.0.1:8090"
)

$ErrorActionPreference = "Continue"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$BrainDir = Join-Path $RepoRoot "brain"
$Python = Join-Path $BrainDir ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) { $Python = "python" }

$failures = 0
function Check($name, $ok, $detail) {
    if ($ok) { Write-Host ("[ok]   {0} {1}" -f $name, $detail) -ForegroundColor Green }
    else { Write-Host ("[FAIL] {0} {1}" -f $name, $detail) -ForegroundColor Red; $script:failures++ }
}

function Run-PythonSnippet([string]$code) {
    # Writes the snippet to a temp file with an explicit UTF-8 no-BOM-ish
    # encoding and executes it; returns raw stdout lines.
    $tmp = Join-Path $env:TEMP ("check_" + [guid]::NewGuid().ToString("N") + ".py")
    [System.IO.File]::WriteAllText($tmp, $code, (New-Object System.Text.UTF8Encoding($false)))
    try {
        $out = & $Python $tmp 2>$null
        return @($out)
    } finally {
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }
}

# Repo path with forward slashes for embedding into Python string literals.
$RepoPy = $RepoRoot -replace '\\', '/'

# 1. Guardian health
try {
    $h = Invoke-RestMethod -Uri "$GuardianUrl/healthz" -TimeoutSec 5
    Check "guardian.healthz" $true ("status={0} policy={1}" -f $h.status, $h.policy_version)
} catch {
    Check "guardian.healthz" $false "not reachable - is Guardian running?"
}

# 2. Guardian Orion poller
try {
    $s = Invoke-RestMethod -Uri "$GuardianUrl/orion/status" -TimeoutSec 5
    $alive = $s.poller -and $s.poller.alive -and $s.poller.cycles -gt 0
    Check "guardian.orion_poller" $alive ("broker={0} cycles={1} errors={2}" -f $s.broker, $s.poller.cycles, @($s.poller.errors).Count)
} catch {
    Check "guardian.orion_poller" $false "orion/status not reachable"
}

# 3. Orion entity contents (read-only GET, contract shape: elementid+type)
$envMap = @{}
$envPath = Join-Path $BrainDir ".env.real-readonly"
if (Test-Path $envPath) {
    foreach ($line in (Get-Content $envPath)) {
        if ($line -match '^\s*([A-Z0-9_]+)\s*=(.*)$') { $envMap[$Matches[1]] = $Matches[2] }
    }
}
$orion = $envMap["ORION_BASE_URL"]
if (-not $orion) {
    Check "orion.us-b-bldg-01" $false "ORION_BASE_URL missing from brain\.env.real-readonly"
} else {
    $pyProbe = @'
import json, sys
import httpx
base = "__ORION__"
r = httpx.get(base + "/v2/entities/us-b-bldg-01", params={"type": "BuildingSensor", "elementid": "us-b-bldg-01"}, timeout=10, verify=True)
if r.status_code != 200:
    print(json.dumps({"ok": False, "why": "HTTP %d" % r.status_code}))
else:
    e = r.json()
    def flat(entity):
        out = {}
        for k, v in entity.items():
            if k in ("id", "type"):
                continue
            out[k] = v.get("value") if isinstance(v, dict) and "value" in v else v
        return out
    f = flat(e)
    smoke = f.get("smokeLevel")
    temp = f.get("temperature")
    stamp = f.get("timestamp")
    # 7.3E-5C: distinguish PRESENT from FRESH. A frozen entity timestamp
    # means the Twin publisher is not ticking; the broker just re-serves
    # its last stored value. Report age instead of claiming live success.
    import datetime as _dt
    age_s = None
    fresh = False
    if isinstance(stamp, str) and stamp.strip():
        try:
            ts = _dt.datetime.fromisoformat(stamp.strip().replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=_dt.timezone.utc)
            age_s = max(0.0, (_dt.datetime.now(_dt.timezone.utc) - ts).total_seconds())
            fresh = age_s <= 120  # Twin ticks every ~5 s; 2 min is generous
        except ValueError:
            pass
    print(json.dumps({"ok": smoke is not None and temp is not None and bool(stamp),
                      "present": bool(smoke is not None and temp is not None),
                      "fresh": fresh, "age_minutes": (round(age_s / 60.0, 1) if age_s is not None else None),
                      "smoke": smoke, "temperature": temp, "timestamp": stamp}))
'@
    $pyProbe = $pyProbe.Replace("__ORION__", $orion)
    $orionJson = $null
    try {
        $orionLines = Run-PythonSnippet $pyProbe
        $orionJson = ($orionLines | Select-Object -Last 1) | ConvertFrom-Json
    } catch { $orionJson = $null }
    if ($null -eq $orionJson) {
        Check "orion.us-b-bldg-01" $false "could not probe Orion (network/TLS/python?)"
    } elseif ($orionJson.present) {
        # Presence and freshness are reported SEPARATELY (7.3E-5C): the
        # entity existing is connectivity; a recent timestamp is live
        # publication. A frozen entity means the Twin publisher is down.
        if ($orionJson.fresh) {
            Check "orion.us-b-bldg-01.fresh" $true ("smokeLevel={0} temperature={1} timestamp={2}" -f $orionJson.smoke, $orionJson.temperature, $orionJson.timestamp)
        } else {
            Check "orion.us-b-bldg-01.fresh" $false ("STALE: entity present but timestamp is {0} minutes old ({1}) - the Twin publisher is NOT ticking. Guardian will mark the device UNTRUSTED (STALE/REPLAY) and freshness gates reject ingestion." -f $orionJson.age_minutes, $orionJson.timestamp)
        }
    } else {
        Check "orion.us-b-bldg-01" $false ("probe rejected: {0}" -f $orionJson.why)
    }
}

# 4. Guardian verdicts for the device
try {
    $v = Invoke-RestMethod -Uri "$GuardianUrl/verdicts" -TimeoutSec 5
    $row = $v."us-b-bldg-01"
    $ok = $null -ne $row
    Check "guardian.verdicts.us-b-bldg-01" $ok ("word={0} reason={1}" -f $row.verdict, $row.reason)
} catch {
    Check "guardian.verdicts.us-b-bldg-01" $false "verdicts feed not reachable"
}

# 5. Brain readiness + stored observations
try {
    $r = Invoke-RestMethod -Uri "$BrainUrl/health/ready" -TimeoutSec 5
    # Brain's /health/ready executes a real DB probe and answers status="ready"
    # (app/api/health.py:26); /health/live answers status="ok". Accept the
    # value the endpoint actually returns on success - both mean reachable.
    $readyOk = ($r.status -eq "ready") -or ($r.status -eq "ok")
    Check "brain.ready" $readyOk ("status={0}" -f $r.status)
} catch {
    Check "brain.ready" $false "not reachable - is Brain running?"
}

$pyDb = @'
import json, os, sqlite3, glob
repo = "__REPO__"
# 7.3E-5C: report every candidate DB and its counts so a missing or
# empty isolated database yields an ACTIONABLE failure line, not blank.
candidates = glob.glob(os.path.join(repo, "brain", "**", "*.db"), recursive=True)
best = None
for c in candidates:
    if "real_integration" in os.path.basename(c):
        best = c
        break
if best is None:
    print(json.dumps({"ok": False, "why": (
        "no isolated real_integration.db found (candidates: %d). "
        "Check DATABASE_URL in brain/.env.real-readonly and Brain's startup "
        "logs for ingest worker errors.") % len(candidates), "db_candidates": len(candidates)}))
else:
    conn = sqlite3.connect("file:%s?mode=ro" % best.replace("\\", "/"), uri=True)
    cur = conn.cursor()
    tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    if "sensor_events" not in tables:
        print(json.dumps({"ok": False, "why": "sensor_events table absent"}))
    else:
        n = cur.execute("SELECT COUNT(*) FROM sensor_events").fetchone()[0]
        target = cur.execute("SELECT COUNT(*) FROM sensor_events WHERE payload LIKE '%us-b-bldg-01%'").fetchone()[0]
        print(json.dumps({"ok": n > 0 and target > 0, "total_events": n, "us_b_bldg_events": target,
                          "db": os.path.basename(best), "why": ("table empty" if n == 0 else "")}))
    conn.close()
'@
$pyDb = $pyDb.Replace("__REPO__", $RepoPy)
$dbJson = $null
try {
    $dbLines = Run-PythonSnippet $pyDb
    $dbJson = ($dbLines | Select-Object -Last 1) | ConvertFrom-Json
} catch { $dbJson = $null }
if ($null -eq $dbJson) {
    Check "brain.stored_observations" $false "could not inspect Brain's isolated DB"
} elseif ($dbJson.ok) {
    Check "brain.stored_observations" $true ("total={0} us_b_bldg={1} db={2}" -f $dbJson.total_events, $dbJson.us_b_bldg_events, $dbJson.db)
} else {
    Check "brain.stored_observations" $false ("{0}" -f $dbJson.why)
}

# 6. Guardian audit-tail accepted events available
$auditCount = 0
try {
    $a = Invoke-RestMethod -Uri "$GuardianUrl/v1/verdict?since=0" -TimeoutSec 5
    $accepted = @($a.events | Where-Object { $_.event -eq "reading.accepted" })
    $auditCount = $accepted.Count
    Check "guardian.audit_events" ($auditCount -gt 0) ("accepted_reading_events={0} total={1}" -f $auditCount, $a.count)
} catch {
    Check "guardian.audit_events" $false "audit tail not reachable"
}

# 7. REAL reconciliation probe (read-only vs the running worker)
$pyRecon = @'
import json, os, sys
repo = "__REPO__"
os.environ["ENV_FILE"] = os.path.join(repo, "brain", ".env.real-readonly")
os.chdir(os.path.join(repo, "brain"))
sys.path.insert(0, os.getcwd())
out = {}
try:
    from app.core.config import get_settings
    from app.integration.guardian_compat import (
        AuditCursor, AuditTailVerifier, PendingEvidenceStore,
    )
    from app.integration.ngsi_twin import load_mapping
    import asyncio

    settings = get_settings()
    mappings = list(load_mapping(settings.snap4city_devices_file).sensors)
    # Concurrency fix (7.3E-4): the RUNNING shadow worker owns the durable
    # cursor and pending store. The probe uses VOLATILE temp paths (cursor
    # at 0, no worker files touched) so it observes evidence without racing.
    import tempfile
    tmpd = tempfile.gettempdir()
    cursor = AuditCursor(os.path.join(tmpd, "check-probe-cursor-unused.json"))
    store = PendingEvidenceStore(os.path.join(tmpd, "check-probe-pending-unused.jsonl"))
    v = AuditTailVerifier(settings, mappings, cursor, pending_store=store)
    from app.schemas.sensor import SensorReading
    import sqlite3, glob
    dbs = glob.glob(os.path.join(repo, "brain", "**", "real_integration.db"), recursive=True)
    readings = []
    if dbs:
        conn = sqlite3.connect("file:%s?mode=ro" % dbs[0].replace("\\", "/"), uri=True)
        for (payload,) in conn.execute("SELECT payload FROM sensor_events"):
            try:
                readings.append(SensorReading.model_validate(json.loads(payload)["event"]))
            except Exception:
                pass
        conn.close()
    async def run2():
        return await v.verify_against(await v.fetch_events(), readings)
    result = asyncio.run(run2())
    out.update(result)
    out["probe"] = "ok"
except Exception as exc:
    out = {"probe": "failed", "why": type(exc).__name__ + ": " + str(exc)}
print(json.dumps(out))
'@
$pyRecon = $pyRecon.Replace("__REPO__", $RepoPy)
$reconJson = $null
try {
    $reconLines = Run-PythonSnippet $pyRecon
    $reconJson = ($reconLines | Select-Object -Last 1) | ConvertFrom-Json
} catch { $reconJson = $null }
if ($null -eq $reconJson) {
    Check "brain.audit_reconciliation" $false "probe could not run (env/config missing?)"
} elseif ($reconJson.probe -ne "ok") {
    Check "brain.audit_reconciliation" $false ("probe failed: {0}" -f $reconJson.why)
} else {
    $detail = "exact_matches={0} pending={1} unmatched={2} malformed={3} duplicates={4} probe_cursor={5} trusted_granted={6}" -f `
        $reconJson.verified_matches, $reconJson.unmatched_pending, $reconJson.unmatched, `
        $reconJson.malformed, $reconJson.duplicates, $reconJson.cursor_seq, $reconJson.trusted_granted
    # A SUCCESSFUL reconciliation requires at least one genuine exact match.
    Check "brain.audit_reconciliation" ($reconJson.verified_matches -gt 0) $detail
    Check "brain.zero_trusted_grants" ($reconJson.trusted_granted -eq 0) ("trusted_granted={0}" -f $reconJson.trusted_granted)
    if ($reconJson.gap_detected) {
        Write-Host "[WARN] audit gap detected: Guardian seq stream was discontinuous." -ForegroundColor Yellow
    }
}

Write-Host ""
if ($failures -eq 0) {
    Write-Host "ALL CHECKS PASSED - evidence reconciliation is consuming real audit data." -ForegroundColor Green
    Write-Host "Summary: guardian_audit_events=$auditCount accepted events seen; matching is verification-only."
    Write-Host "TRUSTED authorization grants remain ZERO by construction (no GuardianVerdict is emitted)."
} else {
    Write-Host ("{0} check(s) FAILED. Review brain\logs\real-*.log for details." -f $failures) -ForegroundColor Red
    exit 1
}
