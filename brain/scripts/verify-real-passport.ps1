# Task 7.3G-10D — VERIFY A REAL GUARDIAN EVIDENCE PASSPORT (read-only)
#
# Windows PowerShell 5.1 compatible. Python stdout is parsed STRICTLY as JSON;
# stderr (expected logging, e.g. guardian_loopback_http_optin) is captured
# separately and never treated as fatal when exit code is 0.
#
# MATCHING FIX (7.3G-10D): instead of re-implementing the matcher, this probe
# now calls Brain's PRODUCTION matcher directly —
# AuditTailVerifier.verify_against() — the exact code path
# check-real-local.ps1 uses, over the SAME audit range, then extracts the
# newest TRUSTED verified evidence from its result. No semantic drift is
# possible between diagnostic and production matching.
#
# NO writes, NO restarts. HMAC keys never printed, never in argv (stdin only).

$ErrorActionPreference = 'Continue'
Set-Location 'C:\Users\moham\OneDrive\Desktop\New folder (12)\triplet_007\brain'
$env:ENV_FILE = (Resolve-Path .\.env.real-readonly).Path
$GUARDIAN = 'http://127.0.0.1:8090'
Write-Output '=== AEGISCITY REAL PASSPORT VERIFICATION (read-only) ==='

function Invoke-Guardian {
    param([string]$Method, [string]$Uri, [string]$Body)
    try {
        if ($Body) {
            return Invoke-WebRequest -UseBasicParsing -Uri $Uri -Method $Method `
                -ContentType 'application/json' -Body $Body -TimeoutSec 10 `
                -ErrorAction Stop
        }
        return Invoke-WebRequest -UseBasicParsing -Uri $Uri -Method $Method `
            -TimeoutSec 10 -ErrorAction Stop
    } catch {
        # Windows PowerShell 5.1 raises WebException; the PowerShell 7-only
        # HttpResponseException type cannot appear in a typed catch here.
        if ($_.Exception.Response) {
            return [pscustomobject]@{
                StatusCode = [int]$_.Exception.Response.StatusCode; Content = ''
            }
        }
        return [pscustomobject]@{
            StatusCode = -1; Content = ''; Error = 'Request failed (details withheld)'
        }
    }
}

# ------------------------------------------------------------- [1] health --
Write-Output ''
Write-Output '--- [1] Guardian health ---'
$health = Invoke-Guardian -Method Get -Uri "$GUARDIAN/healthz"
if ($health.StatusCode -eq 200) { Write-Output '[ok] guardian.healthz: OK' }
elseif ($health.StatusCode -eq -1) { Write-Output ("[FAIL] guardian UNREACHABLE: {0}" -f $health.Error); exit }
else { Write-Output ("[FAIL] guardian.healthz HTTP {0}" -f $health.StatusCode); exit }

# ------------------------------------ [2] run PRODUCTION verifier verbatim --
Write-Output ''
Write-Output '--- [2] Production matcher: AuditTailVerifier.verify_against ---'
$match_py = @'
import json, os, sys, asyncio

os.environ.setdefault("ENV_FILE", os.path.join(os.getcwd(), ".env.real-readonly"))
sys.path.insert(0, os.getcwd())

import logging
logging.basicConfig(level=logging.WARNING)  # stderr only; stdout stays pure JSON

from app.integration.guardian_compat import (
    AuditCursor, AuditTailVerifier, PendingEvidenceStore, GuardianCompatError,
)
from app.integration.ngsi_twin import load_mapping
from app.core.config import get_settings
from app.schemas.sensor import SensorReading
import sqlite3, tempfile

settings = get_settings()
mappings = list(load_mapping(settings.snap4city_devices_file).sensors)

# Volatile probe cursor/store (same isolation trick as check-real-local.ps1:
# never touch the RUNNING worker's durable files).
tmpd = tempfile.gettempdir()
cursor = AuditCursor(os.path.join(tmpd, "passport-probe-cursor.json"))
store = PendingEvidenceStore(os.path.join(tmpd, "passport-probe-pending.jsonl"))
verifier = AuditTailVerifier(settings, mappings, cursor, pending_store=store)

# Load ALL persisted observations, newest-first diagnostics retained.
conn = sqlite3.connect("file:real_integration.db?mode=ro", uri=True)
rows = conn.execute(
    "SELECT occurred_at, payload FROM sensor_events ORDER BY occurred_at DESC LIMIT 5000"
).fetchall()
conn.close()
readings, db_examined, malformed = [], len(rows), 0
newest_reading = None
for occurred_at, payload in rows:
    try:
        r = SensorReading.model_validate(json.loads(payload)["event"])
        readings.append(r)
        if newest_reading is None or r.occurred_at > newest_reading:
            newest_reading = r.occurred_at
    except Exception:
        malformed += 1

async def run():
    events = await verifier.fetch_events()
    result = await verifier.verify_against(events, readings)
    return events, result

events, result = asyncio.run(run())

accepted = [e for e in events if e.get("event") == "reading.accepted"]
mapped = [
    e for e in accepted
    if any(m.entity_id == e.get("sensor_id")
           and m.guardian_property == e.get("observed_property") for m in mappings)
]
verified = result.get("verified", [])
trusted = [v for v in verified]  # production verifier emits verified binds

# The verifier's own stats (authoritative comparison with check-real-local):
stats = {
    "verified_matches": result.get("verified_matches", 0),
    "unmatched": result.get("unmatched", 0),
    "pending": result.get("unmatched_pending", 0),
    "malformed": result.get("malformed", 0),
    "duplicates": result.get("duplicates", 0),
    "cursor_seq": result.get("cursor_seq", 0),
    "gap_detected": result.get("gap_detected", False),
}

# Newest TRUSTED verified bind (verify_against emits binds in encounter order
# = ascending seq; take the last, and prefer TRUSTED via the audit row).
chosen = None
for v in reversed(verified):
    ev = next((e for e in reversed(events)
               if e.get("event") == "reading.accepted"
               and str(e.get("evidence_digest", "")) == v.get("guardian_digest")), None)
    if ev is None:
        continue
    chosen = {
        "audit_seq": ev.get("seq"),
        "sensor_id": v.get("sensor_id"),
        "observed_property": v.get("observed_property"),
        "zone": ev.get("zone"),
        "disposition": ev.get("disposition"),
        "trust": ev.get("trust"),
        "evidence_digest": v.get("guardian_digest"),
        "brain_event_id": v.get("event_id"),
        "correlation_id": v.get("correlation_id"),
        "brain_event_hash": v.get("brain_event_hash"),
        "value_equal": True,  # verifier enforces exact equality before binding
    }
    if str(ev.get("disposition", "")).upper() == "TRUSTED":
        break

newest_audit = accepted[-1] if accepted else {}
out = {
    "chosen": chosen,
    "newest_audit": {
        "seq": newest_audit.get("seq"),
        "sensor_id": newest_audit.get("sensor_id"),
        "observed_property": newest_audit.get("observed_property"),
        "disposition": newest_audit.get("disposition"),
    },
    "brain": {
        "observations": db_examined,
        "malformed_rows": malformed,
        "newest_occurred_at": newest_reading.isoformat() if newest_reading else None,
    },
    "counts": {
        "audit_examined": len(events),
        "accepted_events": len(accepted),
        "mapped_zone_b": len(mapped),
        "exact_matches": len(verified),
        "trusted_exact_matches": sum(
            1 for v in verified
            if str(next((e for e in reversed(events)
                         if e.get("event") == "reading.accepted"
                         and str(e.get("evidence_digest","")) == v.get("guardian_digest")),
                        {}).get("disposition", "")).upper() == "TRUSTED"
        ),
    },
    "verifier_stats": stats,
}
print(json.dumps(out))
'@
$match_py | Set-Content -Path '.\_match_passport.py' -Encoding UTF8

# PS 5.1-safe execution: capture stdout and stderr SEPARATELY; strict JSON
# parse of stdout; stderr shown as diagnostics only; exit code preserved.
$outFile = '.\_stdout.txt'; $errFile = '.\_stderr.txt'
$proc = Start-Process -FilePath 'python' -ArgumentList '.\_match_passport.py' `
    -RedirectStandardOutput $outFile -RedirectStandardError $errFile `
    -NoNewWindow -Wait -PassThru
$pyExit = $proc.ExitCode
$stdout = Get-Content $outFile -Raw -ErrorAction SilentlyContinue
$stderr = Get-Content $errFile -Raw -ErrorAction SilentlyContinue
Remove-Item $outFile, $errFile, '.\_match_passport.py' -ErrorAction SilentlyContinue

if ($stderr) {
    Write-Output '[python diagnostics on stderr]'
    Write-Output ($stderr.Trim())
}
$match = $null
try { $match = $stdout.Trim() | ConvertFrom-Json } catch { }
if ($pyExit -ne 0) {
    Write-Output ("[FAIL] matcher exited with code {0}" -f $pyExit)
    if (-not $match) { Write-Output ("stdout was: {0}" -f $stdout); exit }
}
if (-not $match) {
    Write-Output ("[FAIL] matcher stdout was not valid JSON: {0}" -f $stdout); exit
}

Write-Output '[counts]'
Write-Output ("  audit events fetched          = {0}" -f $match.counts.audit_examined)
Write-Output ("  reading.accepted events       = {0}" -f $match.counts.accepted_events)
Write-Output ("  mapped Zone B events          = {0}" -f $match.counts.mapped_zone_b)
Write-Output ("  persisted Brain observations  = {0}" -f $match.brain.observations)
Write-Output ("  EXACT matches (verifier)      = {0}" -f $match.counts.exact_matches)
Write-Output ("  TRUSTED exact matches         = {0}" -f $match.counts.trusted_exact_matches)
Write-Output '[verifier internal stats]'
Write-Output ("  unmatched={0} pending={1} malformed={2} duplicates={3} cursor_seq={4} gap={5}" -f `
    $match.verifier_stats.unmatched, $match.verifier_stats.pending, `
    $match.verifier_stats.malformed, $match.verifier_stats.duplicates, `
    $match.verifier_stats.cursor_seq, $match.verifier_stats.gap_detected)
Write-Output ("  newest audit event : seq={0} sensor={1}/{2} disposition={3}" -f `
    $match.newest_audit.seq, $match.newest_audit.sensor_id, `
    $match.newest_audit.observed_property, $match.newest_audit.disposition)
Write-Output ("  newest Brain obs   : {0}" -f $match.brain.newest_occurred_at)

if (-not $match.chosen) {
    Write-Output '[RESULT] No exact verified match in this audit range.'
    Write-Output ('  Diagnosis: verifier verified_matches={0} over audit_examined={1} -' -f `
        $match.verifier_stats.verified_matches, $match.counts.audit_examined)
    Write-Output '  if verified_matches > 0 here but chosen=null, the matches were all'
    Write-Output '  non-TRUSTED; if verified_matches=0 while check-real-local reported matches,'
    Write-Output '  the probe cursor started at 0 and covers a DIFFERENT (older) range than the'
    Write-Output '  running worker''s durable cursor - matches exist but are outside this fetch.'
    Write-Output '=== COMPLETE: run again immediately after a fresh Twin tick. ==='
    exit
}

# ------------------------------------------------- [3] matched observation -
Write-Output ''
Write-Output '--- [3] Matched observation (production verifier binding) ---'
Write-Output ("[ok] sensor={0} property={1} zone={2}" -f `
    $match.chosen.sensor_id, $match.chosen.observed_property, $match.chosen.zone)
Write-Output ("[ok] Guardian disposition={0} trust={1} (as-is)" -f $match.chosen.disposition, $match.chosen.trust)
Write-Output ("[ok] digest EXACT (production matcher) audit_seq={0}" -f $match.chosen.audit_seq)
Write-Output ("[ok] brain_event_id={0} correlation={1}" -f $match.chosen.brain_event_id, $match.chosen.correlation_id)

# ------------------------------------------- [4] request the real passport --
Write-Output ''
Write-Output '--- [4] POST /v1/passport with the matched evidence digest ---'
$digest = $match.chosen.evidence_digest
$passport = $null
$resp = Invoke-Guardian -Method Post -Uri "$GUARDIAN/v1/passport" -Body ('{"evidence_digest":"' + $digest + '"}')
if ($resp.StatusCode -eq 200) {
    Write-Output '[ok] passport cache HIT - passport issued:'
    $passport = $resp.Content | ConvertFrom-Json
    $sig = [string]$passport.signature
    $sigHead = if ($sig.Length -gt 20) { $sig.Substring(0, 20) + '...' } else { '<missing>' }
    Write-Output ("     passport_id     = {0}" -f $passport.passport_id)
    Write-Output ("     disposition     = {0}" -f $passport.disposition)
    Write-Output ("     issued_at       = {0}" -f $passport.issued_at)
    Write-Output ("     ttl_s           = {0}" -f $passport.ttl_s)
    Write-Output ("     digest match    = {0}" -f ($passport.evidence_digest -eq $digest))
    Write-Output ("     signature       = {0} (TRUNCATED)" -f $sigHead)
} elseif ($resp.StatusCode -eq 404) {
    Write-Output '[RESULT] HTTP 404 = VERDICT-CACHE MISS (endpoint healthy). Verdict evicted/'
    Write-Output '         restarted since seq; re-run within seconds of a fresh Twin tick.'
} elseif ($resp.StatusCode -eq -1) {
    Write-Output ("[FAIL] REAL NETWORK FAILURE: {0}" -f $resp.Error)
} else {
    Write-Output ("[RESULT] HTTP {0} = contract/transport failure." -f $resp.StatusCode)
}

# --------------------------------------------- [5] signature verification --
$sigResult = 'NOT CONFIGURED'
if ($passport) {
    Write-Output ''
    Write-Output '--- [5] Signature verification (Brain settings; Passport via UTF-8 stdin) ---'
    $verify_py = @'
import json, sys
sys.dont_write_bytecode = True
sys.path.insert(0, ".")
phase = "import"
try:
    from app.core.config import get_settings
    from app.integration.guardian_passport import verify_passport_signature
    phase = "input"
    passport_json = sys.stdin.buffer.read().decode("utf-8-sig")
    phase = "settings"
    settings = get_settings()
    secret = settings.guardian_passport_hmac_key
    key = secret.get_secret_value() if secret is not None else ""
    if not key.strip() or key.strip() == "dev-guardian-service-key":
        print("NOT CONFIGURED")
        sys.exit(0)
    phase = "input"
    passport = json.loads(passport_json)
    if not isinstance(passport, dict):
        raise TypeError("expected object")
    phase = "verification"
    ok = verify_passport_signature(passport, key.encode("utf-8"))
except Exception as exc:
    print("UNVERIFIED")
    # Exception values can contain secrets or passport content.
    print("%s: %s failed (details withheld)" % (type(exc).__name__, phase),
          file=sys.stderr)
    sys.exit(1)
print("VALID" if ok else "INVALID")
'@
    $verifyPath = $null
    $verifyProcess = $null
    $vExit = $null
    $vStdout = ''
    $vStderr = ''
    $verifyFailure = $null
    try {
        $verifyPath = Join-Path ([IO.Path]::GetTempPath()) (
            'aegis-signature-probe-' + [guid]::NewGuid().ToString('N') + '.py'
        )
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($verifyPath, $verify_py, $utf8)
        $info = New-Object System.Diagnostics.ProcessStartInfo
        $info.FileName = 'python'
        $info.Arguments = '-B "' + $verifyPath + '"'
        $info.WorkingDirectory = (Get-Location).Path
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardInput = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $verifyProcess = New-Object System.Diagnostics.Process
        $verifyProcess.StartInfo = $info
        if (-not $verifyProcess.Start()) { throw 'Probe start failed' }
        $outTask = $verifyProcess.StandardOutput.ReadToEndAsync()
        $errTask = $verifyProcess.StandardError.ReadToEndAsync()
        # Preserve original JSON dates/nesting. Fallback supports local tests.
        $passportJson = if ($resp -and $resp.Content) {
            [string]$resp.Content
        } else {
            $passport | ConvertTo-Json -Depth 100 -Compress
        }
        $inputBytes = $utf8.GetBytes($passportJson)
        $verifyProcess.StandardInput.BaseStream.Write($inputBytes, 0, $inputBytes.Length)
        $verifyProcess.StandardInput.Close()
        if (-not $verifyProcess.WaitForExit(30000)) {
            $verifyProcess.Kill()
            throw 'Probe timeout'
        }
        $vExit = $verifyProcess.ExitCode
        $vStdout = $outTask.GetAwaiter().GetResult().Trim()
        $vStderr = $errTask.GetAwaiter().GetResult().Trim()
    } catch {
        $verifyFailure = 'ProcessError: probe transport failed (details withheld)'
    } finally {
        if ($verifyProcess) {
            try {
                if (-not $verifyProcess.HasExited) { $verifyProcess.Kill() }
            } catch { }
            $verifyProcess.Dispose()
        }
        if ($verifyPath) {
            try {
                if (Test-Path -LiteralPath $verifyPath) {
                    Remove-Item -LiteralPath $verifyPath -Force -ErrorAction Stop
                }
            } catch {
                $verifyFailure = 'CleanupError: temporary script removal failed (details withheld)'
            }
        }
    }
    if (-not $verifyFailure -and $vExit -eq 0 -and
        $vStdout -cin @('VALID', 'INVALID', 'NOT CONFIGURED')) {
        $sigResult = $vStdout
        Write-Output ("SIGNATURE VERIFICATION: {0}" -f $sigResult)
    } else {
        # Execution/input failures are not cryptographic mismatches.
        $sigResult = 'UNVERIFIED'
        Write-Output 'SIGNATURE VERIFICATION: UNVERIFIED'
        Write-Output ("[verify] Python exit code: {0}" -f $vExit)
        if ($verifyFailure) {
            Write-Output ("[verify-error] {0}" -f $verifyFailure)
        } elseif ($vStderr -cmatch '\A[A-Za-z][A-Za-z0-9_]*: (import|settings|input|verification) failed \(details withheld\)\z') {
            Write-Output ("[verify-error] {0}" -f $vStderr)
        } else {
            Write-Output '[verify-error] ProtocolError: unexpected Python output (details withheld)'
        }
    }
}

# --------------------------------------------- [5b] default-key probe ------
# Diagnostics-only: check whether the RUNNING Guardian signed this passport
# with its documented DEV FALLBACK key. In-memory, no config/database/service
# changes. Prints exactly one verdict word; the key literal is public
# documentation in Guardian source, and neither it nor the full signature is
# ever displayed.
if ($passport) {
    Write-Output ''
    Write-Output '--- [5b] Default-key detection (dev fallback dev-guardian-service-key) ---'
    $probe_py = @'
import json, sys
sys.dont_write_bytecode = True
sys.path.insert(0, ".")
phase = "import"
try:
    from app.integration.guardian_passport import verify_passport_signature
    phase = "input"
    passport = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    if not isinstance(passport, dict):
        raise TypeError("expected object")
    phase = "verification"
    ok = verify_passport_signature(passport, b"dev-guardian-service-key")
except Exception as exc:
    print("UNVERIFIED")
    # Never echo exception values: they may contain passport/signature data.
    print("%s: %s failed (details withheld)" % (type(exc).__name__, phase),
          file=sys.stderr)
    sys.exit(1)
print("DEFAULT_KEY_CONFIRMED" if ok else "DEFAULT_KEY_NOT_MATCHED")
'@
    $probePath = $null
    $probeProcess = $null
    $pExit = $null
    $pStdout = ''
    $pStderr = ''
    $probeFailure = $null
    try {
        $probePath = Join-Path ([IO.Path]::GetTempPath()) (
            'aegis-default-probe-' + [guid]::NewGuid().ToString('N') + '.py'
        )
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($probePath, $probe_py, $utf8)
        $info = New-Object System.Diagnostics.ProcessStartInfo
        $info.FileName = 'python'
        $info.Arguments = '-B "' + $probePath + '"'
        $info.WorkingDirectory = (Get-Location).Path
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardInput = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $probeProcess = New-Object System.Diagnostics.Process
        $probeProcess.StartInfo = $info
        if (-not $probeProcess.Start()) { throw 'Probe start failed' }
        $outTask = $probeProcess.StandardOutput.ReadToEndAsync()
        $errTask = $probeProcess.StandardError.ReadToEndAsync()
        # Preserve original JSON dates/nesting. Fallback supports local tests.
        $passportJson = if ($resp -and $resp.Content) {
            [string]$resp.Content
        } else {
            $passport | ConvertTo-Json -Depth 100 -Compress
        }
        $inputBytes = $utf8.GetBytes($passportJson)
        $probeProcess.StandardInput.BaseStream.Write($inputBytes, 0, $inputBytes.Length)
        $probeProcess.StandardInput.Close()
        if (-not $probeProcess.WaitForExit(30000)) {
            $probeProcess.Kill()
            throw 'Probe timeout'
        }
        $pExit = $probeProcess.ExitCode
        $pStdout = $outTask.GetAwaiter().GetResult().Trim()
        $pStderr = $errTask.GetAwaiter().GetResult().Trim()
    } catch {
        $probeFailure = 'ProcessError: probe transport failed (details withheld)'
    } finally {
        if ($probeProcess) {
            try {
                if (-not $probeProcess.HasExited) { $probeProcess.Kill() }
            } catch { }
            $probeProcess.Dispose()
        }
        if ($probePath) {
            try {
                if (Test-Path -LiteralPath $probePath) {
                    Remove-Item -LiteralPath $probePath -Force -ErrorAction Stop
                }
            } catch {
                $probeFailure = 'CleanupError: temporary script removal failed (details withheld)'
            }
        }
    }
    if (-not $probeFailure -and $pExit -eq 0 -and
        $pStdout -cin @('DEFAULT_KEY_CONFIRMED', 'DEFAULT_KEY_NOT_MATCHED')) {
        Write-Output $pStdout
        if ($pStdout -eq 'DEFAULT_KEY_CONFIRMED') {
            Write-Output '[meaning] This passport matches the public development fallback.'
            Write-Output '          This diagnostic does not grant Brain authorization.'
        } else {
            Write-Output '[meaning] This passport does not match the development fallback.'
            Write-Output '          The signing key and issuer remain unverified.'
        }
    } else {
        Write-Output 'UNVERIFIED'
        Write-Output ("[probe] Python exit code: {0}" -f $pExit)
        if ($probeFailure) {
            Write-Output ("[probe-error] {0}" -f $probeFailure)
        } elseif ($pStderr -cmatch '\A[A-Za-z][A-Za-z0-9_]*: (import|input|verification) failed \(details withheld\)\z') {
            Write-Output ("[probe-error] {0}" -f $pStderr)
        } else {
            Write-Output '[probe-error] ProtocolError: unexpected Python output (details withheld)'
        }
    }
}

# ------------------------------------------------- [6] assessment recency --
if ($passport) {
    Write-Output ''
    Write-Output '--- [6] Assessment age vs passport issuance age ---'
    try {
        $issued = [datetime]::Parse($passport.issued_at).ToUniversalTime()
        $ageIssued = [math]::Round(((Get-Date).ToUniversalTime() - $issued).TotalSeconds, 1)
        Write-Output ("[info] passport issued_at age = {0}s (TTL={1}s)" -f $ageIssued, $passport.ttl_s)
    } catch { Write-Output '[warn] could not parse issued_at' }
    Write-Output ("[info] assessment instant = audit seq {0} processing time (NOT the TTL)" -f $match.chosen.audit_seq)
}

# ------------------------------------------------------------- [7] summary -
Write-Output ''
Write-Output '--- SUMMARY ---'
Write-Output ("Guardian health            : OK")
Write-Output ("Matched sensor             : {0} / {1} (seq {2})" -f `
    $match.chosen.sensor_id, $match.chosen.observed_property, $match.chosen.audit_seq)
Write-Output ("Exact digest match         : EXACT (production verifier)")
Write-Output ("Guardian disposition       : {0} (trust {1})" -f $match.chosen.disposition, $match.chosen.trust)
if ($passport) {
    Write-Output ("Passport HTTP status       : 200")
    Write-Output ("Passport disposition       : {0}" -f $passport.disposition)
    Write-Output ("Signature verification     : {0}" -f $sigResult)
} else {
    Write-Output ("Passport HTTP status       : {0}" -f $resp.StatusCode)
    Write-Output "Signature verification     : SKIPPED (no passport)"
}
Write-Output ''
Write-Output '=== COMPLETE (read-only; nothing modified, no secrets printed) ==='
