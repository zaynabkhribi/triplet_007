# AEGIS LOOP — Task 7.3E-1: local live three-layer launcher (Brain-owned).
#
# Starts on this Windows PC, in this order:
#   1. Real Guardian  (guardian/src, `python -m guardian`, HTTP loopback :8090)
#   2. Real Twin      (twin/src,      `python src/twin.py serve` :8080)
#   3. Real City Brain(app.main:app  via uvicorn :8000) with its configured
#      background workers (Orion ingest + Guardian shadow reconciliation),
#      using the Real-Readonly environment (.env.real-readonly).
#
# SAFETY (first live integration milestone):
#   * ACTUATOR_EXECUTION_ENABLED=false  — no real actuation.
#   * OPERATIONAL_AUTO_APPROVE=false    — no automatic approvals.
#   * Guardian Shadow reconciliation is verification-only; it can never grant
#     TRUSTED (structurally zero, enforced in app/integration/guardian_compat.py).
#   * No mock fallback: real entry points only.
#
# The script only READS secrets (Twin K1/K2 in twin/secrets.json, Guardian
# integration token in brain/.env.real-readonly) and never prints their values.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\start-real-local.ps1
# Optional: -SkipPreflight  (not recommended)

[CmdletBinding()]
param(
    [switch]$SkipPreflight
)

$ErrorActionPreference = "Stop"

# --- Locate the repository -------------------------------------------------
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$BrainDir = Join-Path $RepoRoot "brain"
$GuardianDir = Join-Path $RepoRoot "guardian"
$TwinDir = Join-Path $RepoRoot "twin"

$env:PYTHONUTF8 = "1"

Write-Host "=== AEGIS LOOP local launcher ===" -ForegroundColor Cyan
Write-Host "Repository: $RepoRoot"

# --- Locate Python ---------------------------------------------------------
$Python = $null
foreach ($candidate in @(
        (Join-Path $BrainDir ".venv\Scripts\python.exe"),
        (Join-Path $RepoRoot ".venv\Scripts\python.exe"),
        "python"
    )) {
    try {
        $probe = & $candidate --version 2>$null
        if ($LASTEXITCODE -eq 0) { $Python = $candidate; break }
    } catch { continue }
}
if (-not $Python) {
    Write-Host "PREFLIGHT FAIL: no usable Python interpreter found." -ForegroundColor Red
    exit 1
}
Write-Host ("Python: {0} ({1})" -f (& $Python --version), $Python)

# --- Preflight checks ------------------------------------------------------
if (-not $SkipPreflight) {
    Write-Host "--- Preflight ---"

    # 1. Configuration and secret presence (never print values).
    $checks = @(
        @{ Path = (Join-Path $BrainDir ".env.real-readonly"); What = "Brain Real-Readonly env (.env.real-readonly)" },
        @{ Path = (Join-Path $BrainDir "config\city.real-readonly.yaml"); What = "city registry (city.real-readonly.yaml)" },
        @{ Path = (Join-Path $BrainDir "config\devices.real-readonly.yaml"); What = "device allowlist (devices.real-readonly.yaml)" },
        @{ Path = (Join-Path $BrainDir "config\incidents.real-readonly.yaml"); What = "incident rules" },
        @{ Path = (Join-Path $GuardianDir "config.yaml"); What = "Guardian config.yaml" },
        @{ Path = (Join-Path $GuardianDir "ngsi.yaml"); What = "Guardian ngsi.yaml" },
        @{ Path = (Join-Path $TwinDir "config.json"); What = "Twin config.json" },
        @{ Path = (Join-Path $TwinDir "secrets.json"); What = "Twin secrets.json (K1/K2 per device)" }
    )
    $failed = $false
    foreach ($check in $checks) {
        if (Test-Path $check.Path) {
            Write-Host ("  [ok]   {0}" -f $check.What) -ForegroundColor Green
        } else {
            Write-Host ("  [MISS] {0} -> {1}" -f $check.What, $check.Path) -ForegroundColor Red
            $failed = $true
        }
    }
    if ($failed) {
        Write-Host "PREFLIGHT FAIL: missing files above. Fill them in before the first live run." -ForegroundColor Red
        if (-not (Test-Path (Join-Path $TwinDir "secrets.json"))) {
            Write-Host "  twin/secrets.json must contain per-device k1/k2 credentials from the Twin team." -ForegroundColor Yellow
            Write-Host "  Shape: { \"<device_id>\": { \"k1\": \"...\", \"k2\": \"...\" } }  (never commit it)" -ForegroundColor Yellow
        }
        exit 1
    }

    # 2. Brain env safety pins (parse without printing values).
    $envLines = Get-Content (Join-Path $BrainDir ".env.real-readonly")
    $envMap = @{}
    foreach ($line in $envLines) {
        if ($line -match '^\s*([A-Z0-9_]+)\s*=(.*)$') { $envMap[$Matches[1]] = $Matches[2] }
    }
    $pinErrors = @()
    if ($envMap["ACTUATOR_EXECUTION_ENABLED"] -ne "false") {
        $pinErrors += "ACTUATOR_EXECUTION_ENABLED must be 'false' for the first live run"
    }
    if ($envMap["GUARDIAN_INTEGRATION_TOKEN"] -and $envMap["GUARDIAN_INTEGRATION_TOKEN"].Trim().Length -lt 8) {
        $pinErrors += "GUARDIAN_INTEGRATION_TOKEN present but too short"
    }
    if ($envMap["ORION_BASE_URL"] -notmatch '^https://') {
        $pinErrors += "ORION_BASE_URL must use HTTPS (hosted Orion broker)"
    }
    if (-not $envMap["GUARDIAN_ALLOW_LOOPBACK_HTTP"]) {
        $pinErrors += "GUARDIAN_ALLOW_LOOPBACK_HTTP must be set to 'true' for this local dev run (Guardian serves plain HTTP on loopback; Brain otherwise requires HTTPS)"
    }
    if ($envMap["ENVIRONMENT"] -eq "production") {
        $pinErrors += "ENVIRONMENT=production is not valid for a local exercise"
    }
    if ($pinErrors.Count -gt 0) {
        $pinErrors | ForEach-Object { Write-Host ("  [PIN]  {0}" -f $_) -ForegroundColor Red }
        exit 1
    }
    Write-Host "  [ok]   safety pins verified (no values printed)" -ForegroundColor Green

    # 3. Network / certificate prerequisites (no requests sent yet beyond a
    #    TLS handshake check against the hosted Orion broker).
    $orionUrl = $envMap["ORION_BASE_URL"]
    try {
        $null = [System.Uri]::new($orionUrl)
    } catch {
        Write-Host "PREFLIGHT FAIL: ORION_BASE_URL is not a valid URL." -ForegroundColor Red
        exit 1
    }
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $iar = $tcp.BeginConnect($orionUrl.Host, $orionUrl.Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(5000)) { $tcp.Close(); throw "timeout" }
        $tcp.EndConnect($iar)
        $tcp.Close()
        Write-Host ("  [ok]   Orion host reachable: {0}:{1}" -f $orionUrl.Host, $orionUrl.Port) -ForegroundColor Green
    } catch {
        Write-Host ("  [WARN] Orion host not reachable yet ({0}); the run can still start but ingestion will fail until it is." -f $_.Exception.Message) -ForegroundColor Yellow
    }
    if ($orionUrl.Scheme -eq "https") {
        # Verify the hosted broker presents a publicly verifiable certificate
        # chain BEFORE any Brain process relies on it. No bypass is used.
        try {
            $null = & $Python -c "import ssl,socket;ctx=ssl.create_default_context();s=socket.create_connection(('$($orionUrl.Host)',$($orionUrl.Port)),5);ss=ctx.wrap_socket(s,server_hostname='$($orionUrl.Host)');print('TLS ok:',ss.version());ss.close()"
            if ($LASTEXITCODE -ne 0) { throw "handshake failed" }
            Write-Host "  [ok]   Orion TLS certificate validates against system roots" -ForegroundColor Green
        } catch {
            Write-Host "PREFLIGHT FAIL: Orion TLS certificate could not be verified (no insecure fallback)." -ForegroundColor Red
            exit 1
        }
    }
}

# --- Start Real Guardian ---------------------------------------------------
$GuardianLogDir = Join-Path $BrainDir "logs"
New-Item -ItemType Directory -Force -Path $GuardianLogDir | Out-Null
Write-Host "--- Starting Real Guardian (python -m guardian, port 8090) ---" -ForegroundColor Cyan
$guardianProc = Start-Process -FilePath $Python `
    -ArgumentList "-m", "guardian", "--port", "8090" `
    -WorkingDirectory (Join-Path $GuardianDir "src") `
    -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $GuardianLogDir "real-guardian.out.log") `
    -RedirectStandardError (Join-Path $GuardianLogDir "real-guardian.err.log") `
    -PassThru
Write-Host ("  Guardian PID: {0}" -f $guardianProc.Id)

# --- Start Real Twin -------------------------------------------------------
Write-Host "--- Starting Real Twin (python src\twin.py serve, port 8080) ---" -ForegroundColor Cyan
$twinProc = Start-Process -FilePath $Python `
    -ArgumentList "src\twin.py", "serve", "--port", "8080" `
    -WorkingDirectory $TwinDir `
    -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $GuardianLogDir "real-twin.out.log") `
    -RedirectStandardError (Join-Path $GuardianLogDir "real-twin.err.log") `
    -PassThru
Write-Host ("  Twin PID: {0}" -f $twinProc.Id)

# --- Wait for Guardian readiness ------------------------------------------
Write-Host "Waiting for Guardian readiness (GET /healthz on 127.0.0.1:8090)..."
$guardianReady = $false
foreach ($i in 1..30) {
    Start-Sleep -Seconds 1
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8090/healthz" -UseBasicParsing -TimeoutSec 2
        if ($resp.StatusCode -eq 200) { $guardianReady = $true; break }
    } catch { continue }
}
if ($guardianReady) {
    Write-Host "  [ok] Guardian is live at http://127.0.0.1:8090" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Guardian /healthz not reachable after 30s — check brain\logs\real-guardian.err.log" -ForegroundColor Yellow
}

# --- Start City Brain (Real-Readonly configuration) -------------------------
Write-Host "--- Starting City Brain (Real-Readonly, uvicorn app.main:app on :8000) ---" -ForegroundColor Cyan
$brainEnvFile = Join-Path $BrainDir ".env.real-readonly"
# Brain's Settings reads `.env` in its working directory by default; point
# it at the dedicated Real-Readonly file via ENV_FILE so the demo .env is
# never touched and mock switches cannot leak into the real exercise.
$env:ENV_FILE = $brainEnvFile
$brainProc = Start-Process -FilePath $Python `
    -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000" `
    -WorkingDirectory $BrainDir `
    -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $GuardianLogDir "real-brain.out.log") `
    -RedirectStandardError (Join-Path $GuardianLogDir "real-brain.err.log") `
    -PassThru
Write-Host ("  Brain PID: {0}" -f $brainProc.Id)

# --- Wait for Brain readiness ----------------------------------------------
Write-Host "Waiting for Brain readiness (GET /health/live on 127.0.0.1:8000)..."
$brainReady = $false
foreach ($i in 1..40) {
    Start-Sleep -Seconds 1
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8000/health/live" -UseBasicParsing -TimeoutSec 2
        if ($resp.StatusCode -eq 200) { $brainReady = $true; break }
    } catch { continue }
}
if ($brainReady) {
    Write-Host "  [ok] Brain API is live at http://127.0.0.1:8000" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Brain /health/live not reachable after 40s — check brain\logs\real-brain.err.log" -ForegroundColor Yellow
}

# --- Status summary --------------------------------------------------------
Write-Host ""
Write-Host "=== Local live stack status ===" -ForegroundColor Cyan
$pidFile = Join-Path $BrainDir "logs\real-local.pids"
Set-Content -Path $pidFile -Value @($guardianProc.Id, $twinProc.Id, $brainProc.Id)
Write-Host ("Guardian : http://127.0.0.1:8090  (healthz={0}, PID={1})" -f $(if ($guardianReady) {"up"} else {"??"}), $guardianProc.Id)
Write-Host ("Twin     : http://127.0.0.1:8080  (Scenario Control page, PID={0})" -f $twinProc.Id)
Write-Host ("Brain    : http://127.0.0.1:8000  (live={0}, PID={1})" -f $(if ($brainReady) {"up"} else {"??"}), $brainProc.Id)
Write-Host ""
Write-Host "Logs: brain\logs\real-{guardian,twin,brain}.{out,err}.log"
Write-Host "Next: .\scripts\check-real-local.ps1   (verifies cross-layer data flow)"
Write-Host "Stop: .\scripts\stop-real-local.ps1"
