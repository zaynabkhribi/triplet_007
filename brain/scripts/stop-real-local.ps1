# AEGIS LOOP — Task 7.3E-1: stop the local live three-layer stack (Brain-owned).
#
# Gracefully stops the processes started by start-real-local.ps1. Does NOT
# touch any database file: Brain's isolated SQLite (real_integration.db /
# city_brain.db) is left in place, so restarting loses nothing.

[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = "SilentlyContinue"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

# PIDs recorded by the starter (best effort; the starter writes them on run).
$pidFile = Join-Path $RepoRoot "brain\logs\real-local.pids"
$targets = @()

if (Test-Path $pidFile) {
    foreach ($line in Get-Content $pidFile) {
        if ($line -match '^\s*(\d+)\s*$') { $targets += [int]$Matches[1] }
    }
}

# Fallback: discover by listening port (8090 guardian, 8080 twin, 8000 brain).
if ($targets.Count -eq 0) {
    foreach ($port in @(8090, 8080, 8000)) {
        $conn = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($conn) { $targets += $conn.OwningProcess }
    }
}

foreach ($procId in $targets) {
    $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Host ("Stopping PID {0} ({1})..." -f $procId, $proc.ProcessName)
        if ($Force) {
            Stop-Process -Id $procId -Force
        } else {
            # Gentle first: SIGTERM equivalent for console children.
            Stop-Process -Id $procId -Force:$false
            Start-Sleep -Seconds 2
            if (Get-Process -Id $procId -ErrorAction SilentlyContinue) {
                Stop-Process -Id $procId -Force
            }
        }
    } else {
        Write-Host ("PID {0} already gone." -f $procId)
    }
}
Remove-Item $pidFile -ErrorAction SilentlyContinue
Write-Host "Local live stack stopped. Databases preserved."
