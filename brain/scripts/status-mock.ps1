[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"
$BrainDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $BrainDir
try { python .\scripts\mock_runtime.py status; exit $LASTEXITCODE }
finally { Pop-Location }
