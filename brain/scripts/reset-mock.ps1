[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"
$BrainDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $BrainDir
try { python .\scripts\mock_runtime.py reset; exit $LASTEXITCODE }
finally { Pop-Location }
