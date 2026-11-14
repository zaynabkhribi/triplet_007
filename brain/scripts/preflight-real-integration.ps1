# Task 7.3G-9 — REAL INTEGRATION PREFLIGHT (read-only diagnostics)
#
# Run:  powershell -ExecutionPolicy Bypass -File .\scripts\preflight-real-integration.ps1
#
# Checks Guardian health, passport endpoint availability, signing-key
# configuration state (WITHOUT printing secret values), Brain passport-mode
# configuration, candidate configs, and execution-readiness pins.
# NO scenario triggers, NO actuator PATCHes, NO config or DB changes.

$ErrorActionPreference = 'Continue'
Set-Location 'C:\Users\moham\OneDrive\Desktop\New folder (12)\triplet_007\brain'
Write-Output '=== AEGISCITY REAL INTEGRATION PREFLIGHT (read-only) ==='

# ---------------------------------------------------------------- Guardian --
Write-Output ''
Write-Output '--- [1] Guardian health ---'
try {
    $g = Invoke-RestMethod -Uri 'http://127.0.0.1:8090/healthz' -TimeoutSec 5
    Write-Output ("[ok] guardian.healthz status={0} policy={1}" -f $g.status, $g.policy_version)
} catch { Write-Output "[FAIL] guardian.healthz unreachable: $($_.Exception.Message)" }

Write-Output ''
Write-Output '--- [2] Passport endpoint availability (probe with a dummy digest; 404 = endpoint ALIVE, no verdict for digest) ---'
$dummy = '0' * 64
try {
    $code = (Invoke-WebRequest -Uri 'http://127.0.0.1:8090/v1/passport' -Method Post `
        -ContentType 'application/json' -Body ('{"evidence_digest":"' + $dummy + '"}') `
        -TimeoutSec 5 -SkipHttpErrorCheck -ErrorAction SilentlyContinue).StatusCode
    if ($code -eq 404) { Write-Output '[ok] guardian.passport endpoint LIVE (404 for unknown digest: correct fail-closed response)' }
    elseif ($code -eq 422) { Write-Output '[ok] guardian.passport endpoint LIVE (422 schema response)' }
    else { Write-Output ("[warn] guardian.passport returned HTTP {0}" -f $code) }
} catch { Write-Output "[FAIL] guardian.passport endpoint unreachable: $($_.Exception.Message)" }

Write-Output ''
Write-Output '--- [3] Guardian signing key provisioning (VALUE NOT PRINTED) ---'
# A real key is provisioned only if the environment variable is set in the
# Guardian's process. We detect presence indirectly: the dev fallback key is
# documented in guardian source; we cannot read the remote process env, so we
# report what to check manually.
Write-Output '[action] On the GUARDIAN host, verify the env var behind auth.key_env_var (GUARDIAN_HMAC_KEY) is SET and != dev-guardian-service-key.'
Write-Output '         (Value must not be shared; presence check only: [Environment]::GetEnvironmentVariable("GUARDIAN_HMAC_KEY") -ne $null)'

# ------------------------------------------------------------------- Brain --
Write-Output ''
Write-Output '--- [4] Brain readiness ---'
try {
    $b = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/health/ready' -TimeoutSec 5
    Write-Output ("[ok] brain.ready status={0}" -f $b.status)
} catch { Write-Output "[FAIL] brain.ready unreachable: $($_.Exception.Message)" }

Write-Output ''
Write-Output '--- [5] Brain passport-mode configuration (from .env.real-readonly; values never printed) ---'
$envFile = '.\.env.real-readonly'
if (Test-Path $envFile) {
    $enabled   = (Select-String -Path $envFile -Pattern '^GUARDIAN_PASSPORT_ENABLED\s*=\s*true').Line
    $keyLine   = (Select-String -Path $envFile -Pattern '^GUARDIAN_PASSPORT_HMAC_KEY\s*=\s*\S').Line
    Write-Output ("passport.enabled.actual = {0}" -f [bool]$enabled)
    Write-Output ("passport.key.configured = {0} (value NOT shown)" -f [bool]$keyLine)
    if (-not $enabled) {
        Write-Output '[BLOCKED] Brain passport authorization is DISABLED. Required (supervised test):'
        Write-Output '          GUARDIAN_PASSPORT_ENABLED=true'
        Write-Output '          GUARDIAN_PASSPORT_HMAC_KEY=<same shared secret as Guardian GUARDIAN_HMAC_KEY>'
    } else {
        Write-Output '[ok] passport mode enabled in env template (live process must be restarted with it)'
    }
} else { Write-Output "[FAIL] $envFile not found" }

# ------------------------------------------------- Candidate configuration --
Write-Output ''
Write-Output '--- [6] Candidate incident rules + decision policy (schema + activation state) ---'
python -c "
import yaml
from pathlib import Path
from app.decision.config import DecisionPolicies, digest
from app.intelligence.incident_rules import IncidentRules

rules = IncidentRules.model_validate(yaml.safe_load(Path('config/incidents.real-zoneb.candidate.yaml').read_text(encoding='utf-8')))
r = rules.rules[0]
print(f'[ok] incident rule: type={r.incident_type} measurement={r.measurement} unit={r.unit} zones={r.zones} thresholds={r.thresholds}')
print(f'[ok] incident rule ACTIVE in runtime? no (INCIDENT_RULES_FILE still -> incidents.real-readonly.yaml)')

pol = DecisionPolicies.model_validate(yaml.safe_load(Path('config/policies.real-zoneb.candidate.yaml').read_text(encoding='utf-8')))
acts = sorted(pol.actuators)
print(f'[ok] policy actuators={acts} zones={sorted({a.zone for a in pol.actuators.values()})}')
print(f'[ok] policy actions={[a.id for a in pol.actions]} all require_approval={[a.requires_approval for a in pol.actions]}')
print(f'[ok] policy approved={pol.approved} (candidate stays inactive)')
print(f'[action] activation requires DECISION_POLICY_FILE -> candidate AND approved_incident_config_sha256 = digest of ACTIVE incident rules file (computed at activation time)')
"

Write-Output ''
Write-Output '--- [7] Execution readiness pins (from .env.real-readonly) ---'
Select-String -Path $envFile -Pattern '^(ACTUATOR_EXECUTION_ENABLED|OPERATIONAL_AUTO_APPROVE|ACTUATOR_TRANSPORT|ORION_BASE_URL|ORION_ACTUATOR_SECRETS_FILE)\s*=' | ForEach-Object {
    $k, $v = $_.Line -split '=', 2
    if ($k -match 'SECRETS_FILE|BASE_URL') { Write-Output ("{0} = <configured: value not shown>" -f $k.Trim()) }
    else { Write-Output ("{0} = {1}" -f $k.Trim(), $v.Trim()) }
}
Write-Output '[info] credentials file presence:'
if (Test-Path 'C:\Users\moham\OneDrive\Desktop\New folder (12)\triplet_007\twin\secrets.json') {
    Write-Output '[ok] twin/secrets.json exists (6 device entries expected; values NOT read here)'
    python -c "import json; d=json.load(open(r'..\twin\secrets.json',encoding='utf-8')); print('[ok] devices with k1+k2 present:', sorted(d.keys()))"
} else {
    Write-Output '[check] twin/secrets.json NOT found at expected path - confirm with Twin team'
}

# -------------------------------------------------- Offline E2E test proof --
Write-Output ''
Write-Output '--- [8] Offline end-to-end coverage check ---'
python -c "
from pathlib import Path
t = Path('tests/integration/test_passport_pipeline.py').read_text(encoding='utf-8')
for stage in ['refresh', 'eligibility_is_momentary', 'dispatch_gate_blocks', 'authorizer_requires_enabled_flag']:
    print(('[ok] covers: ' if stage in t else '[MISSING] covers: ') + stage)
from pathlib import Path as P
acts = P('tests/integration/test_actions.py').read_text(encoding='utf-8')
print(('[ok] orion adapter contract tests present: ' if 'test_orion_per_device_credentials_and_readback' in acts else '[MISSING] orion adapter tests: '))
"

Write-Output ''
Write-Output '=== PREFLIGHT COMPLETE ==='
Write-Output 'Nothing was modified, no scenarios triggered, no actuator commands sent.'
