Set-Location C:\Users\moham\OneDrive\Desktop\csbrain\brain
python -m pytest tests/integration/test_guardian_compat.py -q 2>$null
Write-Output "`n===== NGSI TWIN ====="
python -m pytest tests/integration/test_ngsi_twin.py -q 2>$null
Write-Output "`n===== FULL SUITE ====="
python -m pytest -q 2>$null
Write-Output "`n===== RUFF ====="
python -m ruff check .
