Set-Location 'C:\Users\moham\OneDrive\Desktop\New folder (12)\triplet_007\brain'
Write-Output '=== TARGETED TESTS ==='
python -m pytest tests/integration/test_actions.py tests/integration/test_dashboard.py -q
Write-Output "TARGETED_EXIT=$LASTEXITCODE"
Write-Output '=== FULL SUITE ==='
python -m pytest -q
Write-Output "FULL_EXIT=$LASTEXITCODE"
Write-Output '=== RUFF ==='
python -m ruff check .
Write-Output "RUFF_EXIT=$LASTEXITCODE"
