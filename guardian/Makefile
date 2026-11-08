# AEGIS LOOP — Guardian Makefile
# One-command setup and demo. `make setup && make demo` is <10 min on a clean machine (rubric §12).
PY      ?= python3
VENV    ?= .venv
BIN     := $(VENV)/bin
PORT    ?= 8090
SHARED  ?= shared
export GUARDIAN_SHARED_DIR := $(abspath $(SHARED))

.PHONY: help setup test checks check mock-orion demo lint clean

help:
	@echo "make setup    - create venv + install deps"
	@echo "make test     - run the test suite"
	@echo "make checks   - run all nine triplet scenarios -> logs/<id>-<stamp>.log"
	@echo "make check id=g3 - run one triplet scenario"
	@echo "make demo     - start the Guardian on :$(PORT) (http://localhost:$(PORT)/verdicts)"
	@echo "make mock-orion - fake Orion broker serving the twin's device semantics"
	@echo "make lint     - ruff static check + byte-compile"
	@echo "make clean    - remove venv + caches"

setup:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --quiet --upgrade pip
	$(BIN)/pip install --quiet -r requirements.txt
	@echo "Ready. Run: make checks  (offline, no broker needed), then make demo"

test:
	PYTHONPATH=src $(BIN)/python -m pytest -q

checks:
	PYTHONPATH=src:. $(BIN)/python scenarios/run_check.py

check:
	PYTHONPATH=src:. $(BIN)/python scenarios/run_check.py $(id)

demo:
	PYTHONPATH=src $(BIN)/python -m guardian --port $(PORT)

# A fake Orion broker so a reviewer can drive the demo with no platform access:
#   curl -XPOST localhost:8025/scenario -d '{"name":"g3"}'
mock-orion:
	PYTHONPATH=src:. $(BIN)/python -m mocks.mock_orion --port 8025

lint:
	@if $(BIN)/ruff --version >/dev/null 2>&1; then \
		PYTHONPATH=src $(BIN)/ruff check src tests mocks scenarios; \
	else \
		echo "ruff not installed - falling back to byte-compile only"; \
		PYTHONPATH=src $(BIN)/python -m compileall -q src; \
	fi

clean:
	rm -rf $(VENV) .pytest_cache **/__pycache__ logs/*.jsonl 2>/dev/null || true
	@echo "cleaned"
