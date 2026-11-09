SHELL := /bin/bash
PY ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

.PHONY: setup test selfcheck serve check
setup:
	$(PY) -m pip install -r requirements.txt

test:
	PRSEC_LOAD_DOTENV=0 PYTHONDONTWRITEBYTECODE=1 $(PY) -m pytest -q

# The full-repository scan must fail the gate on the fixture's planted P1 (exit status 1).
selfcheck:
	PRSEC_LOAD_DOTENV=0 PYTHONDONTWRITEBYTECODE=1 $(PY) scan_repo.py tests/fixtures/project; \
	status=$$?; [ $$status -eq 1 ] && echo "selfcheck: OK, the planted P1 failed the gate (exit 1)" \
	|| { echo "selfcheck: expected exit status 1, got $$status"; exit 1; }

serve:
	PRSEC_LOAD_DOTENV=1 $(PY) -m uvicorn app:app --host 127.0.0.1 --port 8000

check: test selfcheck
