SHELL := /bin/bash
PY ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

.PHONY: setup test demo serve check
setup:
	$(PY) -m pip install -r requirements.txt

test:
	PRSEC_LOAD_DOTENV=0 PYTHONDONTWRITEBYTECODE=1 $(PY) -m pytest -q

demo:
	PRSEC_LOAD_DOTENV=0 PYTHONDONTWRITEBYTECODE=1 $(PY) demo.py

serve:
	PRSEC_LOAD_DOTENV=1 $(PY) -m uvicorn app:app --host 127.0.0.1 --port 8000

check: test demo
