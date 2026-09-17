# Website Monitor - developer tasks
# Author: Dr. Denys Dutykh (Khalifa University of Science and Technology, Abu Dhabi, UAE)
.DEFAULT_GOAL := help
DEV_VENV := .venv-dev
PY       := $(DEV_VENV)/bin/python

.PHONY: help install dev test cov lint fmt check status report dry clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

install:  ## Production install (runtime deps only, ~17 MB)
	./install.sh

dev: $(DEV_VENV)  ## Create the development venv (kept out of production)
$(DEV_VENV):
	python3 -m venv $(DEV_VENV)
	$(DEV_VENV)/bin/pip install -q --upgrade pip
	$(DEV_VENV)/bin/pip install -q -r requirements.txt -r requirements-dev.txt

test: dev  ## Run the test suite
	$(PY) -m pytest tests/ -q

cov: dev  ## Run tests with a coverage report
	$(PY) -m pytest tests/ --cov=monitor --cov-report=term-missing -q

lint: dev  ## Lint and type-check
	$(PY) -m pylint monitor.py --disable=R0902,R0913,R0914,R0912,R0915,C0103,W0718 || true
	$(PY) -m mypy monitor.py --ignore-missing-imports || true

fmt: dev  ## Format with black
	$(PY) -m black monitor.py tests/ --line-length 100

check: test lint  ## Everything CI runs

status:  ## Show current monitoring state
	./venv/bin/python monitor.py --status

report:  ## Print a weekly report without emailing it
	./venv/bin/python monitor.py --report weekly --dry-run

dry:  ## Run all checks without sending email
	./venv/bin/python monitor.py --dry-run --verbose

clean:  ## Remove caches and the development venv
	rm -rf $(DEV_VENV) .pytest_cache .mypy_cache __pycache__ tests/__pycache__ .coverage
