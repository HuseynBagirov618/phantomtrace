.PHONY: test run demo eval

PYTHON ?= python
MANIFEST ?= datasets/manifests/evaluation.json
SPLIT ?= development

test:
	PYTHONPATH=src:. $(PYTHON) -m pytest

run:
	PYTHONPATH=src:. $(PYTHON) -m uvicorn apps.api.main:app --host 127.0.0.1

demo:
	PYTHONPATH=src:. $(PYTHON) -m phantomtrace.investigation.cli demo

eval:
	PYTHONPATH=src:. $(PYTHON) -m phantomtrace.investigation.cli eval "$(MANIFEST)" --split "$(SPLIT)"
