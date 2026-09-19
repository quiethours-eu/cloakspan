SHELL := /bin/bash
VENV   := .venv
ifeq ($(OS),Windows_NT)
PY := $(VENV)/Scripts/python.exe
else
PY := $(VENV)/bin/python
endif

.DEFAULT_GOAL := help
.PHONY: help setup test test-container lint security demo up down clean fmt \
        evals evals-aliased evals-holdout evals-json corpus leakage \
        sbom licences lock pin-base-image image release-image benchmark \
        benchmark-concurrency release-artifacts

help:
	@echo "setup          Create the virtualenv and install dev dependencies"
	@echo "demo           Run the offline demo (no credentials required)"
	@echo "test           Run the full test suite (excludes container tests)"
	@echo "test-container Build the image and assert the hardening claims against it"
	@echo "evals          Detection precision/recall per entity and language (dev split)"
	@echo "evals-aliased  As above, merging LT/EE personal codes into one class"
	@echo "evals-holdout  The LOCKED holdout split. Read once, after freezing thresholds"
	@echo "evals-json     Write the machine-readable report to evals-report.json"
	@echo "corpus         Regenerate the evaluation corpus"
	@echo "leakage        Run the leakage regression suite only"
	@echo "lint           Run ruff"
	@echo "fmt            Auto-fix lint issues"
	@echo "security       Run available security scanners"
	@echo "up/down        Start/stop the Docker Compose stack"
	@echo ""
	@echo "Release engineering:"
	@echo "sbom           Write a CycloneDX SBOM for the source tree"
	@echo "licences       Write the licence inventory, and fail on policy breach"
	@echo "lock           Regenerate the dependency lock from this environment"
	@echo "pin-base-image Resolve the container base image to an immutable digest"
	@echo "image          Build the dev image (base image by tag)"
	@echo "release-image  Build the release image (refuses without a pinned digest)"
	@echo "benchmark      Measure the detection path on this machine"
	@echo "benchmark-concurrency  Throughput and event-loop responsiveness under load"
	@echo "release-artifacts  Source SBOM + licences + benchmarks, into dist/"

setup:
	python -m venv $(VENV)
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"
	@echo "Setup complete. Run 'make demo'."

demo:
	$(PY) scripts/demo.py

test:
	$(PY) -m pytest tests evals -q

# Builds the image and asserts the hardening claims against the running
# container: non-root uid, read-only root filesystem, dropped capabilities,
# bounded memory, and zero canary occurrences in the full log stream.
test-container:
	$(PY) -m pytest tests/test_container_hardening.py -m container -q

# Exits non-zero while any entity/language pair is below its published
# threshold. That is the release gate doing its job, not a broken target.
#
# As of corpus v2.0.0 every pair passes, on dev and on the holdout. Read
# docs/evaluation-report.md "What these numbers are not" before quoting any of
# them: the corpus is synthetic, the supports are small, and the identifiers are
# computed from the same published algorithms the detectors validate against.
evals:
	$(PY) -m evals.run_evals --split dev

evals-aliased:
	$(PY) -m evals.run_evals --split dev --alias-baltic-codes

evals-holdout:
	$(PY) -m evals.run_evals --split holdout

evals-json:
	$(PY) -m evals.run_evals --split dev --json evals-report.json --no-gate

corpus:
	$(PY) -m evals.datasets.generate

leakage:
	$(PY) -m pytest evals/leakage -q

lint:
	$(PY) -m ruff check gateway recognizers tests evals scripts
	$(PY) -m ruff format --check gateway recognizers tests evals scripts

fmt:
	$(PY) -m ruff check --fix gateway recognizers tests evals scripts
	$(PY) -m ruff format gateway recognizers tests evals scripts

# Findings and scanner errors fail this target. pip-audit comes with the dev
# dependencies; Gitleaks and Trivy are optional external tools and are reported
# when absent.
security:
	@echo "== ruff (security rules: S/ASYNC) =="
	@$(PY) -m ruff check --select S,ASYNC gateway recognizers
	@echo "== pip-audit (dependency CVEs) =="
	@if $(PY) -c "import importlib.util, sys; sys.exit(importlib.util.find_spec('pip_audit') is None)"; then \
		$(PY) -m pip_audit --requirement deployment/requirements.lock; \
	else \
		echo "  pip-audit not installed in $(VENV): $(PY) -m pip install pip-audit"; \
	fi
	@echo "== gitleaks (committed secrets) =="
	@if command -v gitleaks >/dev/null 2>&1; then \
		gitleaks detect --no-banner; \
	else \
		echo "  gitleaks not installed"; \
	fi
	@echo "== trivy (container image) =="
	@if command -v trivy >/dev/null 2>&1; then \
		trivy image secure-ai-gateway:dev; \
	else \
		echo "  trivy not installed"; \
	fi
	@echo "== licence boundary (proprietary deps) =="
	@$(PY) -m pytest tests/test_licence_boundary.py -q

# ---------------------------------------------------------------------------
# Release engineering
# ---------------------------------------------------------------------------

DIST := dist
BASE_IMAGE := $(shell grep '^BASE_IMAGE=' deployment/docker/base-image.env | cut -d= -f2)
BASE_DIGEST := $(shell grep '^BASE_DIGEST=' deployment/docker/base-image.env | cut -d= -f2)

$(DIST):
	@mkdir -p $(DIST)

sbom: $(DIST)
	$(PY) scripts/supply_chain.py sbom --output $(DIST)/sbom.cdx.json

licences: $(DIST)
	$(PY) scripts/supply_chain.py licences --output $(DIST)/licence-report.json
	$(PY) scripts/supply_chain.py check

lock:
	$(PY) -m pip freeze --exclude-editable > $(DIST)/requirements.raw
	@echo "Review $(DIST)/requirements.raw, then update deployment/requirements.lock"
	@echo "Hashes need a package index; see the header of that file."

pin-base-image:
	$(PY) scripts/pin_base_image.py --by "$(USER)"

image:
	docker build -f deployment/docker/Dockerfile \
	  --build-arg BASE_REF=$(BASE_IMAGE) -t secure-ai-gateway:dev .

# The release gate. Refuses to build against a mutable tag, because a tag names
# different bytes over time and an SBOM taken from one describes an artefact
# that no longer exists.
release-image:
	$(PY) scripts/pin_base_image.py --check
	docker build -f deployment/docker/Dockerfile \
	  --build-arg BASE_REF=$(BASE_IMAGE)@$(BASE_DIGEST) \
	  -t secure-ai-gateway:$(shell $(PY) -c "import re,pathlib;print(re.search(r'version = \"([^\"]+)\"', pathlib.Path('pyproject.toml').read_text()).group(1))") .

benchmark: $(DIST)
	$(PY) scripts/benchmark.py --output $(DIST)/benchmark.json

# Exits non-zero if the health check is starved while a request is inspected --
# which is what happens when the CPU work moves back onto the event loop. That
# is an availability property, so it gets a gate rather than a table entry.
benchmark-concurrency: $(DIST)
	$(PY) scripts/benchmark_concurrency.py --output $(DIST)/benchmark-concurrency.json

# Produce the source-side artefacts that can be regenerated locally. CI adds the
# container evidence, vulnerability reports, signing, and provenance.
release-artifacts: sbom licences benchmark benchmark-concurrency
	@echo ""
	@echo "Artefacts in $(DIST)/:"
	@ls -1 $(DIST)
	@echo ""
	@echo "Still required before the release gate passes:"
	@echo "  - container SBOM      (syft, in CI)"
	@echo "  - image signature     (cosign, in CI)"
	@echo "  - build provenance    (SLSA attestation, in CI)"
	@echo "  - vulnerability reports (pip-audit + trivy, in CI)"
	@echo "  - container tests actually executed (make test-container)"

up:
	docker compose up --build -d
	@echo "Gateway on http://127.0.0.1:8080  (health: /healthz)"

down:
	docker compose down

clean:
	rm -rf $(VENV) .pytest_cache .ruff_cache **/__pycache__
