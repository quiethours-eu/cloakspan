# Test audit — 2026-09-29

## Scope

Audited the test surface of Cloakspan at `bf95f97291b62ee212c84b7bb597edc6c4d891b9` (upstream `main`): all 22 `test_*.py` modules under `tests/` and `evals/`, their fixtures and datasets, the test and evaluation entry points in `Makefile` and `.github/workflows/ci.yml`, and the production owners of the findings below. This was a repository-wide **test audit**, not a line-by-line review of every production module or a security penetration test.

Discovery included an AST and text sweep for assertion-free tests, self-comparisons, exact source assertions, duplicated test bodies and fixtures, test-only production seams, and unexercised negative controls. Candidate tests were checked against their production owners and CI paths before changes. No `AGENTS.md` instructions were present in this checkout.

## Changes made

| Area | Evidence and disposition |
| --- | --- |
| Shared fixtures | `tests/conftest.py` and `evals/conftest.py` were byte-for-byte duplicates. One root `conftest.py` now serves both suites; importable constants and checksum helpers live in `tests/fixtures.py`. Test imports and lint paths were updated. |
| Offline demo | `tests/test_pilot_readiness.py` asserted that `scripts/demo.py` contained `MockProvider` and omitted `OpenAICompatibleProvider`. That could pass even if the demo used the network. The existing executable demo test now runs without configured credentials, fails on a Python socket attempt, and checks what the provider actually saw. The stale `alice@acme.lv` assertion was replaced with the demo's current examples. |
| Repeated assertion | The identical environment-variable regex ran twice in `test_every_setting_the_code_reads_is_documented`. It now runs once and includes digits in names. |
| Eval controls | `test_boundary_examples_have_no_gold_spans` could pass with no boundary or negative examples. It now requires both kinds in each split before checking their labels. |
| Compose contract | A raw YAML string search could be satisfied by a comment or unrelated text. The test now parses `compose.yaml` and checks the gateway's environment mapping. |
| Readiness | Two `/readyz` tests asserted the same response. One was removed; the retained test also makes the mock provider fail if readiness calls it. |

No production code changed. Test and fixture support changed by **+289 / −445 lines, net −156**; CI and Makefile changed by **+6 / −6 lines**. These counts include the new root fixture files and exclude this report.

## Open findings

1. **Vulnerability exception policy was not connected to its scanners (resolved 2026-09-30).** Trivy CI and `make security` now use `scripts/vulnerability_policy.py`, covered by executable CLI tests in `tests/test_vulnerability_policy.py`. Only approved, unexpired HIGH exceptions matching advisory ID, package name, Trivy package type, and installed version can pass. CRITICAL findings cannot be excepted or downgraded. Invalid or expired approvals fail even on clean reports. Python version constraints use PEP 440; OS package exceptions require an exact version including the distribution revision. The committed exception list remains empty. `pip-audit` does not provide severity evidence, so its findings remain unconditionally blocking; applying HIGH exceptions there could hide a CRITICAL vulnerability. This limitation is explicit in the policy rather than silently weakening the gate.
2. **Container log tests depend on earlier test execution.** `TestContainerLogsCarryNoContent` in `tests/test_container_hardening.py` reads log canaries sent by tests in the preceding class. A selected log test can therefore pass without sending its own canary; the full CI run uses the intended order. Make log assertions create or require their own traffic before evaluating logs. No edit was made here because the Docker daemon was unavailable locally.
3. **Stale normalization helper and diagram.** `gateway/detectors/base.py::normalize_for_detection` has no in-repository callers; the pipeline uses `build_detection_view`. `docs/data-flow.md` still names the old helper. Public import compatibility should be checked before removing it; the diagram can be corrected independently.

## Retained candidates

The egress validation tests without explicit assertions check successful return versus exception. The SBOM serial-number comparison and key-derivation comparison use independent calls to test determinism. The audit event slot check, licence import boundary check, and container hardening tests enforce architecture or release contracts. These were retained because their failure modes are distinct and credible.

## Validation and limits

- `python -m pytest tests evals -q`: **856 passed, 17 deselected**, one dependency deprecation warning.
- `python -m pytest tests/test_container_hardening.py -m container -q`: **17 skipped** because the Docker daemon was unreachable. The container assertions and image build were not verified locally.
- `python -m ruff check conftest.py gateway recognizers tests evals scripts` and `python -m ruff format --check ...`: passed.
- `python -m evals.run_evals --split dev`: passed after the eval change.
- `git diff --check`: passed.

The linked OpenClaw skill's `check-changed.mjs` and `$autoreview` steps are specific to that repository and are not available in Cloakspan. The changed files were reviewed directly and checked with Cloakspan's Python gates instead.

The changes are uncommitted in an isolated worktree. No PR was opened or merged. The original checkout was left untouched.
