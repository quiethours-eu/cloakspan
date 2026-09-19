# Contributing

Cloakspan is an alpha security project for teams worldwide. Small, reviewable changes with
explicit failure behavior are preferred over broad feature additions.

## Before opening a pull request

- Use an issue for behavior changes or new features.
- Do not include customer prompts, API keys, private model URLs, or other real
  sensitive data in issues, tests, logs, or screenshots.
- Report vulnerabilities through GitHub's private vulnerability-reporting
  flow, not a public issue. See [SECURITY.md](SECURITY.md).
- Keep hosted/multitenant work, streaming, tools, structured output, and
  multimodal support outside the v0.1 milestone unless the roadmap changes.

## Development setup

Python 3.12 is the supported development version.

On Linux, macOS, WSL, or Git Bash:

```bash
make setup
make test
make lint
make demo
```

On PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest tests evals -q
.\.venv\Scripts\python.exe -m ruff check gateway recognizers tests evals scripts
.\.venv\Scripts\python.exe -m ruff format --check gateway recognizers tests evals scripts
```

Container tests require Docker and are a release gate:

```bash
make test-container
```

## Pull-request expectations

A pull request should:

1. explain the behavior and failure behavior;
2. include positive, negative, boundary, and leakage tests where relevant;
3. update the compatibility matrix, operations guide, or risk register when
   behavior or residual risk changes;
4. keep logs, audit events, metrics, and errors free of prompt content; and
5. pass every required CI job without `continue-on-error`.

Changes to authentication, policy, detection, transformation, restoration,
vault, provider egress, audit, or release workflows are security-sensitive.
Call that out explicitly in the pull request.

## Countries and languages

Recognizer contributions from any country are welcome. Cite an authoritative
format specification, validate checksums where available, and include synthetic
positive, negative, and boundary examples. Document supported formats and known
ambiguities. Add evaluation cases before advertising support for a new entity
or language; do not use real personal data in fixtures.

## Style

- Python is formatted and linted with Ruff.
- Prefer plain, typed code and explicit validation at trust boundaries.
- Unknown or uninspectable fields fail closed; do not add opaque pass-through.
- Add dependencies only when their licence and security boundary are understood.

By contributing, you agree that your contribution is licensed under the
project's Apache-2.0 licence.
