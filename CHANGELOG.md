# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases use semantic versioning with prerelease identifiers while the
project remains alpha.

## [Unreleased]

### Added

- Complete macOS/Linux and Windows playground quickstarts using only runtime
  dependencies, with a synthetic example and the expected result.
- Installable alpha wheel and source archive, isolated package smoke checks,
  and draft release preparation after successful CI.
- A hash-verified runtime dependency lock and a registry-resolved container
  base image digest for release preparation.

- `SAG_LOCAL_ROUTING` (GDPR mode) with the values `off` (default), `detected`,
  and `all`. `detected` sends every request in which any detector found
  anything to the `local` destination, pseudonymised, and requires an NER
  model. `all` sends every request that is not blocked to `local` and does not
  build the external client. The mode is applied after the policy and
  `SAG_FILTERS_PATH` rules, never lifts a block, and marks its decisions with
  the rule name `local-routing:<mode>` and a `+local-routing:<mode>` policy
  version suffix. See ADR-0017.
- Versioned YAML custom filters via `SAG_FILTERS_PATH`, combining regex or
  dictionary matching with transformation, blocking, or local routing in one
  definition. Includes startup validation, audit fingerprints, and examples.
- Cloakspan logo, app icon, social preview, and brand usage guide.
- `cloakspan` CLI alias alongside the existing `secure-ai-gateway` command.

- First-public-release implementation plan and concise roadmap.
- Contribution, conduct, support, issue, and pull-request guidance.
- Safe example environment and Docker build-context exclusions.
- Production startup validation for policy destinations and API keys.

### Changed

- CI uses the current major versions of its GitHub actions. The release job
  also requests `artifact-metadata: write`, which build-provenance attestation
  now needs to record where the pushed image is stored.

- README leads with the benefit, demo, and local playground; setup diagnostics
  follow the getting-started path.
- Removed pasted terminal output from the Apache-2.0 licence file.

- The unreleased `deployment/policies/auto-local.yaml` policy is removed in
  favour of `SAG_LOCAL_ROUTING=detected`. Pointing `SAG_POLICY_PATH` at it now
  fails at startup.
- Public name changed to Cloakspan with worldwide positioning and explicit
  country/language coverage boundaries. Existing deployment identifiers remain
  compatible.
- Offline demo uses neutral examples and includes payment-card tokenization.

- Compose now uses production mode and requires operator-provided secrets and
  provider endpoints instead of a known API key and mock fallbacks.

### Fixed

- The Windows package check stops the playground's whole process tree and
  retries removing its work directory while Windows releases the files, so an
  extension module that is still mapped no longer fails a correct package.

### Security

- Production refuses to start when a policy can select an unconfigured provider
  that would otherwise resolve to the mock adapter.
- With `SAG_LOCAL_ROUTING` on, `SAG_LOCAL_BASE_URL` is required in every
  environment and must resolve only to loopback or private-network addresses,
  checked at startup and on every request. The local provider then ignores
  ambient proxy settings.
- The inspection pipeline refuses a message whose role it does not inspect, a
  message field other than `role` and `content`, and a top-level field or value
  the request schema does not accept, instead of forwarding them uninspected.
  The HTTP API already returned 422 for all of these; direct callers of
  `SecurityPipeline.process` now get `DetectionError`.

## [0.1.0-alpha.1] - In preparation

First public evaluation release. A tagged release remains blocked until the
documented security and operational evidence is complete. See the
[draft release notes](docs/releases/v0.1.0-alpha.1.md) and
[release procedure](docs/releases/README.md).
