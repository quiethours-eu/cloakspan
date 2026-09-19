# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases use semantic versioning with prerelease identifiers while the
project remains alpha.

## [Unreleased]

### Added

- First-public-release implementation plan and concise roadmap.
- Contribution, conduct, support, issue, and pull-request guidance.
- Safe example environment and Docker build-context exclusions.
- Production startup validation for policy destinations and API keys.

### Changed

- Compose now uses production mode and requires operator-provided secrets and
  provider endpoints instead of a known API key and mock fallbacks.

### Security

- Production refuses to start when a policy can select an unconfigured provider
  that would otherwise resolve to the mock adapter.

## [0.1.0-alpha.1] - Unreleased

First public evaluation release. A tagged release remains blocked until the
documented security and operational evidence is complete.
