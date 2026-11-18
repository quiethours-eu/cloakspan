# Roadmap

This is the public view. Detailed delivery planning and commercial material are
maintained separately from the public repository.

## Released: `v0.1.0-alpha.1`

Published on 17 November 2026. See the
[release notes](docs/releases/v0.1.0-alpha.1.md) and the
[staging rehearsal report](docs/releases/v0.1.0-alpha.1-staging.md).

The alpha set out to ship an honest, self-hosted, single-node Community Edition
release:

1. align all public claims with implemented behavior;
2. remove unsafe production defaults and mock fallbacks;
3. bound request bytes, rate, concurrency, detector time, and provider work;
4. add complete error-path audit events and protected metrics;
5. publish separately measured deterministic and optional NER profiles;
6. document OpenAI-compatible external providers and private Ollama routing;
7. build from hash-locked dependencies and release the exact tested image
   digest with SBOM, scan, signature, and provenance; and
8. prove install, upgrade, rollback, and failure behavior on a Hetzner staging
   VM.

Two of these were only partly met and carry over to the beta:

- **Item 5.** Only the deterministic detectors are measured. The optional NER
  profile is not, because no NER model ships with the project; see the
  [evaluation report](docs/evaluation-report.md).
- **Item 8.** The rehearsal was one scripted run on a shared development VM
  with a mock provider. It did not cover a host reboot, a Docker daemon
  restart, or an upgrade that pulls the published image.

The alpha remains explicitly not production-ready while independent security
review is outstanding.

## Now: public beta

Expand country and language coverage through community recognizers backed by
published format specifications and synthetic evaluation cases. Prioritise
formats requested by pilot users worldwide and report coverage per entity and
language before advertising support.

Public beta requires a focused independent review with no critical/high finding
open, two documentation-only installation tests by people outside development,
two controlled pilots, and at least seven days of stable Hetzner staging. It
also requires the two items carried over from the alpha: a measured NER profile,
and a rehearsal on a dedicated host that includes a reboot and the published
image.

## Later: stable `v1.0.0`

Stable requires an independent penetration test and retest, thirty days of
release-candidate stability, published support/incident policies, and measured
detection and performance evidence.

## Deferred programs

- Hosted/multitenant service with PostgreSQL RLS, per-tenant KMS, HA, billing,
  and a control plane.
- Qualified Anthropic-native and coding-agent client support.
- Chat Completions streaming/tools, broader structured output and multimodal inspection.
- Persistent vaults, Kubernetes/Helm, SSO/SCIM, dashboards, and SIEM exports.

These programs do not belong to the v0.1 release milestone.

## Separate opt-in milestone: coding agents

The [Codex/Claude Code plan](docs/codex-claude-code-implementation-plan.md) has an
experimental inspectable Responses and native Messages implementation with
registered tools, SSE, scoped history replay and resource controls. Capabilities
default off. This is separate from v0.1. Both pinned restricted CLI profiles have
completed the full local synthetic workflow; live/desktop qualification remains
separate.

Implement the public profiles in the [versioned support matrix](docs/agent-compatibility.md)
for Codex CLI 0.161.0 and Claude Code CLI 2.1.293, without requiring private
configuration captures. Both pinned CLIs passed read/edit/test/follow-up,
automatic inspectable compaction and resumed work against a synthetic provider;
qualify desktop/model/OS/optional bridge separately for deployment. Both required
clients must read/edit/test,
follow up, automatically compact and resume safely in the actual deployment.
Inspectable custom-provider local summaries use ordinary requests. Opaque state,
opaque compaction endpoints, provider storage and WebSockets remain
disabled until reviewed security/retention contracts exist; no invariant is
waived. Synthetic fixtures/preflight/benchmark are implementation evidence only.
Reference latency/capacity measurements, independent review and pilot approval
remain outstanding before wider opt-in rollout.
