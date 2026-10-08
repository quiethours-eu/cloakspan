# Roadmap

This is the public view. Detailed delivery planning and commercial material are
maintained separately from the public repository.

## Now: `v0.1.0-alpha.1`

Ship an honest, self-hosted, single-node Community Edition release:

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

The alpha remains explicitly not production-ready while independent security
review is outstanding.

## Next: public beta

Expand country and language coverage through community recognizers backed by
published format specifications and synthetic evaluation cases. Prioritise
formats requested by pilot users worldwide and report coverage per entity and
language before advertising support.

Public beta requires a focused independent review with no critical/high finding
open, two documentation-only installation tests by people outside development,
two controlled pilots, and at least seven days of stable Hetzner staging.

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
