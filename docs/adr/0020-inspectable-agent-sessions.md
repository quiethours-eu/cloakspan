# ADR-0020: Principal-scoped inspectable replay; opaque state disabled

**Status:** experimental implementation decision · 2026-10-08 ·
`REQUIRES_SECURITY_REVIEW`. **Owner:** Technical lead (implementation), Security
owner (review). No invariant waiver or production qualification is granted.

## Decision

Keep history in the client and inspect every replayed original/restored text,
tool argument and result on each request. Map a validated stable `X-Session-Id`,
`X-Conversation-Id`, public Codex `session-id`/`thread-id`, legacy `session_id` or native
Claude Code `x-claude-code-session-id` header to a SHA-256
conversation scope bound to the authenticated tenant and `ApiKey.key_id`
principal. Multiple supplied aliases must agree; duplicates/conflicts fail.
Preserve `key_id` when rotating a credential if retaining the same session scope
is intended. Changing request IDs and prompt/cache keys
are not conversation identities. A guessed session ID is not authorization.
The native Claude `x-claude-code-agent-id` is validated and partitions the scoped
session for a subagent; it grants no inherited restoration provenance. Typed
client metadata is inspected then consumed locally. A Responses cache identity
is hashed with authenticated scope, protocol/model/destination and policy before
egress, and grants neither restoration nor conversation access.

Mint stable scoped placeholders but create fresh restoration provenance for
every request. Parallel requests and forks/subagents never inherit another
request's provenance. Forked context must be sent and inspected again under the
new scoped session. The vault remains ephemeral; full inspectable replay can
recreate mappings after restart with stable scope and keys. Missing context or
unavailable keys must cause explicit restoration refusal for executable content.

`DELETE /v1/agent/sessions/{id}` validates the identity and deletes mappings only
under the authenticated tenant/principal's derived scope. It does not erase
another principal's session by guessing its raw ID. Keep this separate from the
legacy conversation deletion contract.

Concurrent requests can refresh one canonical vault token with differently
spelled originals. Restoration authenticates the scoped unexpired vault record
and checks its canonical identity, then uses the original held in the current
request's provenance. It never acquires authorization from that refresh. Agent
requests declaring tools reject ambiguous canonical variants within one request
before egress, preserving exact edit/path semantics; Chat Completions retains
its existing within-request behavior.

Disable opaque reasoning, signed/encrypted items, `/v1/responses/compact`,
`store: true`, `previous_response_id`, retrieval and WebSockets. A provider origin
receipt would not prove content inspection and would not satisfy SI-03.
Inspectable client-generated summaries may be ordinary replayed text, but no
automatic client compaction workflow is qualified by text acceptance alone.

The public Codex CLI 0.161.0 custom-provider profile selects local compaction
outside the OpenAI/Azure remote-compaction capability. It sends ordinary
inspectable model requests and replays text summaries, as shown in the pinned
[provider capabilities](https://github.com/openai/codex/blob/979011409de0a60b52f179721948e65531d26144/codex-rs/model-provider/src/provider.rs#L462)
and [compaction dispatch](https://github.com/openai/codex/blob/979011409de0a60b52f179721948e65531d26144/codex-rs/core/src/session/turn.rs#L1505).
That path follows existing inspection/current-request provenance and needs no
opaque receipts, endpoint or invariant waiver. Actual automatic local compaction
and resume tests establish client behavior separately from this design decision.

## Future decision requirements

Before enabling opaque state, write a separate dated ADR with named security
owner that states the exact changes to SI-01/SI-02/SI-03. Bind exact bytes and
origin exchange to tenant, principal, session, provider/model, policy and key
versions. Specify bounded token dependencies, TTL/deletion, key rotation,
restart/cancellation, encrypted receipts if needed, and cross-request tests.
Do not implement a session-wide restoration allowlist or durable raw transcripts.
Local routing cannot reuse external opaque state or fall back externally.

## Consequences and evidence

No transcript database or durable vault is added for inspectable replay. Tests
cover stable replay, parallel provenance, authenticated principal separation,
restart with stable keys and missing-history refusal. Long automatic compaction
and resume passed with the actual Codex CLI 0.161.0 and Claude Code CLI 2.1.293
against the local synthetic provider: real 1,000-line reads, ordinary native
summary requests, client-native compaction evidence, inspected summary replay
and a separate resumed follow-up. Codex recorded native persisted compaction;
Claude emitted compact_boundary events. The
[matrix](../agent-compatibility.md#actual-public-cli-evidence-2026-10-08)
records exact lowered test thresholds and estimated usage. This establishes the
restricted synthetic CLI profile without an invariant waiver; it does not
qualify live model capacity, desktop behavior or production deployment. Clients
requiring opaque continuation remain unqualified.
