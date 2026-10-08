# Codex and Claude Code implementation plan

Status: proposed engineering plan, 8 October 2026. Baseline: `7e27545`.

Build a Responses API path that lets the team's coding clients read files,
edit code, run tests, continue conversations, and resume work through Cloakspan.
Preserve privacy inspection before provider egress and make restoration safe
for executable tool arguments. Support is earned by complete client workflows,
including failure cases, rather than by a successful text request.

This is a separate compatibility milestone. The current
[roadmap](../ROADMAP.md) defers streaming, tools, and Anthropic compatibility;
this plan does not add them to the v0.1 release or claim they already work.

## 1. Fix the deployment scope first

The team's stated target is Codex and Claude Code through the Responses API.
Implement Responses first and verify the exact Claude Code connection before
adding another protocol. Native Claude Code gateway traffic uses Anthropic
Messages. If the team already uses a Messages-to-Responses bridge, test that
bridge as part of the supported deployment. Otherwise a native Messages adapter
is required for Claude Code support; a Responses endpoint alone cannot provide it.

Record the client versions, operating systems, model versions, authentication
method, endpoint settings, and any bridge version in a compatibility matrix.
Start with gateway credentials and configured upstream API credentials. Treat
subscription/OAuth forwarding as a separate authentication contract.

The initial transport is HTTP with server-sent events (SSE) and replayed history.
WebSockets and provider-stored continuation are later capabilities unless the
captured client behavior makes them necessary. Do not advertise a client mode
that cannot operate with the selected transport.

When a bridge is present, prefer a local deployment:

```text
Codex -------------------------------> Cloakspan Responses -> Responses provider
Claude Code -> local protocol bridge -> Cloakspan Responses -> Responses provider
```

The bridge receives original content and belongs inside the trusted boundary.
Its upstream calls must all pass through Cloakspan, with prompt logging disabled.
If Claude Code requires its native route, add:

```text
Claude Code -> Cloakspan Messages -> Anthropic provider
```

Both adapters use the same inspection, policy, token, and restoration services.
Protocol translation is not evidence that tools, reasoning, or caching survive;
prove those behaviors with the actual clients.

## 2. Establish the supported contract with synthetic recordings

Create a disposable repository and a local recording/mock provider. Use synthetic
personal values, synthetic credentials that policy should block, and ordinary
source code. Never record real repository contents or credentials as fixtures.

Capture startup, developer/system instructions, text input, file reads, search,
edits, patches, shell commands, parallel tool calls, follow-ups, cancellation,
retry, resume, context compaction, and subagent requests. Include a session long
enough to trigger automatic compaction, not only a manually constructed request.

For every observed field, header, item, and event, document its parser, content
classification, inspection behavior, reconstruction rule, and failure response.
Include model discovery and token-count requests where the clients use them.
Record requests that bypass the configured inference endpoint.

Deliver synthetic fixtures and a versioned support matrix before broadening
validation. Unsupported content must get an actionable error; accepting an
unknown field and forwarding it unchanged is not a compatibility strategy.

## 3. Introduce protocol adapters without weakening validation

Add a dedicated Responses request model and provider adapter. Implement
`POST /v1/responses`; cover compaction traffic such as
`POST /v1/responses/compact` if used by the pinned client. Keep the existing
Chat Completions contract independent during rollout.

Represent inspected content as typed locations in the original protocol, such
as a message text block, tool description, JSON argument value, or tool result.
Each location carries its original offsets and transformation result. Rebuild
the outbound payload from validated fields rather than copying the incoming
dictionary or flattening structured items into chat messages.

| Content | Required treatment |
|---|---|
| Instructions and message text, including developer messages | Inspect every supported text block and preserve roles and ordering. |
| Tool definitions and structured schemas | Inspect descriptions, examples, defaults, keys, enum strings, and other content-bearing fields. Preserve schema meaning; block sensitive structural values that cannot be safely transformed. |
| Function/custom tool input and results | Decode the supported format, inspect content, retain call/result associations, and reconstruct it without silent coercion. |
| File contents, diffs, terminal output and replayed history | Inspect before every provider request; previous inspection alone does not authorize new egress. |
| Model names, tool names, IDs, routing fields and headers | Validate against their actual structural contracts. Treat arbitrary strings as potential content; inspect, constrain, locally map, or reject them. |
| Metadata and cache controls | Support explicit fields with documented semantics. Do not forward arbitrary metadata or silently remove requested behavior. |
| Images, uploaded file references and unsupported blocks | Reject until there is a dedicated inspection path. Never let a remote reference bypass content inspection. |
| Signed or encrypted reasoning and compaction items | Handle only through the reviewed continuation design in section 6. No generic opaque pass-through. |

Reject duplicate JSON keys, invalid encodings, ambiguous shapes, excessive
nesting, and oversized item collections. Bound total body bytes and inspected
content before expensive work. Run the whole request through policy before the
first upstream byte is sent.

For native Claude Code, implement a separate Messages model, content-block
visitor, provider adapter, and event encoder. Support the tested version/beta
headers and cache behavior through an explicit capability contract. Token
counting, when implemented, must receive the transformed request too.

## 4. Make restoration into tools a separate security boundary

Current restoration only writes into prose. Extending it into executable
arguments changes that boundary and needs a documented design and tests.
Token provenance proves where a value came from; it does not authorize every
use of that value.

Create a registry of supported tools and formats. Each entry specifies argument
locations that may be restored, eligible value types, destination restrictions,
schema/grammar validation, and behavior on an unresolved token. Never change
tool names, call IDs, JSON keys, or protocol control fields by restoration.

| Tool surface | Implementation rule |
|---|---|
| Local file paths | Restore only in registered path fields. Enforce the configured workspace/path policy and preserve the client's sandbox checks. Account for symlinks at execution time; the gateway alone cannot enforce filesystem access. |
| File contents and edit arguments | Restore approved values, serialize JSON correctly, and verify that only the intended spans changed. Test exact edit matching and private values in source strings and comments. |
| Free-form patches | Parse the actual patch format. Restore permitted paths/content and revalidate hunk structure; reject malformed or ambiguous patches. |
| Shell commands | Never use unrestricted string replacement. Support a defined parser-backed subset, restore only eligible literal arguments, quote for the actual shell, and verify that restoration adds no operators or executable syntax. Reject unsupported forms containing placeholders. |
| Network destinations and externally transmitted payloads | Do not restore sensitive values under the local-file rules. Require a separate destination-aware policy; default to refusing sensitive restoration in these sinks. |

For example, restoring a scoped private directory in a local read can be
permitted. The same token placed inside a command that uploads that directory
must not acquire permission merely because the token is valid.

For executable content, unknown, forged, expired, cross-session, or truncated
placeholders fail the tool call. Do not return executable arguments with a
half-restored value. Handle both the current placeholder grammar and malformed
lookalikes that the client might otherwise execute literally.

Validate the full set of tool calls in a response before releasing that response's
executable calls. The client remains responsible for approvals, sandboxing, and
execution. Cloakspan must not auto-approve tools or claim to prevent all network
exfiltration from a shell or MCP server. Tests must prove that restored values
cannot escape the permitted tool sinks through a different argument or tool.

The normal read, edit, patch, and test commands observed in section 2 are release
requirements. A mode that routinely blocks those operations is an experimental
subset, not usable coding-agent support.

## 5. Stream with a protocol state machine

Parse upstream SSE incrementally with UTF-8 decoding, event-size limits, valid
state transitions, item identity checks, and terminal-event validation. Validate
response shapes too: the current permissive response handling is insufficient
once provider output can become executable client actions.

For text, hold only the bounded suffix that could be an incomplete surrogate,
and release completed safe text promptly. Derive the buffer bound from the
supported token grammar. Never release half of a token and try to correct it in
a later event. Preserve the existing refusal behavior for non-executable prose.

Assemble tool arguments until complete, restore and validate them under section
4, then emit valid client events. Withhold executable calls until the upstream
response has successfully completed and the response's tool batch has passed
validation. Stream independent text and permitted heartbeats while calls wait.
Test any necessary event re-encoding against the client; do not reorder events
blindly or expose argument fragments before validation.

Transform deltas and final snapshots consistently. Preserve call IDs, content
indexes, usage, failure signals, and the appropriate terminal events. Do not
report a completion if restoration failed or the upstream stream ended early.

This provides incremental surrogate restoration, not arbitrary full-output DLP.
Policies needing complete-output semantic analysis require their own buffering
and latency contract; do not claim that bounded token buffering implements them.

On disconnect, cancel provider work and release resources. Apply concurrency,
idle, total-duration, item, and restored-output limits. Retry only defined safe
pre-delivery failures using the same transformed request. After any downstream
output, propagate failure instead of restarting generation and risking duplicate
tool execution. Account for client retries separately.

## 6. Preserve history and define opaque continuation explicitly

### Ordinary history replay

Keep chat storage in the client. Replayed original/restored messages pass through
inspection again and mint the same placeholders with stable keys and scope.
Create a fresh request provenance set every time. Never persist that set or make
all vault entries in a conversation eligible for restoration.

Bind conversation scope to the authenticated tenant and principal plus a validated
client session identity. Enforce session ownership; a guessed session header is
not authorization. Do not use a changing request ID, prompt text, or a cache key
as conversation identity. Define fork/subagent scope and context transfer, and
test that parallel requests do not share restoration authorization.

Full restored-history replay can recreate mappings after a restart when stable
keys and scope remain available. It does not inherently require a transcript
database or a durable vault. Test that behavior instead of imposing unnecessary
storage. Missing history or keys must produce an explicit restoration failure.

### Reasoning, compaction and stored continuation

Signed and encrypted items cannot safely be edited. A record showing that the
provider emitted an opaque item proves its origin, not inspection of its contents.
Likewise, an old valid token does not satisfy current-request provenance.

First determine whether the pinned clients can complete long sessions with
inspectable replay/compaction under a supported configuration. If opaque replay
is required, write a separate continuation ADR addressing SI-01, SI-02 and SI-03
before enabling it. Specify the exact invariant change; do not redefine origin
verification as content inspection.

The proposed opaque-state design must at least bind an origin receipt to tenant,
principal, session, upstream provider/model, policy/key version, and the exact
opaque bytes and originating sanitized exchange. Reject foreign, altered, expired,
or incompatible-policy state. Track only the minimum token dependencies and
prevent clients from turning a response ID into access to unrelated history.
Any new restoration authorization must be explicitly bounded and tested against
cross-request replay; a vault-wide or session-wide allowlist is unacceptable.

If durable receipts or mappings are needed, add an encrypted single-node backend
with TTL, deletion, key rotation, restart, and cancellation semantics. Do not store
raw transcripts by default. `store: true`, `previous_response_id`, response
retrieval, and WebSockets stay disabled until their state and retention contracts
are implemented. A private/local route must not reuse opaque external-provider
state or fall back externally when local continuation fails.

The repository requires a written, dated decision with a named owner for invariant
waivers. This plan is not that waiver. Record the security decision in the ADR and
update the invariant tests before enabling any changed behavior. If a required
client feature cannot meet the reviewed contract, do not label that client version
supported. Long-session compaction and resume are release gates, not optional
cleanup after the initial demo.

## 7. Keep the deployment useful and measurable

Use stable placeholders and preserve native caching controls, content ordering,
and supported model metadata. Do not shorten authentication tags to save tokens.
Caching must never skip inspection or make a previous request's provenance reusable.

Pass through upstream usage and cache usage without counting locally restored
text as provider-generated tokens. Benchmark direct versus gateway requests using
the same synthetic tasks. Report input/output token changes, cache hits, inspection
time, time to first text, tool-release delay, total task time, memory, and failure
rate. Set numerical latency/capacity budgets on the reference deployment before
the pilot; report measurements by detector profile and prompt size. Do not promise
token savings simply because conversations or mappings are saved.

Ship a doctor/preflight check and configuration examples for the exact Codex,
Claude Code/bridge, and desktop setups. Verify endpoint, authentication, selected
model capabilities, session scope, a streaming response, and a harmless complete
tool round trip. Keep upstream credentials at the gateway; authenticate users
with separately revocable gateway credentials.

Return protocol-compatible errors with a safe code, request ID, and practical
next step. Do not echo raw prompts, private paths, argument values, or unknown
user-chosen field names into shared diagnostics. Audit every outcome, including
policy blocks, inspection failure, stream failure, cancellation, and restoration
refusal. Keep prompts and token mappings out of logs and metrics labels.

Retain provider egress checks and local-routing enforcement across both adapters.
A local destination must actually implement the chosen protocol/tools. Never
silently select an external provider to make an unsupported local request work.
Complete the detector timeout and resource-limit work needed for long agent inputs;
an async timeout around a thread does not stop a stuck detector.

Document coverage: this protects the configured model request path. Client
telemetry, direct web requests, MCP calls, downloads, and executed commands may
use other paths. Test them and configure egress separately where the deployment
requires broader control. Detector misses remain a documented limitation.

## 8. Deliver in reviewable changes

Paths below are proposed additions; shared files already exist.

| Change | Main work | Completion gate |
|---|---|---|
| 1. Client contract and security decisions | Synthetic recordings, support matrix, tool/stream/state ADRs; `tests/fixtures/agent_protocols/` | Actual team client/bridge topology is reproduced; every observed field has a disposition. |
| 2. Typed inspection foundation | `gateway/protocols/`, `gateway/inspection/preparation.py`, `gateway/domain.py` | Existing Chat Completions tests pass; no accepted content field lacks inspection/classification. |
| 3. Responses request and provider path | `gateway/api/responses.py`, `gateway/routing/responses.py`, auth/config integration | Text and replay fixtures pass; malformed/unsupported input causes zero provider calls. |
| 4. Tool inspection and restoration | `gateway/tools/`, `gateway/restoration/`, response validation | Read/edit/patch/shell fixtures work; sink and syntax attacks fail before executable output is released. |
| 5. Incremental SSE | `gateway/streaming/`, provider lifecycle and retry changes | Client event fixtures, all token split points, interruption, backpressure, and cancellation tests pass. |
| 6. Session and compaction lifecycle | `gateway/sessions/`, reviewed opaque-state contract and optional vault backend | Follow-up, compaction, concurrent agents, expiry, restart and resume pass; replay isolation holds. |
| 7. Claude Code connection | Existing bridge qualification, or `gateway/api/messages.py` plus native adapter | Actual Claude Code completes the same coding tasks; translation preserves the required behavior. |
| 8. Operator and release integration | Doctor, client configs, audit, resource controls, docs and benchmarks | CLI and desktop qualification, deployment tests and rollout gates pass. |

Keep the new endpoints behind explicit capability flags while incomplete. Avoid
an unrestricted proxy fallback. Activate each client profile only when all its
required capabilities have passed, including any approved invariant changes.

## 9. Acceptance tests and release gates

| Area | Required evidence |
|---|---|
| Coding usability | Each supported client reads the synthetic repository, edits code, runs its tests, explains the result, and handles a follow-up without bypassing Cloakspan. Assert resulting file contents and tool execution, not only the final prose. |
| Data coverage | Known-detectable synthetic canaries in every accepted content location are transformed or blocked. Inspect captured upstream bodies and headers; verify no canaries appear in logs, errors, metrics, or bridge diagnostics. This is a regression guarantee for the test corpus, not proof of perfect detection. |
| Tool authorization | Valid tokens in unauthorized sinks, forged tokens, cross-session tokens, shell metacharacters, Unicode paths, malformed patches, and unresolved placeholders cannot create executable calls. |
| Streaming | Test every surrogate split position, split UTF-8 characters, interleaved items, malformed/duplicate events, mismatched final snapshots, truncated streams, oversized events and missing terminal events. No executable partial output is released. |
| State | Parallel requests, forks, subagents, guessed session IDs, restarts, TTL expiry, policy/key changes, compaction and resume preserve the chosen isolation contract. |
| Failure behavior | Auth errors, rate limits, provider failure, detector timeout, local-provider failure, cancellation and retry remain bounded, auditable, and do not trigger external fallback or duplicate tool execution. |
| Cost and latency | Publish the direct/gateway benchmark and cache behavior against the declared deployment budgets. Verify that long thinking periods do not cause artificial client idle timeouts. |
| Client coverage | Test the actual pinned CLI versions and the desktop configurations the team uses. Mark untested combinations unsupported rather than inferring support from a shared protocol. |

Run existing `make test`, `make lint`, `make demo`, and leakage checks alongside
the new deterministic tests. Run live model qualification with synthetic data,
explicit test credentials, and a bounded budget. Complete the repository's
container, security, packaging, and required CI release checks for the final image.

Release sequence: local synthetic qualification, a small team pilot, then wider
opt-in rollout. Pin the tested client/bridge versions for the pilot. Trigger
rollback on a canary leak, unsafe restoration, duplicate tool execution, broken
compaction/resume, or breached resource budgets. Rollback disables affected
capabilities or restores the previous tested gateway; it never redirects clients
around the gateway. Preserve compatible keys/state and document interrupted-session
recovery rather than silently changing state semantics.

Update the compatibility contract, limitations, operations guide, threat model,
and invariant evidence with the implemented behavior. The milestone is complete
only when both required clients finish the full read, edit, test, follow-up,
compact, and resume workflow safely in the team's actual deployment.

## References

- [Current compatibility contract](openai-compatibility.md)
- [Security invariants and required decision records](security-invariants.md)
- [Current limitations](limitations.md)
- [Retry and request provenance design](adr/0014-retry-cancellation-and-provenance.md)
- [Codex gateway compatibility requirements](https://learn.chatgpt.com/docs/enterprise/gateway-compatibility)
- [Codex gateway configuration](https://learn.chatgpt.com/docs/enterprise/connect-to-a-gateway)
- [Claude Code gateway protocol](https://code.claude.com/docs/en/llm-gateway-protocol)
- [Claude Code CLI and desktop gateway configuration](https://code.claude.com/docs/en/llm-gateway-connect)
