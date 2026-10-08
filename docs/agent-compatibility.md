# Coding agent compatibility

**Matrix version:** 4 · 2026-10-08. **Status:** experimental, opt-in public client
profiles. Codex CLI 0.161.0 and Claude Code CLI 2.1.293 are the pinned public
contracts; both actual CLIs pass read/edit/test/follow-up/automatic-compaction/resume
against a local synthetic provider. No live production
deployment or desktop configuration is qualified by documentation alone.

The [implementation plan](codex-claude-code-implementation-plan.md) defines a
separate compatibility milestone. Public documentation and pinned public client
source/package contracts guide implementation. Generated protocol fixtures and
actual CLI runs against a synthetic provider are distinct kinds of evidence;
neither records private repositories or requires private client configuration.
The v0.1 Chat Completions contract remains independent.

## Versioned deployment matrix

| Client | Version / OS | Transport and topology | Authentication | Qualification |
|---|---|---|---|---|
| Codex CLI | 0.161.0 / Linux x86_64 synthetic deployment | Custom provider, HTTP Responses/SSE, inspectable local summaries | Revocable gateway bearer key; upstream key stays at gateway | Full actual synthetic coding/automatic-compaction/resume workflow passed with test controls below |
| Codex desktop | Separate public desktop configuration | Custom provider routing requires surface verification | Gateway key; OAuth/subscription forwarding unsupported | Public configuration documented; desktop workflow unqualified |
| Claude Code CLI | 2.1.293 / Linux x86_64 synthetic deployment | Native Messages/SSE, restricted bare CLI profile | Gateway key via x-api-key; Anthropic key stays at gateway | Full actual synthetic coding/automatic-compaction/resume workflow passed with test controls below |
| Claude Code desktop | Separate third-party inference configuration | Native Messages routing through desktop gateway configuration | Gateway key; OAuth/subscription forwarding unsupported | Public configuration documented; desktop workflow unqualified |
| Claude Code with bridge | Client, bridge, model and OS not supplied | Local Messages-to-Responses bridge, only if explicitly selected | Bridge receives gateway key; provider key stays at gateway | Unqualified; bridge tools, caching, events and bypasses require testing |

The public profiles below are sufficient to implement and test the documented
CLI contracts; private versions, captures and configurations are not prerequisites.
Production qualification records the deployment's exact client/build, OS,
upstream/model version, gateway revision, endpoint settings, beta/version headers
and authentication. Rerun gates after upgrades. Native Messages is the selected
Claude protocol, so a bridge is not required. An optional bridge sees original
content and needs separate trusted-deployment qualification.

## Public contract sources and profiles

Codex is pinned to [release 0.161.0](https://github.com/openai/codex/releases/tag/rust-v0.161.0)
and public source commit `979011409de0a60b52f179721948e65531d26144`.
Use a custom provider named Cloakspan, gateway `env_key`, Responses HTTP/SSE,
`supports_websockets=false` and an explicit local model catalog. The catalog must
describe the selected upstream's real text/tool capabilities and omit opaque
reasoning requirements. These settings are in the
[official configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference).
The pinned [provider capability implementation](https://github.com/openai/codex/blob/979011409de0a60b52f179721948e65531d26144/codex-rs/model-provider/src/provider.rs#L462)
selects inspectable local compaction for providers outside its OpenAI/Azure
remote-compaction contract; the [local compaction path](https://github.com/openai/codex/blob/979011409de0a60b52f179721948e65531d26144/codex-rs/core/src/session/turn.rs#L1505)
uses ordinary model requests and text summaries. This requires neither the opaque
compact endpoint nor an invariant waiver.
The shipped profile selects `gpt-5.1` with effort `none`, which
[OpenAI documents as a no-reasoning mode with tool support](https://openai.com/index/gpt-5-1-for-developers/).
The original local catalog caps context at 16,384 tokens, compaction at 12,000
tokens and tool output at 10,000 bytes; these are client controls, not capacity
evidence. The gateway example allows one million inspected characters and a
4 MiB body for tools plus replay; reference performance at that size is pending.

Claude Code is pinned to
[@anthropic-ai/claude-code 2.1.293](https://www.npmjs.com/package/@anthropic-ai/claude-code/v/2.1.293),
with registry SHA-512 integrity
`PfPSvsd0zH1R1NhLKLebYdEXg/KcGCXc7LBntE186EWuZtBXa7sMnBqs0/uW/BvzkBEfHKqww/WbK/kMAk0TXg==`.
The [official gateway connection guide](https://code.claude.com/docs/en/llm-gateway-connect)
documents base URL and gateway-key authentication. Use native Messages with the
restricted bare CLI tools in the client example. Disable experimental features,
thinking request parameters, interleaved thinking, deferred MCP tool search and
nonessential traffic using the
[official environment controls](https://code.claude.com/docs/en/env-vars).
These controls do not prove a model will return no thinking; opaque output is
still refused. The [official protocol guide](https://code.claude.com/docs/en/llm-gateway-protocol)
also explains that beta-disable retains effort and some beta headers. Support
only the explicit inspected profile contract, without stripping arbitrary
requested semantics or forwarding unknown headers.

Desktop/IDE surfaces have separate configuration and qualification. In particular,
Claude Desktop uses its third-party inference configuration, so CLI shell
variables do not establish desktop routing. The public desktop documentation
guides implementation without requiring private captures; actual desktop
behavior and production deployment still need verification.
The client examples include the public Codex desktop configuration paths and
Claude's explicit third-party inference keys, with gateway-key authentication.
Gateway OIDC authentication is outside this implemented credential contract.

## Experimental inspectable subset

`SAG_ENABLE_RESPONSES` and `SAG_ENABLE_MESSAGES` default off. The experimental
adapters support validated text, explicitly modeled function tools and results,
inspected history replay, and HTTP SSE. Accepted content is visited by the typed
protocol parser and inspection preparation; unknown fields and unsupported blocks
fail before provider egress. Existing Chat Completions streaming/tools remain
refused. Enable only the protocol that the experimental deployment needs.

Tool restoration uses a registry (`read_file`, `write_file`, `edit_file`,
`apply_patch`, `shell`, explicit registered client aliases, local `Grep`/`Glob`,
typed `TodoWrite`, and polling/interrupt-only `write_stdin`). It validates the
whole executable batch before releasing any call. Workspace restrictions and a
small shell grammar intentionally limit this subset; a real coding client may
need additional reviewed formats. The client retains its approvals, sandbox,
filesystem checks and execution responsibility. See [ADR-0018](adr/0018-agent-tool-restoration.md).

Every emitted call must match a current declared name/native type and the
request's tool-choice, parallelism and batch-size controls. Executable schemas
accept a bounded assertion subset (`type`, properties/required/additionalProperties,
enum/const, simple bounds, allOf/anyOf/oneOf); references, patterns, format,
conditionals and unknown assertions fail before egress. Arguments still follow
registered typed formats and must satisfy their declared schema after restoration.
The structured-output schema contract is separate. Tool-bearing requests also
refuse ambiguous canonical variants within one request, to preserve exact edits.

The shell subset is one literal argv command using `shlex`, restricted to local
operations such as `cat`, `ls`, `wc`, `stat`, `head`, `tail`, `pwd`, `test`,
`touch`, `mkdir`, `cp`, `mv`, `printf %s`, `pytest`, `python -m pytest`,
`rg`/`grep` and restricted `find` with allowlisted flags. Search restoration
escapes token values in regex patterns; glob token values cannot add glob
operators. Expansions/operators/redirections, arbitrary Python, network programs,
search preprocessors and `find -exec`/`-delete` are refused. The patch subset is the explicit
Begin/Add/Update/Delete/Move/hunk/End-of-File grammar and cannot introduce line
breaks through restoration. These constraints require actual client testing.

Registered Codex permission hints retain client approval behavior but cannot
restore placeholders into control fields, request network access or name paths
outside the workspace. `write_stdin` allows only polling or a literal interrupt,
so it cannot introduce an interactive command. Bash's background flag is typed;
`dangerouslyDisableSandbox: true` is refused. PDF `Read.pages` and alternate
execution-environment identifiers may appear in supported declarations but are
refused in emitted calls until their inspection/workspace contracts exist.

Streams validate event identity, completion, and final snapshots. Text uses
bounded incremental surrogate buffering and bounded raw/restored snapshot
storage; executable arguments remain withheld until completion, clean SSE EOF
and full batch validation. This is not full-output DLP. See
[ADR-0019](adr/0019-agent-streaming.md).
Validated upstream usage and cache-usage counters retain provider semantics;
restored text is not recounted as provider generation. Inspection still runs on
every cached/replayed request. Live cache hits, real tokenizer changes and token
savings require separate provider evidence.

Replay original/restored history on every request with a stable `X-Session-Id`,
`X-Conversation-Id`, public Codex `session-id`/`thread-id`, legacy `session_id` or native
Claude Code `x-claude-code-session-id` header. Aliases must agree.
Session identity is validated and mapped to a SHA-256 conversation scope bound
to authenticated tenant and `ApiKey.key_id` principal; the raw header
does not grant access to another principal's mappings. Every request has fresh
restoration provenance. Keep token/vault root keys stable for restart replay.
Forks use separate identities and inspect replayed context again. A validated
Claude `x-claude-code-agent-id` further partitions a session's restoration scope;
it grants no inherited provenance.
Preserve principal `key_id` on credential rotation to retain that scope.
`DELETE /v1/agent/sessions/{id}` deletes only the authenticated principal's
derived session mappings. Concurrent canonical token refreshes cannot replace
the original bound to current-request provenance after vault authentication.
The legacy Chat Completions request and conversation-deletion paths reserve the
`agent_` namespace and refuse IDs with that prefix, preventing them from selecting
or deleting a derived agent namespace.
See [ADR-0020](adr/0020-inspectable-agent-sessions.md).

Opaque reasoning, encrypted/signed continuation, opaque compaction,
`/v1/responses/compact`, provider-stored state, `store: true`,
`previous_response_id`, response retrieval and WebSockets are disabled. There is
no invariant waiver. Clients needing these capabilities are not supported by
this subset. The pinned custom-provider Codex profile selects local compaction
using ordinary inspected requests and replayed text summaries. Automatic local
compaction and resume passed in the actual pinned synthetic workflow below;
they require neither opaque state nor weaker current-request provenance.

## Implemented field dispositions

These contracts combine pinned public-client shapes and generated protocol
fixtures; actual workflow results are recorded separately below.
`parse_responses_request` / `parse_messages_request`
validate and rebuild these fields. `LocationBuilder` marks content and structural
strings and arbitrary JSON content numbers (as decimal structural locations),
then `AgentPreparation` inspects every location. Sensitive numbers are rejected
without coercion. Safe content values
can be transformed; sensitive structural values fail rather than changing their
meaning. All fields not listed in the native parser fail with a fixed safe code
and no provider call; no unknown field name is echoed into diagnostics.

| Responses field/item | Classification and reconstruction |
|---|---|
| `model` | Constrained structural identifier, inspected; optional gateway model override |
| `input`, `instructions` | Inspectable text or validated native item array; preserve ordering |
| Message `role`, `type`, `id`, `status`, assistant `phase` | Constrained structure; developer/system/user/assistant role contract, assistant phase null/commentary/final_answer; never restore |
| Message text/refusal blocks | Inspect text/refusal; replay output annotations must be empty; images/files refused |
| `function_call` arguments, `custom_tool_call` input | Decode JSON string and numeric leaves / inspect text custom input; sensitive numeric values fail; preserve call/name/ID associations |
| Function/custom call output | Inspect text or supported text blocks; match a prior unique call |
| `tools` | Explicit registered function schema or supported custom apply_patch text/pinned grammar format; inspect descriptions and schema strings/numbers including defaults/examples/enums/constants/bounds; bind current name/native type; validate bounded executable assertions and registered nested control/todo shapes; sensitive structural values fail; defer_loading only false |
| `tool_choice` | `none`/`auto`/`required` or declared function/custom name; constrained structure |
| `stream`, `parallel_tool_calls` | Strict booleans |
| `store`, `background` | Only false; outbound store explicitly false even when omitted |
| `max_output_tokens`, `max_tool_calls`, `temperature`, `top_p` | Bounded typed controls |
| `truncation`, `service_tier`, `reasoning` effort/summary | Explicit enum controls; opaque reasoning input/output unsupported |
| `text` verbosity/format | Explicit text/json_object/json_schema format; inspect schema/description, constrain format name |
| `include` | Empty or the unique reasoning.encrypted_content selector sent by pinned Codex; the selector does not permit nonempty encrypted output/replay |
| Empty `reasoning` replay item | Summary empty, content absent/null/empty, encrypted_content absent/null; constrained ID/status; nonempty reasoning or encrypted content refused |
| `prompt_cache_key` | Bounded inspected identifier; replace with a hash bound to tenant/principal/session, protocol/model/destination/policy before provider egress; raw cache field identity is not forwarded |
| `client_metadata` | Explicit typed Codex IDs and encoded turn metadata, including bounded compaction/workspace/tool-attribution shapes; inspect structural content, then consume locally; no attribution becomes execution authority |
| Provider state, arbitrary `metadata`, `prompt_cache_retention`, `user`, `safety_identifier`, `prompt` | Refused; no unknown semantics or blind pass-through |

| Messages field/block | Classification and reconstruction |
|---|---|
| `model`, `max_tokens`, `stream`, sampling controls, `service_tier` | Constrained identifier / bounded typed controls / explicit enums |
| `system`, user/assistant `messages`, `stop_sequences` | Inspect all accepted text in order |
| Text block `text`, optional empty `citations` | Inspect text; nonempty references refused |
| Assistant `tool_use` | Inspect JSON string/numeric input leaves; sensitive numbers fail; constrain name/ID; preserve association |
| User `tool_result`, `is_error` | Inspect text/text-block result; strict bool; match prior unique tool_use |
| `tools` name/description/input_schema | Bind registered name/type; inspect description plus schema strings/numbers, defaults/examples/enums/constants/bounds; sensitive structural values fail; reject unsupported executable assertions and validate restored arguments |
| `tool_choice` | Explicit auto/any/none/tool + declared name; optional strict disable_parallel_tool_use bool |
| `cache_control` | Ephemeral, optional 5m/1h TTL, at most four explicit breakpoints across supported request/system/text/tool/result locations; inspect every replay |
| `thinking` | Only the explicit disabled type; enabled/adaptive thinking and opaque output refused |
| `output_config` | Only bounded effort enums; no arbitrary output configuration |
| `metadata.user_id` | Bounded opaque identifier or the pinned CLI's typed device/account/session JSON identities; inspect, then consume locally; not forwarded as provider metadata |
| `container`, `mcp_servers`, `context_management`, images/files | Refused; no opaque or uninspectable pass-through |
| Token counting | Same validated/inspected request before counting; does not leak raw content |

Only `anthropic-version: 2023-06-01` is accepted. `anthropic-beta` accepts a
bounded list drawn from `claude-code-20250219`, `effort-2025-11-24`,
`interleaved-thinking-2025-05-14`, `context-1m-2025-08-07`,
`extended-cache-ttl-2025-04-11`, `prompt-caching-2024-07-31`,
`token-counting-2024-11-01`, `token-efficient-tools-2025-02-19` and
`fine-grained-tool-streaming-2025-05-14`. Unsupported values fail before egress.
These tags do not authorize thinking blocks, enlarge gateway limits or enable
unknown content. The validated beta list is reconstructed for the current native
provider request. Gateway credentials and raw client session headers are not
forwarded; upstream headers are constructed explicitly and use provider credentials.
No arbitrary client header forwarding occurs. Responses SSE text/refusal,
content parts, item/argument lifecycle and terminal snapshots, and Messages
start/block/delta/stop events have protocol-specific validation; unsupported
events fail rather than being forwarded unchanged. Native `stop_sequence` must
match the exact sanitized sequence requested on the current call.
The known inspection-character bound returns a safe native 400
context_length_exceeded error with an inspectable-compaction hint. Detector,
privacy, authentication and capacity failures retain distinct error handling;
no raw prompt/path/unknown field name is included in diagnostics. Model discovery
returns configured permitted model IDs rather than querying an upstream catalog.
Codex's remote_compaction_v2 beta hint can occur even with its local compaction
provider profile; it is not forwarded or permission to call the disabled compact
endpoint. Client transport/telemetry headers do not pass through as provider
attribution.
An identifier mentioned inside ordinary user/summary text remains inspected
content, rather than a structural identity field; UUIDs are not globally stripped
from prose. This distinction matters for native transcript references after
Claude compaction.

## Qualification gates

For each pinned matrix row, run on a disposable synthetic repository and inspect
every outbound request, permitted header, event and bypass path:

1. Startup, model discovery, instructions, file read/search, edit, patch and shell
   test execution; assert changed files and actual tool executions.
2. Follow-up, parallel tools, cancellation, safe retry, subagents/forks, long
   automatic compaction and restart/resume; assert session/provenance isolation.
3. Detectable canaries in all accepted locations are transformed or blocked;
   no canary appears in upstream bodies/headers, diagnostics or logs.
4. Forged/unresolved/expired/cross-session tokens, invalid arguments, malformed
   stream transitions and disallowed sinks release no executable tool batch.
5. Direct/gateway latency, usage/cache usage, memory, errors and capacity meet
   reference-deployment budgets; local routing has no external fallback.

Both pinned CLI profiles passed **read, edit, test, follow-up, automatic compact
and resume** in the local synthetic deployment below. The overall milestone
remains incomplete until the intended live/desktop deployment and release gates
pass. A text demo, generated fixture suite or preflight pass alone cannot
establish usable coding support.
No pilot approval or measured reference capacity is recorded in this matrix.

## Actual public CLI evidence (2026-10-08)

The installed Codex CLI 0.161.0 and Claude Code CLI 2.1.293 completed the full
synthetic coding, automatic-compaction and resume workflow through the real
gateway against a deterministic local provider. Eight separate CLI invocations
completed natively: initial read/edit/pytest, resumed follow-up, resumed long
session and post-compaction resume for each client. The harness verified changed
source, actual passing test execution, stable session scope, a real read of
1,000 synthetic note lines (91,000 bytes), inspected summary replay and restored
post-compaction follow-up. These are actual binary observations, distinct from
generated protocol fixtures.

Codex declared `exec_command`, restricted `write_stdin` and custom `apply_patch`;
the workflow executed reads/tests through `exec_command` and an actual patch.
It made one ordinary Responses summary request without tools and persisted its
native `compacted` rollout record with the summary/window/response identity.
Its JSON stdout omits a compaction event, so the persisted native record supplies
that evidence. Claude used `Read`, `Edit` and `Bash`, made two ordinary Messages
summary requests and emitted native `compact_boundary` events. No opaque compact
endpoint or provider-stored continuation was enabled.

All 21 native HTTP requests returned 200: nine Responses, ten Messages and two
Claude token-count requests. The original synthetic email canary was absent from
both upstream body histories and all 21 safe audit events. Structural client
metadata was consumed locally and cache/session identifiers were mapped under
their defined contract; ordinary inspected prose may still mention a transcript
identifier. Both replayed summaries contained the expected marker and transformed
canary directly in summary text before the resumed response restored it for the
client. Recognized automatic summary requests also contained final note 0999
with its transformed owner, proving that the long notes reached summarization.

| Compaction test control | Recorded setting |
|---|---|
| Gateway inspection characters | 262,144, distinct from the one-million-character deployment example |
| Codex catalog | auto_compact_token_limit=6000; tool-output truncation=30000 bytes |
| Claude environment | CLAUDE_CODE_AUTO_COMPACT_WINDOW=100000; CLAUDE_AUTOCOMPACT_PCT_OVERRIDE=5; CLAUDE_CODE_MAX_OUTPUT_TOKENS=1024 |
| Synthetic usage | Input tokens estimated as serialized inspected JSON characters //4; output count fixed by the local provider; no inflated pressure counter |

The lower public client thresholds make automatic compaction reproducible on
synthetic notes; they do not measure a real model's tokenizer, context capacity,
cache, quality or cost. The final strengthened report recorded success,
privacy_checked and automatic_compaction_qualified as true. The
[sanitized aggregate report](../tests/fixtures/agent_protocols/public-cli-qualification.json)
records the successful runs, privacy assertions, controls and qualification
limits without raw requests or client identities. Reproduce it with
`scripts/public_client_check.py --mode gateway --workflow --compact --timeout 120`
and explicitly supplied pinned binary paths. Normal pytest does not download or
run public CLI binaries. Desktop, live provider and production capacity remain
unqualified.

## Operator evidence

[Client examples](../deployment/clients/README.md) reproduce the pinned restricted
CLI profiles; desktop and production qualification remains separate.
`scripts/agent_preflight.py` makes explicitly requested
network probes with synthetic data and a restricted local read round trip.
`scripts/benchmark_agents.py` measures a synthetic direct/gateway comparison by
detector profile and request size. Neither runs real Codex or Claude Code.
`scripts/public_client_check.py` runs explicitly supplied pinned CLI binaries on
disposable synthetic repositories, with isolated client configuration and a local
provider; it neither installs clients nor uses real provider credentials.

The gateway covers configured inference endpoints. Client telemetry, MCP,
download/web requests and executed commands can use separate network paths.
Deployment-wide egress restrictions must be tested and enforced separately.

## Implementation verification (2026-10-08)

These results cover the final public-profile source and the exact image below.
They establish implementation evidence, with separate client and production
qualification limits.

| Check | Recorded result | Scope |
|---|---|---|
| Main test suite | 1,700 passed; 48 container tests deselected, in 14.28 seconds | Automated repository regression corpus, including public request contracts, native CLI proof validators and cancellation audit |
| Lint and package smoke | Ruff passed 144 files; wheel and sdist installed smoke checks passed | Packaged CLI/API behavior; includes the Apache grammar notice |
| Demo and leakage checks | Offline demo passed; 62 leakage cases passed | Synthetic inspection corpus, not perfect detection evidence |
| Licence checks | 62 dependency components passed | Licence checks; does not imply independent security review |
| Dependency vulnerability checks | Both hash-locked runtime and main dependency pip-audit checks found no known vulnerabilities | Tool/database result; does not imply independent security review |
| Container tests | All 48 existing/agent tests passed on the exact final image in 17.41 seconds | Native protocol/tool/security and container-hardening regressions |
| Secret scans | Gitleaks 8.30.1 passed all 23 committed revisions and the proposed source tree | Secret-detection tool result, not a proof of complete secret absence |
| Image vulnerability scan | Trivy 0.75.0 with official GHCR database: zero blocking HIGH/CRITICAL findings on the final exact image | Tool/database result, not independent security review or release qualification |
| SBOM | Source CycloneDX SBOM covers 62 components; exact-image container SBOM generated | Inventory artifacts; does not establish signing or provenance |
| Native synthetic benchmark | 40 direct and 40 gateway runs; zero failures | In-process synthetic provider/runtime paths; no real client/model/network/cache qualification |
| Concurrency responsiveness | Health request p50 24.49 ms against a 500 ms synthetic gate | Synthetic concurrency check; no whole-container RSS or production capacity evidence |

The final tested container tag was `secure-ai-gateway:agent-test`, image ID
`sha256:0de0ce4e7daab9cdc4947a76ab3606d7a2f201f2671347afb07bbd416090b749`.
It uses the repository's pinned base
`python:3.12-alpine3.23@sha256:33a47b0a92c0766bdd77cd82bbaa4c320ce48db01a2bfe1782920ca7a16e3744`.
The build used temporary BuildKit CA secret mounts for network installation;
the CA was not baked into the image. Final container tests and the image scan
ran against that exact image. Wheel and sdist installed-package smoke checks
also passed after their final rebuild. All 75 gateway module hashes in the image
match the final source. Signing, publishing and required CI release checks remain pending,
so this is implementation verification, not release or reference-deployment
qualification.

Outstanding production evidence: desktop workflows and selected deployment
OS/model/optional bridge; endpoint-bypass coverage; live provider
tool/cache behavior and a bounded live budget; reference deployment latency,
capacity and complete RSS measurements; independent security review and final
release-artifact checks. Pinned public CLI coding, automatic inspectable compaction
and resume passed in the local synthetic deployment, independently of private captures.
If another client profile requires opaque state, a
separate reviewed continuation ADR and any explicitly approved dated/named
invariant waiver must precede enabling it. No waiver or pilot approval exists.
These passing implementation checks leave the milestone incomplete.
