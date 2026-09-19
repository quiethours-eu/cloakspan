# OpenAI compatibility contract

**Status:** alpha · enforces [SI-01](security-invariants.md#si-01--no-uninspected-egress)
and [SI-02](security-invariants.md#si-02--reject-unknown-content)

This document is the complete list of what the gateway accepts, rejects, and
ignores. It exists because "OpenAI-compatible" is not a specification — every
proxy in this category means something slightly different by it, and the
difference is exactly where uninspected content gets through.

**The contract rule:** every accepted field has a named inspection function.
Every rejected field has a documented HTTP status and error code. There is no
third category of "passed through because nobody thought about it".

## Column meanings

| Column | Meaning |
|---|---|
| **Accepted** | The gateway understands this field, inspects it if it can carry content, and forwards it |
| **Rejected** | The request fails with the stated status; nothing is forwarded |
| **Ignored** | Stripped from the outbound payload; the request proceeds |
| **Inspection** | The function that scans the field. `—` means the field cannot carry customer content |

---

## Endpoints

| Endpoint | v1 | Notes |
|---|---|---|
| `POST /v1/chat/completions` | **Accepted** | The only inspected request path |
| `GET /v1/models` | **Accepted** | Lists configured *destinations*, not upstream models. Requires auth |
| `DELETE /v1/conversations/{id}` | **Accepted** | Not an OpenAI endpoint. Erases every surrogate mapping for the conversation, scoped to the authenticated tenant by construction, so one tenant cannot delete another's records by guessing an id. Required for an erasure request to be answerable in seconds rather than one TTL. Returns `records_removed`; idempotent. See [ADR-0013](adr/0013-vault-lifetime-deletion-and-restart.md) |
| `GET /healthz` | **Accepted** | Liveness. No auth, no downstream calls |
| `GET /readyz` | **Accepted** | Readiness. Never checks an external provider ([SI-15](security-invariants.md#si-15--no-control-plane-dependency-on-the-request-path)) |
| `POST /v1/completions` | **Rejected** | 404. Legacy endpoint; no inspection path written for it |
| `POST /v1/embeddings` | **Rejected** | 404. Planned; input arrays need their own inspection contract |
| `POST /v1/responses` | **Rejected** | 404. Plan Phase 3 |
| `POST /v1/moderations`, `/v1/files`, `/v1/assistants`, everything else | **Rejected** | 404 |
| `/docs`, `/redoc`, `/openapi.json` | **Disabled** | Unnecessary surface on a security appliance ([app.py](../gateway/api/app.py)) |

---

## `POST /v1/chat/completions` — top-level fields

### Accepted

| Field | Type | Inspection | Notes |
|---|---|---|---|
| `model` | string | `ApiKey.permits_model` | 403 `invalid_request_error` if the key is not scoped to it. May be replaced by `SAG_EXTERNAL_MODEL` / `SAG_LOCAL_MODEL` before egress |
| `messages` | array | `SecurityPipeline.inspect_payload` | See the message contract below. Required, non-empty, else 422 |
| `temperature`, `top_p`, `n`, `max_tokens`, `max_completion_tokens`, `presence_penalty`, `frequency_penalty`, `seed`, `logprobs`, `top_logprobs`, `parallel_tool_calls` | scalar | — | Numeric and boolean sampling controls. Forwarded verbatim |
| `service_tier` | enum | — | Only the schema's named provider tiers are accepted; arbitrary text is rejected |

### Rejected

| Field | Condition | Status | Error code | Why |
|---|---|---|---|---|
| `stream` | truthy | **400** | `streaming_unsupported` | Buffered inspection is the v1 design. An entity split across two chunks can be released before it is recognised. Refused explicitly, never silently downgraded |
| `stream_options` | present | **422** | `uninspectable_field` | Meaningless without streaming; accepting it would imply support |
| `tools`, `functions` | present | **422** | `uninspectable_field` | Tool and function **descriptions and schemas are customer content** and are not yet inspected. Forwarding them uninspected violates SI-01 |
| `stop`, `user` | present | **422** | `uninspectable_field` | Both can carry free text. This version inspects message content only, so it refuses them rather than forwarding them unscanned |
| `tool_choice`, `function_call` | present | **422** | `uninspectable_field` | Rejected with the fields they control, for coherence |
| `response_format` | present | **422** | `uninspectable_field` | Structured-output schemas carry field names and descriptions. Plan Phase 5 |
| `logit_bias` | present | **422** | `uninspectable_field` | Token-id map; correct handling requires the upstream tokenizer, which the gateway does not have |
| `metadata`, `store` | present | **422** | `uninspectable_field` | `store: true` asks the provider to retain the request — a retention decision the gateway must not silently relay |
| `prediction` | present | **422** | `uninspectable_field` | Predicted output carries customer content and is not inspected |
| `audio`, `modalities` | present | **422** | `uninspectable_field` | Non-text output is outside the buffered text contract |
| *any unrecognised key* | present | **422** | `unknown_field` | **Reject-unknown is the contract.** A field we do not recognise is a field we did not inspect |

### Ignored

None. There is deliberately no ignore list: silently dropping a field a customer
set produces behaviour they cannot explain, and "we ignored it" and "we forwarded
it" must never be indistinguishable from outside.

---

## The `messages` contract

Each element must be a JSON object. A non-object element is **422
`invalid_message`**.

### Roles

| Role | v1 | Inspection |
|---|---|---|
| `system` | **Accepted, inspected** | `SecurityPipeline._detect` over `content` |
| `user` | **Accepted, inspected** | ” |
| `assistant` | **Accepted, inspected** | ” |
| `tool` | **Accepted, inspected** | ” |
| `developer` | **Rejected — 422 `unsupported_role`** | Not in `INSPECTED_INPUT_ROLES`. Accepting it without inspecting it is an SI-01 bypass |
| `function` | **Rejected — 422 `unsupported_role`** | Legacy |
| *any other string* | **Rejected — 422 `unsupported_role`** | Reject-unknown |

### Message fields

| Field | v1 | Inspection |
|---|---|---|
| `role` | **Required.** Must be one of the four accepted roles | Allowlist check |
| `content` | **Required, must be a string** | `SecurityPipeline._detect`, then `TransformationEngine.transform` |
| `content` as an array (multimodal / content parts) | **Rejected — 422 `inspection_failed`** | Non-text parts cannot be scanned; refusing beats forwarding bytes we did not read |
| `content: null` | **Rejected — 422 `inspection_failed`** | Valid in OpenAI for assistant tool-call messages; those are rejected in v1 anyway |
| `name` | **Rejected — 422 `uninspectable_field`** | Free-text participant name. Carries PERSON data and is not inspected |
| `tool_calls`, `tool_call_id`, `function_call` | **Rejected — 422 `uninspectable_field`** | Tool-call arguments are customer content. Restoration never writes into control fields |
| *any unrecognised key* | **Rejected — 422 `unknown_field`** | Reject-unknown |

### Size limits

| Limit | Value | Behaviour |
|---|---|---|
| HTTP request body | `SAG_MAX_REQUEST_BYTES`, default 1 048 576 bytes | **413 `request_too_large`**, enforced while streaming before JSON parsing |
| Total inspected characters | `SAG_MAX_INPUT_CHARS`, default 65 536 | **422** once the running total is exceeded |
| Message count | 512 | **422 `invalid_message`** above the cap |

---

## Response contract

The provider response is read in full. Token restoration runs only after the
complete body is available.

| Response field | Restoration | Notes |
|---|---|---|
| `choices[].message.content` | **Restored** | The only field on the restoration allowlist |
| `choices[].message.role`, `finish_reason`, `index` | Not restored | Control data |
| `choices[].message.tool_calls` | Not restored, **not inspected** | Tool calls are rejected on the request path, so a compliant provider cannot produce them. A non-compliant one that does gets its tool call forwarded to the client with tokens unrestored — correct, but untested |
| `id`, `object`, `created`, `model`, `usage`, `system_fingerprint` | Passed through | |
| Any other provider field | Passed through | **Gap.** The response is not schema-validated; a provider that returns extra fields has them relayed to the client |

A token appearing anywhere outside the allowlist is left verbatim. The gateway
never guesses, never falls back, and never partially restores.

### Response headers

These are additions to the OpenAI shape. SDKs ignore them; operators use them.

| Header | Meaning |
|---|---|
| `X-Request-Id` | Correlates with the audit event |
| `X-Conversation-Id` | Echoes or assigns the conversation scope |
| `X-Policy-Decision` | `allow` / `transform` / `route_local` / `block` |
| `X-Policy-Rule` | The rule that decided |
| `X-Policy-Version` | Declared version, or `sha256:` of the policy file |
| `X-Entities-Detected` | Count only, never types-with-values |
| `X-Tokens-Restored` | |
| `X-Tokens-Refused` | Sustained non-zero values indicate token-probing; alert on it |

---

## Error envelope

Every error uses OpenAI's shape so existing SDKs handle it naturally:

```json
{"error": {"message": "...", "type": "...", "param": null, "code": "..."}}
```

| Status | `type` | `code` | Cause |
|---|---|---|---|
| 400 | `invalid_request_error` | — | Body is not valid JSON, or not a JSON object |
| 400 | `invalid_request_error` | `streaming_unsupported` | `stream` is truthy |
| 401 | `invalid_request_error` | `invalid_api_key` | Missing or unknown bearer token |
| 413 | `invalid_request_error` | `request_too_large` | The streamed HTTP body crossed `SAG_MAX_REQUEST_BYTES` |
| 403 | `invalid_request_error` | — | The API key is not scoped to the requested model |
| 403 | `policy_violation` | `blocked_by_policy` | A policy rule blocked the request. The rule name is included; the matched content is not |
| 422 | `inspection_error` | `inspection_failed` | Content could not be inspected. Fail closed |
| 422 | `inspection_error` | `unsupported_role` | Message role outside the allowlist |
| 422 | `inspection_error` | `uninspectable_field` | A field that carries content the gateway cannot yet scan |
| 422 | `inspection_error` | `unknown_field` | Reject-unknown |
| 502 | `api_error` | `upstream_error` | Provider failure. Status only — never the provider's response body, which can echo the prompt back |
| 504 | `api_error` | `upstream_error` | Provider timeout |
| 500 | `api_error` | — | Unhandled. Returns a request id to quote; the traceback goes to the log only |

No error message contains prompt content, restored values, or provider
credentials ([SI-11](security-invariants.md#si-11--no-content-in-observability),
[SI-12](security-invariants.md#si-12--no-provider-credentials-in-logs-or-errors)).

---

## Authentication

| Aspect | Behaviour |
|---|---|
| Scheme | `Authorization: Bearer <key>` |
| Storage | SHA-256 hash, never plaintext; constant-time comparison |
| Scope | Each key carries a tenant id and an application name; the tenant becomes the vault scope |
| Conversation | `X-Conversation-Id` request header. **Absent → a fresh conversation id is generated**, which means tokens from a previous turn will not restore. Clients that want multi-turn consistency must send it |
| Rotation / expiry | **Not implemented.** T14 in the threat model |

---

## Conformance status

The table below summarizes the enforced contract.

| Contract requirement | Today |
|---|---|
| `stream` rejected | ✅ `schema.py`, 400 `streaming_unsupported` |
| Non-string `content` rejected | ✅ 422 `inspection_failed` |
| Streamed body and inspected-text limits enforced | ✅ 413 body cap; 422 inspection cap |
| Model scoping enforced | ✅ [app.py](../gateway/api/app.py) |
| Restoration allowlist enforced | ✅ `RESTORABLE_RESPONSE_FIELDS` |
| Unrecognised **roles** rejected | ✅ 422 `unsupported_role` |
| Unrecognised **top-level fields** rejected | ✅ 422 `unknown_field` |
| `tools` / `functions` rejected | ✅ 422 `uninspectable_field` |
| `response_format` rejected | ✅ 422 `uninspectable_field` |
| Message `name` rejected | ✅ 422 `uninspectable_field` |
| Request schema validated | ✅ `ChatCompletionRequest`, `extra="forbid"` |
| Message-count cap | ✅ `MAX_MESSAGES` = 512 |
| Free-text `stop` / `user` fields refused | ✅ 422 `uninspectable_field` |
| Response schema validated | ➖ **By decision, no.** See below |

**[SI-01](security-invariants.md#si-01--no-uninspected-egress) and
[SI-02](security-invariants.md#si-02--reject-unknown-content) are met.** The body
is validated against a typed model with `extra="forbid"`, and — the part that
makes it structural rather than careful — **the outbound payload is rebuilt from
the validated model, not from the client's dict**. A key that is not a field on
the model is not carried anywhere, so it cannot reach the provider even if a
future change forgets to check for it.

Enforced by [tests/test_request_contract.py](../tests/test_request_contract.py),
including the property form of SI-01: for any accepted payload, every string the
provider receives came from a message we inspected or is a token we minted.

### Why responses are *not* schema-validated

Deliberate asymmetry, stated so it reads as a decision rather than an oversight.
Rejecting a provider's new response field would break the gateway every time an
upstream ships a feature, and the security boundary on the response side is the
**restoration allowlist**, not the schema: a token is only ever expanded in
`choices[].message.content`, so an unrecognised field cannot cause a value to be
released. Requests are attacker-controlled; responses come from a destination the
operator chose. The two get different rules for that reason.
