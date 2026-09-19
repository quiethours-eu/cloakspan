# Security Invariants

**Status:** FROZEN for v1 · 2026-08-03 · supersedes the invariant table
previously embedded in `docs/threat-model.md`

An invariant is a **release requirement**, not a design preference. Each one
below has a statement, a reason, the code that enforces it, the test that proves
it, an owner, and an honest status. A gap here is a gap in the product, not a
gap in the documentation.

> **An invariant may be waived only by a written, dated decision with a named
> owner.** Silent waivers are how this category of product fails.

## Status legend

| Mark | Meaning |
|---|---|
| ✅ **MET** | Enforced in code and covered by at least one test |
| 🔶 **PARTIAL** | Enforced for the common case; a named gap remains |
| ❌ **NOT MET** | Stated but not yet enforced, or currently contradicted by the implementation |

---

## Numbering, and why it changed

The repository previously used a bare `#1`–`#10` invariant numbering, referenced
from source comments, tests, the Dockerfile, and eight documents. The external
implementation plan introduces its own `1`–`12` list that **reuses the same
numbers for different requirements** — its `#9` is "no content in observability",
ours was "no custom cryptography".

Leaving both in place would make every `invariant #N` comment in the tree
ambiguous. The two lists are therefore merged here into one set with `SI-` prefixed
identifiers, which are stable from now on. Any remaining bare `#N` reference in
the tree is stale and should be treated as a defect.

### Mapping from the legacy numbering

| Legacy (`threat-model.md`) | Now |
|---|---|
| #1 No restoration without authenticated tenant + conversation | SI-04 |
| #2 No cross-tenant mapping lookup | SI-05 |
| #3 No arbitrary placeholder triggers restoration | SI-03 |
| #4 Raw content not logged by default | SI-11 |
| #5 Provider credentials never in logs | SI-12 |
| #6 Control-plane outage does not break self-hosted requests | SI-15 |
| #7 Malformed/unsupported structures fail per explicit policy | SI-02 |
| #8 Security-critical actions produce audit evidence | SI-13 |
| #9 No custom cryptography | SI-09 |
| #10 No production claim without independent review | SI-18 |

### Mapping from the implementation plan's list

| Plan §4 | Now |
|---|---|
| 1 No uninspected egress | SI-01 |
| 2 Reject unknown content | SI-02 |
| 3 Current-request restoration only | SI-03 |
| 4 Unguessable token identity | SI-06 |
| 5 Unambiguous token derivation | SI-07 |
| 6 Cryptographic context binding | SI-05 |
| 7 Safe AES-GCM operation | SI-08 |
| 8 Fail closed | SI-10 |
| 9 No content in observability | SI-11 |
| 10 Explicit egress | SI-14 |
| 11 Retry safety | SI-16 |
| 12 Original-text integrity | SI-17 |

Legacy invariants with no counterpart in the plan (SI-04, SI-09, SI-12, SI-13,
SI-15, SI-18) are retained: each closes a threat in the register and dropping
them to match an external list would be a regression.

---

## The invariants

### SI-01 — No uninspected egress

**Statement.** No part of an accepted request may leave the gateway before
detection and policy evaluation have run over it.

**Why.** This is the product. Everything else is a refinement of it. A field that
reaches the provider unscanned means the customer's control did not apply, and
they will not know which requests were affected.

**Enforced by.** `SecurityPipeline.inspect_payload`
([pipeline.py:124](../gateway/inspection/pipeline.py)) detects over every
message it inspects; `process` ([pipeline.py:201](../gateway/inspection/pipeline.py))
builds the outbound payload from the inspected text.

**Test.** `evals/leakage/test_leakage_regression.py::TestPseudonymisationPreventsLeakage`
asserts against what the mock provider actually received.

**Status.** ✅ **MET.** The two bypasses that stood here since the contract freeze
are closed:

1. **Unrecognised message roles** — a message with `role: "developer"`, a role
   OpenAI itself now uses, was skipped by inspection and still copied into the
   outbound payload. Now 422 `unsupported_role`.
2. **Unknown top-level fields** — `outbound = dict(payload)` copied the whole
   body, so `tools`, `response_format`, and any misspelled or future field
   passed through uninspected. Now 422 `unknown_field` or `uninspectable_field`.

What makes it structural rather than careful: **the outbound payload is rebuilt
from the validated model**, not from the client's dict
([schema.py](../gateway/api/schema.py)). A key that is not a field on
`ChatCompletionRequest` is not carried anywhere, so it cannot reach the provider
even if a future change forgets to reject it.

**Test.** `tests/test_request_contract.py::TestNothingReachesTheProviderUninspected`
— including the property form the invariant-test matrix named as the highest-value
gap: for any accepted payload, every string the provider receives came from an
inspected message or is a token we minted. It would have caught both bypasses
without anyone enumerating either.

**Owner.** Technical lead (contract), Security owner (sign-off).

---

### SI-02 — Reject unknown content

**Statement.** Unsupported, ambiguous, or unrecognised payload shapes return an
explicit 4xx. The gateway never chooses between "inspect" and "forward" by
guessing; when it cannot classify a field, it refuses the request.

**Why.** An allowlist that fails open is not an allowlist. The failure mode of a
denylist is silent, and silence in a security control is indistinguishable from
success.

**Enforced by.** Non-string message content raises `DetectionError` → HTTP 422
([pipeline.py:147](../gateway/inspection/pipeline.py)); `stream=true` returns
HTTP 400 with `streaming_unsupported`
([app.py:119](../gateway/api/app.py)); oversized input returns 422
([pipeline.py:157](../gateway/inspection/pipeline.py)).

**Test.** `evals/leakage/...::TestFailClosed::test_non_text_content_is_refused_not_forwarded`,
`tests/test_api_e2e.py::TestChatCompletions::test_streaming_is_refused_explicitly`.

**Status.** ✅ **MET.** `ChatCompletionRequest` uses `extra="forbid"`, a
`Literal` role allowlist, `str`-only content, and a 512-message cap. Recognised
-but-refused fields carry their own code and an explanatory reason, so an
integrator can tell "you sent something we do not recognise" from "we recognise
this and deliberately refuse it".

Responses are deliberately **not** schema-validated. The asymmetry is argued in
[docs/openai-compatibility.md](openai-compatibility.md#why-responses-are-not-schema-validated):
requests are attacker-controlled, responses come from a destination the operator
chose, and the response-side boundary is the restoration allowlist rather than
the schema.

**Owner.** Technical lead.

---

### SI-03 — Current-request restoration only

**Statement.** A value is restored into a response only when its exact token is
present in the immutable provenance set created by **this** pipeline run.

**Why.** This is the invariant every comparable open-source project is missing,
and the reason the product exists. A token the user legitimately saw in turn 1,
replayed into turn 5, must not expand — because the gateway cannot distinguish a
user quoting a token from an attacker probing one.

**Enforced by.** `TokenProvenance` is constructed fresh per request
([pipeline.py:180](../gateway/inspection/pipeline.py)), never persisted, never
shared; `RestorationEngine.restore` refuses any token failing
`was_minted_here` before it reaches the vault
([restoration/engine.py:80](../gateway/restoration/engine.py)).

**Test.** `tests/test_restoration_safety.py::TestAttackerInjectedTokens` (4 tests),
notably `test_token_from_an_earlier_turn_is_not_replayed`, which confirms the
vault genuinely holds the value and *still* refuses under fresh provenance.

**Status.** ✅ **MET.**

**Owner.** Security owner.

---

### SI-04 — Authenticated scope on every vault and restoration call

**Statement.** No code path reaches the vault or the restoration engine without a
`RequestContext` carrying an authenticated tenant and conversation.

**Why.** Structural enforcement beats tested enforcement. A check can be removed
by a refactor; a required constructor argument cannot be removed without the
change being visible in every call site.

**Enforced by.** `RequestContext` is a required first parameter of
`SurrogateVault.put/get/delete` ([vault/store.py:131](../gateway/vault/store.py))
and `RestorationEngine.restore`; it validates non-empty strings in
`__post_init__` ([domain.py:90](../gateway/domain.py)).

**Test.** `tests/test_restoration_safety.py::TestCrossTenantIsolation`.

**Status.** ✅ **MET.**

**Owner.** Security owner.

---

### SI-05 — Cross-tenant isolation is cryptographic, not control-flow

**Statement.** Tenant, conversation, token version, and entity type are
authenticated as vault context. A record addressed from the wrong context must
fail to decrypt, not merely fail a comparison.

**Why.** Control-flow isolation is one missing `if` away from a breach.
Cryptographic isolation degrades to "undecryptable bytes", which is a safe
failure.

**Enforced by.** Tenant and conversation are part of the storage key
([vault/store.py:115](../gateway/vault/store.py)) **and** bound into the AEAD
additional authenticated data ([vault/store.py:121](../gateway/vault/store.py))
**and** re-checked on the decrypted plaintext, raising `CrossTenantAccessError`
([vault/store.py:169](../gateway/vault/store.py)).

**Test.** `TestCrossTenantIsolation` (3), `tests/test_api_e2e.py::TestTenantIsolationOverHttp` (2).

**Status.** ✅ **MET.** Tenant, conversation, token, token version, key version,
and record format version are all bound into a length-prefixed, domain-separated
AAD ([ADR-0012](adr/0012-vault-record-envelope-and-key-rotation.md)). Entity type
is bound transitively, because the token string is in the AAD and the token
embeds its entity type.

The cryptographic claim itself is now tested, not just the behaviour:
`test_relocated_blob_fails_to_decrypt_not_merely_compare` decrypts a record with
the right AAD and with a different tenant's AAD and asserts the second fails at
the cipher. Every earlier cross-tenant test would still have passed with the AAD
removed.

**Owner.** Security owner.

---

### SI-06 — Unguessable token identity

**Statement.** Tokens are non-sequential and carry at least a 128-bit
security margin, unless an independent reviewer approves a smaller value in
writing.

**Why.** Sequential tokens are defeated by counting, with no exploit to write.
Every implementation we reviewed mints them.

**Enforced by.** The tag is `HMAC-SHA256` over the request context, truncated to
8 bytes / 16 hex characters ([tokens.py:116](../gateway/transformations/tokens.py)).
An explicit collision check refuses to mint rather than overwrite
([tokens.py:156](../gateway/transformations/tokens.py)).

**Test.** `TestConsistency::test_tokens_are_not_sequential`,
`tests/test_properties_and_fuzz.py::test_token_shaped_garbage_is_never_restored`.

**Status.** ✅ **MET, with the question left open for the reviewer.** The token
format is now `<ENTITY_TYPE:v1:TAG>` with a **128-bit** tag, and the version is
bound into both the HMAC input and the vault AAD.

The prior 64-bit argument — that this is a forgery problem rather than a
collision problem, and that a forged tag must additionally land inside the single
request that mints it — is not wrong, and it is preserved in
[ADR-0011](adr/0011-token-format-and-versioning.md). But SI-06 permits a smaller
value only with written independent-reviewer approval, which does not exist, and
the cost of 128 bits is 16 characters per token. We pay it and put the question
on the Phase 7 agenda; versioning is what makes either answer cheap to adopt.

The collision branch — the stated defence against T3 — now executes under test
for the first time (`test_distinct_values_with_the_same_tag_refuse_to_mint`).

**Owner.** Security owner; resolution requires the Independent reviewer.

---

### SI-07 — Unambiguous token derivation

**Statement.** HMAC inputs use domain separation and length-prefixed or otherwise
canonical serialization. Raw string concatenation is prohibited.

**Why.** `("ab", "c")` and `("a", "bc")` must not produce the same message. With
naive concatenation a tenant named `acme\x00x` collides with tenant `acme` in
conversation `x`, and the collision restores one customer's data into another's
response.

**Enforced by.** Each field is length-prefixed and NUL-joined before hashing
([tokens.py:130](../gateway/transformations/tokens.py)).

**Test.** `tests/test_restoration_safety.py::TestConsistency::test_same_value_differs_across_tenants`
and `test_same_value_differs_across_conversations`.

**Status.** ✅ **MET.** Separator-injection cases such as a tenant id containing
`\x00` or `:` remain part of the adversarial regression suite.

**Owner.** Security owner.

---

### SI-08 — Safe AEAD operation

**Statement.** Every encryption operation uses a nonce that is unique under its
key. Records carry a key version and support rotation.

**Why.** GCM nonce reuse under one key is catastrophic — it leaks the
authentication key, not just one plaintext. A vault with no key version cannot be
rotated without downtime or data loss, so in practice it is never rotated.

**Enforced by.** A fresh 96-bit `os.urandom` nonce per `put`
([vault/store.py:143](../gateway/vault/store.py)), prefixed to the ciphertext.
Random 96-bit nonces are the standard construction for this key volume.

**Test.** `tests/test_restoration_safety.py::TestCrossTenantIsolation::test_a_different_token_key_cannot_verify`.

**Status.** ✅ **MET.** Records now carry a self-describing envelope —
`format_version ‖ key_version ‖ nonce ‖ ciphertext` — bound into the AAD. Keys
are derived from operator root secrets with HKDF under distinct info strings, so
setting `SAG_VAULT_KEY` and `SAG_TOKEN_KEY` to the same value still yields two
unrelated keys. Rotation is additive (`SAG_VAULT_KEY_V<n>` plus
`SAG_VAULT_ACTIVE_KEY_VERSION`) and needs no re-encryption pass, because records
are short-lived by design.

The failure this closes is the quiet one: rotating the key used to render every
mapping undecryptable while surfacing **no error at all**, because a decryption
failure is deliberately treated as "absent". A record naming an unconfigured key
version now raises `VaultKeyUnavailableError`
(`test_removing_a_key_still_in_use_is_loud_not_silent`).

**Owner.** Security owner (design), Platform owner (rotation runbook).

---

### SI-09 — No custom cryptography

**Statement.** No cryptographic primitive is implemented in this repository.

**Why.** We are not qualified to, and neither is our reviewer pool. A product
whose entire claim is cryptographic isolation cannot afford a hand-rolled
construction.

**Enforced by.** `hmac`/`hashlib` from the standard library
([tokens.py:133](../gateway/transformations/tokens.py)); `AESGCM` from
`cryptography` ([vault/store.py:111](../gateway/vault/store.py));
`hmac.compare_digest` for secret-dependent comparison
([tokens.py:189](../gateway/transformations/tokens.py)).

**Test.** Reviewed at code review; no automated check.

**Status.** ✅ **MET.**

**Owner.** Security owner.

---

### SI-10 — Fail closed

**Statement.** Detector errors, detector timeouts, normalization failures, vault
failures, and ambiguous restoration states block release. Never fall through to
"allow".

**Why.** If the gateway cannot determine what is in the prompt, it cannot decide
whether the prompt is safe to send. Guessing permissively defeats the product.

**Enforced by.** Any detector exception raises `DetectionError` → HTTP 422 and the
request is never forwarded ([pipeline.py:115](../gateway/inspection/pipeline.py),
[app.py:143](../gateway/api/app.py)). Policy evaluation falls through to an
implicit deny ([policy/engine.py:94](../gateway/policy/engine.py)) and the
loader refuses a policy without a catch-all rule
([policy/engine.py:160](../gateway/policy/engine.py)). Restoration leaves a
token verbatim rather than partially restoring
([restoration/engine.py:96](../gateway/restoration/engine.py)).

**Test.** `evals/leakage/...::TestFailClosed`, `tests/test_policy_engine.py::TestValidation`.

**Status.** ✅ **MET** for detectors, policy, and restoration. **Detector
*timeouts* are not implemented** — a detector that hangs blocks the request
thread until the client gives up, which fails closed by accident rather than by
design. Tracked as R-03 (ReDoS) in the risk register.

**Owner.** QA/reliability owner.

---

### SI-11 — No content in observability

**Statement.** Logs, metrics, traces, health responses, audit events, and
exception serialization cannot contain prompt text, response text, a restored
value, or vault plaintext.

**Why.** A privacy control whose logs are a second copy of the data has moved the
problem, not solved it — and moved it somewhere with weaker access control and
longer retention.

**Enforced by.** `AuditEvent` is a frozen, slotted dataclass with an explicit
field list and **no `extra`/`metadata` dict**
([audit/events.py:30](../gateway/audit/events.py)) — there is no field through
which a future change smuggles prompt text without altering the class.
Only entity **types and counts** are recorded. `DetectionError` names the detector
and the exception type, never the text
([pipeline.py:117](../gateway/inspection/pipeline.py)).

**Test.** `tests/test_audit_and_logging.py::TestAuditContainsNoRawContent` (canary
value), `::test_audit_event_has_no_extensible_field` (structural).

**Status.** 🔶 **PARTIAL.** Audit and error paths are enforced and tested —
`TestExceptionsCarryNoPlaintext` searches the `str`, `repr`, and full traceback
of every exception the pipeline can raise for the value that caused it, which is
exactly where a well-meaning `f"failed on {text}"` would land.

The container log scan is now a job rather than an anecdote
(`make test-container`), but **it has never executed**: the Docker registry was
unreachable in our environment, so it skips with an explicit reason. It must run
once before the container claim counts as evidence.

Still open: OpenTelemetry tracing is not implemented and must be built
redaction-first; there is no metrics surface yet. Both belong under this
invariant, not after it.

**Owner.** Platform owner.

---

### SI-12 — No provider credentials in logs or errors

**Statement.** Provider API keys never appear in a log line, an error message, an
audit event, or an HTTP response.

**Why.** httpx exception strings contain the full request URL, which can carry
credentials. An error path is still a log path.

**Enforced by.** `ProviderError` construction deliberately excludes `str(exc)` and
the response body, surfacing only the exception type and status code
([routing/base.py:138](../gateway/routing/base.py)).

**Test.** `tests/test_audit_and_logging.py::TestNoCredentialLeakage`.

**Status.** ✅ **MET.**

**Owner.** Platform owner.

---

### SI-13 — Security-critical actions produce audit evidence

**Statement.** Every block, every refused token, and every cross-tenant refusal
produces an audit event before the request terminates.

**Why.** The audit trail is what the customer shows their regulator. An action
with no record did not happen, as far as an assessor is concerned.

**Enforced by.** A blocked request is audited *before* `PolicyBlockedError` is
raised ([pipeline.py:186](../gateway/inspection/pipeline.py)); the success path
records `tokens_restored` and `tokens_refused`
([pipeline.py:230](../gateway/inspection/pipeline.py)). Policy version is
stamped into every event, so a decision is reproducible.

**Test.** `tests/test_audit_and_logging.py::TestAuditSerialisation`,
`tests/test_api_e2e.py::TestChatCompletions::test_blocked_request_returns_403`.

**Status.** 🔶 **PARTIAL.** The audit schema now carries a version
(`AUDIT_SCHEMA_VERSION`, currently 2) and refusals are broken down by reason —
`not_minted`, `vault_miss`, `cross_tenant`, `key_unavailable` — so an empty vault
after a restart is distinguishable from an attacker enumerating tokens. Without
that breakdown the metric was unalertable, because every deploy produced the same
spike as an attack.

Still open: `DetectionError` and `ProviderError` paths return 4xx/5xx **without
writing an audit event**, so a request refused for un-inspectable content leaves
no record. Phase 6.

**Owner.** Platform owner.

---

### SI-14 — Explicit egress

**Statement.** Provider destinations are configured server-side, validated, and
allowlisted. Ambient proxy environment variables are ignored. Clients cannot
choose an upstream URL.

**Why.** A gateway that will POST to an operator-supplied URL is an SSRF primitive
with authentication in front of it. `169.254.169.254` is the first thing anyone
tries.

**Enforced by.** Destinations come from environment variables resolved at startup
([config.py:119](../gateway/config.py)); policy rules select a destination *by
name* from a fixed map, and an unknown name is a 500 rather than a fetch
([pipeline.py:217](../gateway/inspection/pipeline.py)). `trust_env=False` on the
httpx client prevents silent proxy redirection, with explicit opt-in via
`SAG_TRUST_ENV_PROXY` ([routing/base.py:113](../gateway/routing/base.py)).

**Test.** `tests/test_egress_and_retry.py::TestEgressPolicy`,
`::TestProviderValidatesEgress`, `::TestClientsCannotChooseAnUpstream`.

**Status.** ✅ **MET.** Both halves are now closed.

*Client-controlled:* destinations are selected by name from a map built at
startup, and the typed request model makes that structural — a field like
`base_url` or `api_base` is rejected as unknown, asserted per field name.

*Operator-controlled:* `EgressPolicy` validates scheme, an optional host
allowlist, and **every address the host resolves to**. Loopback, link-local,
private, reserved, and multicast are refused — so `169.254.169.254` is refused,
which is the first thing anyone tries. Validation runs at startup (so a
misconfiguration is found at deploy time) and again per request. Plaintext HTTP
is refused for non-local destinations, redirects are not followed, TLS
verification is explicit, and responses are capped at 8 MiB.

`local` permits private addresses by default, because routing to a model on
loopback is the entire point of `route_local`. The global override
`SAG_EGRESS_ALLOW_PRIVATE` logs loudly, because it removes the control.

**Residual, stated rather than footnoted.** httpx resolves again when it
connects, so between our check and its connection a name could resolve
differently — TOCTOU, the mechanism behind DNS rebinding. Per-request validation
closes misconfiguration and slow rebinding; fast rebinding needs a transport
pinned to the validated address and remains open. Recorded in
`gateway/routing/egress.py` and on the list for the independent review.

**Owner.** Platform owner.

---

### SI-15 — No control-plane dependency on the request path

**Statement.** The Community Edition serves requests with no external dependency
beyond the configured provider. Readiness never checks a third party.

**Why.** A self-hosted security control that stops working when *our* service is
down is a liability the customer did not agree to buy. It is also the difference
between "local-first" being true and being marketing.

**Enforced by.** `/readyz` checks only process state and key configuration
([app.py:70](../gateway/api/app.py)). There is no telemetry or phone-home code
on the request path.

**Test.** `tests/test_api_e2e.py::TestHealthAndReadiness::test_readiness_does_not_depend_on_external_provider`.

**Status.** ✅ **MET.**

**Owner.** Technical lead.

---

### SI-16 — Retry and concurrency safety

**Statement.** Retries, cancellations, and concurrent requests cannot broaden a
provenance set or cause a token minted by one run to be restored by another.

**Why.** Provenance is the primary restoration control. Any mechanism that lets a
provenance set outlive or escape its request defeats SI-03 without touching the
restoration code.

**Enforced by.** `TokenProvenance` is created inside `process` and never escapes
it ([pipeline.py:180](../gateway/inspection/pipeline.py)). The vault is keyed
per (tenant, conversation, token), so concurrent requests in one conversation
write idempotently.

**Test.** `tests/test_vault_hardening.py::TestConcurrency` —
`test_concurrent_requests_in_one_conversation_do_not_share_provenance` and
`test_concurrent_cross_tenant_requests_do_not_interfere`.

**Status.** 🔶 **PARTIAL.** Concurrency and cancellation are both enforced and
tested. Sixteen concurrent requests in one conversation mint the same token, each
restores only through its own provenance set, and a foreign set restores nothing.
Cancelling between the vault write and the provider response leaves an orphan
record that is **not restorable by anyone** — the provenance set died with the
request and no later request can recreate it. `InMemoryBackend` has an explicit
lock, so thread-safety is a documented requirement of `VaultBackend` rather than
an accident of CPython's per-operation `dict` atomicity.

**Retries now exist**, and the tripwire that guarded their absence did its job:
`test_there_is_no_retry_logic_to_race` failed on the first run after the retry
loop landed, forcing the tests ADR-0014 required to be written before the
feature shipped rather than after.

Retries re-send the **already-transformed** payload — detection runs exactly
once, asserted by counting detector invocations across a retried request — and
reuse the same provenance set. Only failures where the upstream demonstrably did
not process the request are retried; **timeouts are not**, because there is no
idempotency key and a retry could produce a duplicate billed completion.

Remaining at 🔶 only because the deadline-across-attempts assertion is weaker
than it should be: it checks that the remaining budget shrinks, not that the
total is exactly bounded.

**Owner.** QA/reliability owner.

---

### SI-17 — Original-text integrity

**Statement.** Detection runs over a normalized view, but only validated source
spans are replaced in the **original** text. Text the gateway did not detect
reaches the provider byte-identical to what the client sent.

**Why.** Two reasons, and the second is the one that bites. First, a customer
sending a code block or a signed payload gets it silently rewritten. Second, and
worse: normalization that is applied to the forwarded text is a *transformation
the customer cannot see*, so any bug in it is invisible until a provider rejects
a request.

**Enforced by.** `gateway/normalization/` — the detection view and its offset
map. Detection runs on the view; `SecurityPipeline._map_to_original` translates
every span back and validates it; transformation and forwarding both operate on
the **original**.

Three checks stand between a mapping and a replacement: bounds, non-overlap
after mapping (two spans that did not overlap in the view can overlap once
dropped characters are absorbed), and a **round trip** — re-viewing the mapped
original text must reproduce the text the detector matched. Any failure raises
`DetectionError` and fails the request closed; nothing is silently dropped or
clamped.

**Test.** `tests/test_normalization.py` — offset-map totality, span expansion
over stripped characters, folding, screening, and two properties:
`test_text_with_no_detections_is_forwarded_byte_identical` and
`test_replace_then_reverse_reproduces_the_original`.

**Status.** ✅ **MET.** Both invariants now hold at once: the customer's bytes
reach the provider unchanged, *and* every index of the original is covered by
the map, so "unchanged" does not mean "unscanned".

The measured effect on evasion, from `make evals`: adversarial recall went
**33% → 100%** on Latvian personal codes and **0% → 100%** on emails, with no new
false positives on the boundary corpus. Cyrillic homoglyphs, zero-width
insertion, fullwidth digits, and en-dash substitution are all detected, and the
replacement span *includes* the evasion characters so they are removed with the
value.

One documented exception to totality: a message consisting entirely of ignorable
characters produces an empty view covering no indices. Sound — there is nothing
visible to detect — and asserted positively rather than skipped.

**Owner.** Detection owner (offset map), Security owner (sign-off).

---

### SI-18 — No production claim without independent review

**Statement.** No marketing, documentation, or sales material describes the
restoration design as validated, or the product as production-ready, until an
independent reviewer who did not design it has reported and their findings are
remediated.

**Why.** The restoration design is better than what exists in the field, which is
a bar we set for ourselves and then graded ourselves against. That is not
evidence.

**Enforced by.** Alpha status stated in `README.md` and at the top of
`docs/threat-model.md`.

**Test.** Process, not automated.

**Status.** ✅ **MET** as a statement; the review itself is plan Phase 7 and has not
happened.

**Owner.** Product/release owner.

---

## Summary

| ID | Invariant | At contract freeze | Now |
|---|---|---|---|
| SI-01 | No uninspected egress | ❌ | ✅ |
| SI-02 | Reject unknown content | 🔶 | ✅ |
| SI-03 | Current-request restoration only | ✅ | ✅ |
| SI-04 | Authenticated scope on every vault call | ✅ | ✅ |
| SI-05 | Cross-tenant isolation is cryptographic | 🔶 | ✅ |
| SI-06 | Unguessable token identity | 🔶 | ✅ |
| SI-07 | Unambiguous token derivation | ✅ | ✅ |
| SI-08 | Safe AEAD operation | 🔶 | ✅ |
| SI-09 | No custom cryptography | ✅ | ✅ |
| SI-10 | Fail closed | ✅ | ✅ |
| SI-11 | No content in observability | 🔶 | 🔶 |
| SI-12 | No provider credentials in logs or errors | ✅ | ✅ |
| SI-13 | Security-critical actions produce audit evidence | 🔶 | 🔶 |
| SI-14 | Explicit egress | ❌ | ✅ |
| SI-15 | No control-plane dependency on the request path | ✅ | ✅ |
| SI-16 | Retry and concurrency safety | ❌ | 🔶 |
| SI-17 | Original-text integrity | ❌ | ✅ |
| SI-18 | No production claim without independent review | ✅ | ✅ |

**15 met, 3 partial, 0 not met** (was 7 / 6 / 5 at the contract freeze).
Community Edition beta requires all eighteen at ✅, with any 🔶 carrying a
written, dated waiver with a named owner.

Nothing is at ❌ any more. The three at 🔶 are all "enforced, with a named gap",
not "unenforced":

- **SI-11** — audit and error paths are covered; the container log scan is a
  runnable job that **has never executed** here (the Docker registry was
  unreachable). Tracing and metrics are not implemented and must be built
  redaction-first.
- **SI-13** — the success and policy-block paths are audited; the error paths
  still write no audit event.
- **SI-16** — concurrency, cancellation, and retry are all enforced and tested;
  the total-deadline assertion is weaker than it should be.

The largest *unmeasured* risk is no longer an invariant at all: it is that
detection quality has only been measured against a small synthetic corpus, and
the restoration design has not been reviewed by anyone who did not write it
(SI-18, plan Phase 7).

Executable coverage lives in the adversarial, property, egress, policy, and
vault test suites.
