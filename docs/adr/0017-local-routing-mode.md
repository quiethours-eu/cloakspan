# ADR-0017: Local routing mode (GDPR mode) as a routing floor after policy composition

**Status:** PROPOSED · 2026-09-22 · `REQUIRES_SECURITY_REVIEW`
**Invariants:** [SI-01](../security-invariants.md#si-01--no-uninspected-egress),
[SI-10](../security-invariants.md#si-10--fail-closed),
[SI-13](../security-invariants.md#si-13--security-critical-actions-produce-audit-evidence),
[SI-14](../security-invariants.md#si-14--explicit-egress),
[SI-18](../security-invariants.md#si-18--no-production-claim-without-independent-review)

## Context

Some deployments work under a flat rule: a request that contains personal data
is answered by a model the operator runs, and the third-party provider never
receives it, not even as tokens. The README calls this GDPR mode.

PR #12 expressed the rule as a policy file, `deployment/policies/auto-local.yaml`,
selected with `SAG_POLICY_PATH`. It listed fourteen entity types in one
`route_local` rule at priority 90 and sent everything else to `external` through
a catch-all. Review showed that a policy file cannot hold this rule. Each case
below sent a request with detected or detectable personal data to `external`,
and each was reproduced against the real pipeline:

1. **No NER model.** Without `SAG_NER_MODEL_PATH`, names, organisations, places
   and street addresses are not detected, so a prompt whose only personal detail
   is a name looked clean. Nothing stopped the preset from running that way.
2. **Legacy patterns.** A type from `SAG_CUSTOM_PATTERNS`, such as
   `EMPLOYEE_ID`, had no rule in the list and fell to the catch-all.
3. **Conflict resolution.** When spans overlap, the higher-scoring one wins
   ([entity taxonomy](../entity-taxonomy.md#conflict-resolution)). A custom type
   that swallows a listed one, such as `HOST=` followed by an IP address, or
   `Case Smith` over a NER `PERSON`, leaves only the unlisted type.
4. **Composition overrides.** A filter from `SAG_FILTERS_PATH` naming
   `destination: external` at priority 95, or at 90 with a name that wins the
   alphabetical tie; a filter reusing the `EMAIL_ADDRESS` label; an
   application-scoped allow rule at priority 999. Each outranks or ties the
   preset's rule.
5. **Loader leniency.** A typo such as `mach:` for `match:` turns an operator's
   rule into a catch-all. In a policy whose `default_destination` is
   `external`, such as `default.yaml`, a `route_local` rule with no destination
   goes to `external`. A `min_score` hides lower-scoring spans from a rule.
6. **`local` was only a name.** In development an unset `SAG_LOCAL_BASE_URL`
   made `local` the offline mock. When set, it could point at any host, public
   ones included, over plain http, and through an ambient proxy when
   `SAG_TRUST_ENV_PROXY` was on.
7. **Packaging.** The file was not in the wheel, so a `pip install` had no way
   to select it.

One more gap sits outside the preset. `SecurityPipeline.inspect_payload` reads
only the `role` and `content` of each message, and `_build_outbound` copies the
request it is given. A message whose role was not in `INSPECTED_INPUT_ROLES` was
skipped and still forwarded, and so was every field inspection never reads:
message fields such as `name` and `tool_calls`, top-level fields such as `user`,
`metadata` and `tools`, and free text in an accepted field such as
`service_tier`. The HTTP API already refused all of these with 422, so only
direct library callers were exposed, but under this mode each would be a way to
reach a provider with uninspected text: under `detected`, a request whose
`content` is clean goes to `external`.

## Decision

### 1 · A mode, not a file

One variable, `SAG_LOCAL_ROUTING`, with three values:

| Value | Effect |
|---|---|
| `off` (default; unset or empty means the same) | The composed policy decides, exactly as before |
| `detected` | A request in which any detector found anything goes only to `local`, pseudonymised |
| `all` | Every request that is not blocked goes only to `local`. The external client is never built |

The value is trimmed and lower-cased, and anything else stops startup with
`SAG_LOCAL_ROUTING must be one of: off, detected, all`. This is stricter than
the boolean settings in `gateway/config.py` on purpose: `on`, `true` or `gdpr`
must not quietly read as off. The name describes what the setting does, so it
does not read as a compliance switch.

### 2 · Any span, no entity list

`apply_local_routing(mode, decision, inspection)` in
`gateway/policy/local_routing.py` is a pure, total function. It returns the
decision unchanged when the action is `block`, when the destination is exactly
`local`, or when the mode does not require local for this inspection. Otherwise
it returns a `route_local` decision to `local`, with rule name
`local-routing:<mode>` and every detected entity type as the matched entities.

Under `detected`, one inspected span is enough: any entity type, any score, any
detector, including NER, filters, `SAG_DICTIONARY_TERMS`, `SAG_CUSTOM_PATTERNS`,
and whichever span won conflict resolution. Under `all`, every request
qualifies. The function never looks at entity names, rule order or
`min_score`, which is what closes cases 1 to 5 above. The destination check is
an exact string comparison, so `external`, `mock`, an empty destination and
`Local` are all rewritten.

### 3 · Applied after the policy is composed

`PolicyEngine.with_local_routing(mode)` works like `with_rules`. `build_pipeline`
calls it after the YAML policy and the `SAG_FILTERS_PATH` rules are composed, so
no rule, filter or legacy pattern can be added after it. With the mode on, every
decision's policy version ends in `+local-routing:<mode>`, blocks included. A
later `with_rules` keeps the mode, and applying a mode twice raises
`PolicyError`.

`required_destinations` becomes mode-aware: the policy's own set for `off`, that
set plus `local` for `detected`, and only `local` for `all`. The existing
production check that refuses a mock-backed destination uses this set, so
`all` in production needs only `SAG_LOCAL_BASE_URL`.

### 4 · `detected` requires NER; `all` does not depend on detection

`detected` without a detector named `ner` refuses to start in every
environment. The error names `SAG_NER_MODEL_PATH` and suggests
`SAG_LOCAL_ROUTING=all`. The startup line reports the model's manifest
languages; they are not checked against the traffic.

`all` works without NER because it does not consult detection to choose the
destination.

### 5 · `local` is a place on your own network

With the mode on, `SAG_LOCAL_BASE_URL` is required in every environment, so the
mock is never the local destination. Every address the host resolves to must be
in this list:

| Range | What it is |
|---|---|
| `127.0.0.0/8`, `::1/128` | Loopback |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC 1918 private networks |
| `100.64.0.0/10` | RFC 6598 shared address space, which Tailscale uses |
| `fc00::/7` | IPv6 unique local addresses |

IPv4-mapped IPv6 addresses are unwrapped before the check. Everything else is
refused, including link-local (so `169.254.169.254`), unspecified, multicast,
reserved, NAT64 and 6to4 addresses, public addresses, and a name that resolves
to a mix of private and public addresses. The check runs when the provider is
built and again before every request. Plain http stays allowed, because a
self-hosted model on the same host or LAN usually has no TLS. While the mode is
on, the local provider never uses ambient proxy settings, whatever
`SAG_TRUST_ENV_PROXY` says. That setting also lets httpx read a CA bundle from
`SSL_CERT_FILE` or `SSL_CERT_DIR`; the local provider keeps that part, so an
https model behind an internal CA still verifies.

The list is explicit rather than built on `ipaddress`. Treating "not
`is_global`" as private would admit `169.254.169.254`, CPython revised these
tables in 2024 (CVE-2024-4032), and the repository's `_is_globally_routable`
returns true for `100.64.0.10` on Python 3.13 and 3.14, so it would refuse a
model reached over Tailscale.

### 6 · `all` never builds the external client

Under `all`, no `external` provider exists, not even a mock alias, and
`SAG_EXTERNAL_BASE_URL`, `SAG_EXTERNAL_API_KEY` and `SAG_EXTERNAL_MODEL` are
ignored. A regression that selected `external` would hit the existing
unknown-destination error (500) rather than a client.

### 7 · A provider-identity tripwire

Just before the provider call, `SecurityPipeline.process` checks that under
`all`, or under `detected` when anything was detected, the provider object it
is about to use is `providers["local"]`. If not, it raises
`LocalRoutingViolation`, the API returns 500 through its generic handler, and
nothing is sent. This lives in a different module from the engine and tests a
different thing: the object that is about to receive the request, not the
predicate that chose it. It reads the mode and the entity counts itself rather
than calling `LocalRouting.requires_local`, so the two checks share no function.
It is unreachable unless the engine's rewrite or that predicate regresses, so
both are tested by fault injection.

### 8 · Uninspected roles and fields are refused

`inspect_payload` raises `DetectionError`, instead of skipping and forwarding,
for a message whose role it does not inspect, for a message field other than
`role` and `content`, and for a top-level field that `ChatCompletionRequest`
does not accept or a value of a type it does not accept. The top-level check,
`accepts_request_fields` in `gateway/api/schema.py`, is built from that model's
fields and types, so the two cannot drift apart. The errors name at most the
message index, never the role, the field or the content. This applies in every
mode. The HTTP API already returned 422 for all of these, so only direct
library callers see a change.

### 9 · Pseudonymisation is unchanged, and local decisions keep their action

A request the mode moves goes through the existing `route_local` path: every
detected span in every inspected message is replaced with a token before the
local model sees it, and tokens in the reply are restored. TB3 in the threat
model and the leakage eval that local routing is not a licence to send raw
identifiers both stay as they are.

A decision that already goes to `local` is left alone. The default policy's
`baltic-ids-local-only` keeps its rule name, and an operator's explicit `allow`
rule to `local` still forwards the original text to their own model. The mode
changes destinations. It never lifts a block.

### Observability

No new variable, header or audit field. `X-Policy-Version` and the audit
`policy_version` end in `+local-routing:<mode>`. `X-Policy-Rule` and the audit
`rule_name` read `local-routing:<mode>` when the mode moved a request, and the
audit `destination` and `provider` record where it went. `AUDIT_SCHEMA_VERSION`
stays 3. With the mode on, one INFO line at startup gives the mode, the policy
version, the NER model, and the local and external hostnames, so an operator can
see that the mode is actually on.

## Required tests

1. Parsing: unset, empty and `off` give off; `detected` and `all` parse in any
   case with surrounding spaces; `on`, `true`, `1`, `yes`, `gdpr`, `local`,
   `strict` and `detect` stop startup.
2. Decision table at engine level: off is identical to the uncomposed engine;
   a block is never weakened; any span under `detected` moves every non-local
   destination; a clean request under `detected` is left to the policy; `all`
   moves every non-block decision; a local decision keeps its rule and action;
   the version suffix is on every decision; `required_destinations` per mode.
3. A property test over random entity labels, scores (NaN included) and
   applications against adversarial policies (application-scoped allow at 999,
   `route_local` with no destination, `min_score`, name ties, filter-shaped
   overrides, a typo'd `mach` key): with any span under `detected`, and always
   under `all`, the result is `block` or `local`.
4. Startup: `detected` without NER refuses in development and production; the
   mode without `SAG_LOCAL_BASE_URL` refuses even in development; `all` builds
   no `external`; the local provider ignores proxies but keeps a CA bundle from
   `SSL_CERT_FILE`; a public local address is refused at startup; the summary
   line appears only with the mode on and holds no URL path, userinfo or key.
5. Egress: each accepted and refused address class in section 5, a mixed
   resolution, and a re-check per request that sends nothing once the name
   starts resolving to a public address.
6. Leakage evals through `build_pipeline` for every case in the Context, each
   asserting the external provider received nothing and the local provider
   received tokens rather than values. Plus: a clean request still reaches
   external unchanged under `detected`; a local failure is not retried
   externally; a detector failure reaches no provider; the tripwire fails
   closed when the engine rewrite, or `requires_local`, is patched out; the
   audit event of a moved request records `local` and the suffixed version.
7. The refusal of uninspected roles and fields on the library path, with
   nothing forwarded.

## Alternatives considered

| Option | Rejected because |
|---|---|
| The enumerated preset file (PR #12) | Every case in the Context. A list of types drifts from the detectors, and a file-selected mode cannot require NER or a real local endpoint |
| A second policy schema with an `any_entity` match and statically verified constraints | Closes the same cases, but adds a second policy front end and a verifier that must mirror the engine's ordering forever. It refuses some existing filter setups and does nothing for operators who keep their own policy |
| Enforcement in the pipeline only | `build_pipeline` would have to recompute required destinations beside the engine, and the enforcement and the tripwire would share one function |
| `ipaddress.is_global`, or `_is_globally_routable`, to define private | See section 5: one admits link-local, the other refuses Tailscale |
| An operator list of public hosts allowed as `local` | Lets a cloud API pass as local, which is the path this mode exists to close |
| Sending original values to the local model | Changes TB3, SI-01 semantics and the existing leakage eval. It would need its own ADR |
| A mock `local` in development while the mode is on | With no URLs set, `local`, `external` and `mock` are one object, so the tripwire and the address check mean nothing |
| Naming the variable `SAG_GDPR_MODE` | Reads like a compliance switch |

## Consequences

**Security.** SI-01 is strengthened on the library path (uninspected roles and
fields are refused) and, under `detected`, for every detected request. SI-14 gains a
private-network requirement and a proxy ban for the local destination. No
invariant is waived. `docs/security-invariants.md` is frozen for v1, so this ADR
carries the evidence. Two gaps stay open and are stated here rather than
closed: detectors still have no timeout (SI-10, R-03), so a hung detector holds
the request and nothing is forwarded until it returns; and failed requests (a
local provider error, a per-request egress refusal, the tripwire) still write no
audit event (SI-13).

**Operators.** Any detection moves a request, with no per-type exemptions. With
NER on, ordinary `ORG` or `LOCATION` hits go local, and a system prompt that
contains a support email address sends every request local. The image ships
neither the NER runtime (the `[ner]` extra) nor a model, so of the two modes
only `all` starts in it; `detected` needs an installation with that extra and a
model the operator supplies. A real local URL is needed even in development. A
self-hosted model on a public address is refused and needs a VPN or Tailscale
in front of it. `100.64.0.0/10` also covers carrier-grade NAT space: the check
sees addresses, not who owns them. The local model receives tokens rather than
values, which can affect answer quality. A local failure returns 502 or 504 (or
the upstream 4xx) and is never retried against `external`. Compose still asks for `SAG_EXTERNAL_BASE_URL` under `all`,
although the gateway never builds that client. The rule the mode replaced is
recorded only in the decision's `reason`, which is not audited; recovering it
means replaying the versioned policy.

**Detection bound.** `detected` is only as good as detection. Personal data no
detector finds still reaches the external provider in clear. Only `all` is
independent of detection. Recorded as T19 in the threat model.

**Existing users.** With the mode off, the policy object, version, provider map,
build order and logs are unchanged. The one behaviour change is that library
callers now get `DetectionError` for uninspected roles and fields.
`deployment/policies/auto-local.yaml` is removed; it was never released, and
pointing `SAG_POLICY_PATH` at it now fails at startup.

**Sales.** The mode is described as routing and pseudonymisation. It is never
called anonymisation, and no material may say that turning it on makes a
deployment GDPR compliant. The Sales consequence of
[ADR-0016](0016-equality-leakage-of-deterministic-pseudonyms.md) applies
unchanged.

**Review.** Named for the Phase 7 reviewer under SI-18: the private range list,
the placement of the routing floor, and whether a tripwire that can only fire on
a regression earns its place.

## Open questions for the independent reviewer

> Should the local destination require https for private addresses that are not
> loopback? It is safer on a shared LAN and breaks a plain Ollama on another
> machine.

> `NerDetector` drops a span with out-of-bounds offsets and logs a warning.
> Under `detected`, a misbehaving backend could therefore leave a name
> undetected without failing the request. Should it raise instead?
