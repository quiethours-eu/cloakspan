# Operations

Deployment, upgrade, rollback, backup, and troubleshooting for the Community
Edition. Written for the person on call at 02:00 who did not build this.

**Scope:** self-hosted, single node, Docker. Multi-tenant hosted operation is a
separate program and is not covered here.

---

## Before you deploy

| | |
|---|---|
| Generate keys | `openssl rand -hex 32` — twice, for `SAG_VAULT_KEY` and `SAG_TOKEN_KEY`. Do **not** set them to the same value; they are derived apart, but reusing one root secret defeats the point |
| Set `SAG_ENVIRONMENT=production` | Turns "ephemeral key" from a warning into a startup failure. A warning nobody reads is not a control |
| Set `SAG_API_KEYS` | `key:tenant:application`, comma-separated. The tenant becomes the vault scope |
| Point `SAG_EXTERNAL_BASE_URL` at your provider | Must be `https` and must resolve to a public address; the gateway refuses private and link-local destinations |
| Consider `SAG_EGRESS_ALLOWLIST` | Pins egress to your approved providers. Empty means any public host |
| Decide on `SAG_LOCAL_ROUTING` | `off` by default. `detected` sends every request with a detection that is not blocked to your own model, and needs `SAG_NER_MODEL_PATH` and the `[ner]` extra, which the container image does not include; `all` sends every request that is not blocked there. See [GDPR mode](configuration.md#gdpr-mode-sag_local_routing) |
| Point `SAG_LOCAL_BASE_URL` at your own model | Required when `SAG_LOCAL_ROUTING` is on, in every environment. It must resolve only to loopback or private-network addresses (Tailscale's `100.64.0.0/10` included), and it is checked again on every request |
| Decide the retention window | `SAG_VAULT_TTL_SECONDS` is a **privacy control**, not a cache size. It is how long surrogate mappings — the only place real personal data is written outside process memory — survive |

Verify before taking traffic:

```bash
curl -fsS http://127.0.0.1:8080/readyz
```

`/readyz` deliberately does not check your provider. It answers "can this
gateway serve?", not "is OpenAI up?" — so a provider outage does not take your
locally-routed and blocked requests down with it.

---

## Deploying

```bash
docker compose up -d
```

The image runs as uid 10001 with a read-only root filesystem and all
capabilities dropped. If your platform requires you to relax any of that, treat
it as a change worth reviewing rather than a configuration detail — those
properties are asserted by `make test-container`.

---

## Upgrading

The vault is in-memory by default, so an upgrade **loses every live surrogate
mapping**. That is not a data-loss event — nothing durable is lost — but it has
a visible symptom, so know it before the tickets arrive.

1. Announce a short window. Conversations in flight will be affected.
2. `docker compose pull && docker compose up -d`
3. Watch `/readyz` until it returns 200.
4. Expect a spike in `tokens_refused` with reason `vault_miss` for up to one
   TTL. See *A spike in refused tokens* below.

**Rollback** is the same operation with the previous tag:

```bash
docker compose down
docker run ... secure-ai-gateway:<previous-version>
```

There is no schema migration to reverse, because there is no persistent schema.
That is a deliberate property of the Community Edition and the reason rollback
is cheap here and will not be in the hosted edition.

Before releasing a new version, the upgrade and rollback must have been
*performed* from the previous release candidate, not
merely described. **That has not been done for any version yet.**

---

## Backup and restore

**There is nothing to back up in the Community Edition, by design.**

| Data | Where | Backup |
|---|---|---|
| Surrogate mappings | Process memory, TTL-bounded | None. Short-lived by design; backing them up would create a durable copy of exactly the data the product exists to protect |
| Audit events | stdout | Your log pipeline. Contains no prompt content |
| Policy | `deployment/policies/default.yaml` | Version control |
| Keys | Your secret manager | **Back these up.** Losing `SAG_VAULT_KEY` makes every live mapping unrestorable |

If you configure a file-backed vault, personal data is now at rest on disk and
everything in `docs/data-retention.md` applies to your backups too.

---

## Rotating keys

Additive, with no downtime and no re-encryption pass, because records are
short-lived:

```bash
SAG_VAULT_KEY_V1=<old>
SAG_VAULT_KEY_V2=<new>
SAG_VAULT_ACTIVE_KEY_VERSION=2
```

Restart. New records are written under v2; existing records keep decrypting
under v1 until their TTL elapses. Remove v1 after one TTL plus a margin.

Removing a key that is **still in use** raises `VaultKeyUnavailableError` rather
than silently failing to restore — which is the specific failure the record
envelope exists to make visible. See
[ADR-0012](adr/0012-vault-record-envelope-and-key-rotation.md).

Rotating `SAG_TOKEN_KEY` invalidates every token immediately, in every live
conversation. Only do it on suspected key compromise, and expect user-visible
breakage.

---

## Troubleshooting

### The gateway refuses to start

| Message | Cause |
|---|---|
| `SAG_VAULT_KEY is not set and SAG_ENVIRONMENT is production` | Working as intended. Set a real key |
| `must be at least 32 bytes` | The secret is too short. Not truncated or padded, because that would hide the problem |
| `destination 'external': ... resolves to ..., which is loopback, link-local, private, or reserved` | Your provider URL points inside the network. If deliberate, use the `local` destination; if not, this just caught an SSRF footgun |
| `plaintext http is not permitted for a non-local destination` | Prompts would cross the network in clear |
| `SAG_NER_MODEL_PATH is set to ..., which is not a directory` | NER is enabled but unavailable. Deliberately fatal: running without it means you believe PERSON is being caught while it is not |
| `SAG_LOCAL_ROUTING must be one of: off, detected, all` | A typo or a value such as `on` or `true`. It is refused rather than read as `off` |
| `SAG_LOCAL_ROUTING=<mode> needs SAG_LOCAL_BASE_URL` | The mode is on and there is no local model. The offline mock is not accepted in its place, even in development |
| `SAG_LOCAL_ROUTING=detected needs an NER model` | Set `SAG_NER_MODEL_PATH`, or use `SAG_LOCAL_ROUTING=all`, which does not depend on detection |
| `NER is enabled but spaCy is not installed` | The `[ner]` extra is not installed. The container image does not include it, so run `detected` from an installation that has it, or use `SAG_LOCAL_ROUTING=all` |
| `destination 'local': ... is not loopback or a private network` | With the mode on, the local host resolved to a public, link-local, or otherwise unlisted address. Reach the model over a private network or Tailscale instead |

### A spike in refused tokens

Check `tokens_refused_by_reason` in the audit event before assuming an attack:

| Reason | Meaning |
|---|---|
| `vault_miss` | The token was minted by this request but the vault has no value — usually a restart or an elapsed TTL. **This is what a deploy looks like** |
| `not_minted` | The token was not minted by this request. Attacker-supplied, hallucinated, or replayed from an earlier turn. A sustained rate is worth investigating |
| `cross_tenant` | Should be **exactly zero**. Any occurrence is an incident |
| `key_unavailable` | A configured key was removed while still in use. Configuration error, not an attack |

Without that breakdown a deploy and an attack produce the same signal, which is
why alerts should be written against the reasons and not the total.

### Requests are rejected with 422

The gateway rejects what it cannot inspect. Check `error.code`:

| Code | Meaning |
|---|---|
| `unknown_field` | A field we do not recognise. Reject-unknown is the contract — including for newer OpenAI features |
| `uninspectable_field` | A field we recognise and refuse: `tools`, `response_format`, message `name` |
| `unsupported_role` | A role outside `system`/`user`/`assistant`/`tool` |
| `inspection_failed` | Non-string content, or a detector failed |
| `suspicious_encoding_bidi` | Bidirectional controls — the Trojan Source class |
| `suspicious_encoding_invisible` | Dense invisible padding |

### Checking that GDPR mode is on

With `SAG_LOCAL_ROUTING` set to `detected` or `all`, the gateway logs one INFO
line at startup on the `gateway.config` logger. It gives the mode, the policy
version, the NER model, and the local and external hostnames. If
`SAG_LOG_LEVEL` is `INFO` and that line is missing, the mode is off.

In the audit stream:

| Field | What it tells you |
|---|---|
| `policy_version` | Ends in `+local-routing:detected` or `+local-routing:all` for every request handled while the mode was on, blocked requests included |
| `rule_name` | `local-routing:<mode>` when the mode overrode the policy's destination. Any other rule name means the policy's own decision stood |
| `destination` | Where the request was routed. `local` for everything the mode moved |

Successful responses carry the same values as `X-Policy-Version` and
`X-Policy-Rule`. Blocked (403) and failed responses carry neither, so check
blocked requests in the audit stream.

A check for a DPO: under `all`, no request should have gone anywhere but
`local`, and under `detected`, no request with a detection should have. This
must print nothing:

```bash
docker compose logs --no-log-prefix gateway \
  | jq -cR 'fromjson? | objects | select(has("schema_version"))
      | select(.provider != "none" and .destination != "local")
      | select((.policy_version | endswith("+local-routing:all"))
          or ((.policy_version | endswith("+local-routing:detected"))
              and (.entity_counts | length > 0)))'
```

Events with `provider` `none` are excluded because nothing was handed to any
provider's client: blocked requests, every request refused or failed before
that, and a request whose destination failed its request-time egress check. A
blocked event still carries a destination, usually the policy's
`default_destination`, although nothing was sent. A request that failed after
it was handed to a provider's client, for example because the local model was
down, has an event naming that provider with an `error` reason code, so it
appears here if that provider was not `local`.

### Latency is higher than expected

Run `make benchmark` on the same documented hardware used for the baseline. The
detection path is single-digit-to-low-double-digit milliseconds; if the total is
much larger, the time is in the provider call, not here.

---

## What to alert on

Each signal is in the audit stream; those with a metric name are also on
`GET /metrics` when it is enabled (see [Limits and metrics](#limits-and-metrics)).

| Signal | Metric | Threshold | Why |
|---|---|---|---|
| `CrossTenantAccessError` | — | **any** | Should be structurally impossible. Page |
| `tokens_refused_by_reason.cross_tenant` | `cloakspan_tokens_refused_total{reason="cross_tenant"}` | **any** | Same |
| `tokens_refused_by_reason.key_unavailable` | `cloakspan_tokens_refused_total{reason="key_unavailable"}` | any | A key in use was removed |
| `tokens_refused_by_reason.not_minted` | `cloakspan_tokens_refused_total{reason="not_minted"}` | sustained rate | Token probing |
| `encoding_signals.suspicious_encoding_bidi` | `cloakspan_request_refusals_total{reason="suspicious_encoding_bidi"}` counts refused requests | sustained rate | Deliberate deception attempts |
| HTTP 422 rate | `cloakspan_request_refusals_total` with `reason` `unknown_field`, `uninspectable_field`, `unsupported_role`, `invalid_message`, `inspection_failed` | step change | Usually a client upgrade meeting reject-unknown, not an attack |
| `error` = `detector_timeout` | `cloakspan_request_refusals_total{reason="detector_timeout"}` | sustained rate | Inputs inspection cannot finish in time, or a saturated instance |
| — | `cloakspan_detector_overruns_in_flight` | above zero for minutes | Detector threads still running after their request was refused; each holds a slot |
| `error` = `capacity_exceeded` | `cloakspan_request_refusals_total{reason="capacity_exceeded"}` | sustained rate | The instance is full. Add instances, or find what holds slots |
| `error` = `rate_limit_exceeded` | `cloakspan_request_refusals_total{reason="rate_limit_exceeded"}` | sustained rate | A key is over its allowance. The audit event names the key id |
| `error` = `provider_timeout`, `provider_unavailable`, `provider_error`, `provider_bad_response` | `cloakspan_request_refusals_total{reason=...}` | step change | The upstream model is failing, not the gateway |
| `error` = `egress_blocked`, `local_routing_violation` | `cloakspan_request_refusals_total{reason=...}` | **any** | A destination failed a request-time check. Nothing was sent |
| `/readyz` non-200 | — | 2 consecutive | |

Do **not** alert on `tokens_refused` in total. It spikes on every deploy, and an
alert that cries wolf at each release is an alert that gets muted.

---

## Limits and metrics

These apply to `POST /v1/chat/completions`. `/healthz`, `/readyz`, `/metrics`,
`GET /v1/models` and `DELETE /v1/conversations/{id}` are not rate limited and
do not count against capacity; leaving deletion unthrottled keeps the erasure
runbook below usable under load. The experimental agent endpoints keep their
own limits (`SAG_AGENT_*`, below).

Checks run in this order: authentication, rate limit, concurrency cap, body
size and body deadline, request contract, inspection, provider.

| Limit | Setting | Refusal |
|---|---|---|
| Requests per minute per API key | `SAG_RATE_LIMIT_PER_MINUTE`, default `600`; `0` turns it off | 429 `rate_limit_exceeded`, `Retry-After` in whole seconds |
| Requests in flight, all keys together | `SAG_MAX_CONCURRENT_REQUESTS`, default `64` | 503 `capacity_exceeded`, `Retry-After: 1`, immediately; nothing queues, and the key's rate-limit allowance is not spent |
| Request body size | `SAG_MAX_REQUEST_BYTES`, default `1048576` | 413 `request_too_large` |
| Request body arrival | `SAG_REQUEST_BODY_TIMEOUT_SECONDS`, default `15` | 408 `request_timeout` |
| Inspection time | `SAG_DETECTOR_TIMEOUT_SECONDS`, default `15` | 503 `detector_timeout`, no `Retry-After`; nothing is forwarded |
| Provider time, across retries | `SAG_REQUEST_TIMEOUT_SECONDS` | 504 `upstream_error` (audit reason `provider_timeout`) |

What these are, plainly:

- **Per process, single node.** The container runs one Uvicorn process. Two
  replicas each allow the full rate and the full concurrency. Nothing is
  shared, and every count resets on restart.
- **The rate limit is per API key, not per client address.** Unauthenticated
  requests are refused with 401 before the rate limit and are not themselves
  rate limited. Each still writes an audit event, so a flood of bad keys is a
  flood of audit lines. Rate-limit unauthenticated traffic at the reverse
  proxy.
- **The concurrency cap is global.** There is no per-key share: one key with
  slow requests can hold every slot, each for up to the provider deadline, and
  every other key then gets `capacity_exceeded`. A request refused for
  capacity does not spend its key's rate-limit allowance.
- **The rate limit is a token bucket** holding one minute's allowance, so an
  idle key may send that many at once. The concurrency cap, not the rate limit,
  bounds how many run together.
- **A detector cannot be interrupted.** Inspection runs in a worker thread. On
  timeout the request is refused and nothing is forwarded, but the thread runs
  on until the detector returns and keeps its concurrency slot until then
  (`cloakspan_detector_overruns_in_flight`). Resubmitting a pathological input
  therefore fills the cap and then meets `capacity_exceeded`; it cannot start
  an unbounded number of threads. The response carries no `Retry-After`,
  because an immediate retry of the same input usually times out again. The
  abandoned thread stores no vault mapping (see [limitations](limitations.md)
  for the one narrow window where it can). Detector threads come from a dedicated pool
  the size of the cap, separate from the pool used for egress checks and
  restoration.
- **The deadline cannot fire during a single call that holds the GIL.** One
  catastrophic regular expression match stops the event loop as well, so the
  timeout is noticed only when that match returns, and `/healthz` stalls with
  it. Custom patterns remain trusted configuration; see
  [limitations](limitations.md).

### Metrics

`GET /metrics` serves counters and gauges in the Prometheus text format. The
route does not exist unless `SAG_METRICS_TOKEN` is set, and then it accepts
only that token as a bearer credential, compared in constant time. It never
consults the API key store, so a tenant key is never accepted, and startup
fails if the token is also one of `SAG_API_KEYS`, shorter than 32 characters,
or repetitive. It is served on the API port; scrape it from inside your
network.

```yaml
scrape_configs:
  - job_name: cloakspan
    authorization:
      credentials_file: /etc/prometheus/cloakspan-metrics-token
    static_configs:
      - targets: ["gateway:8080"]
```

| Metric | Type | Labels |
|---|---|---|
| `cloakspan_requests_total` | counter | `route`, `status_class`, `decision`, `destination` |
| `cloakspan_request_refusals_total` | counter | `route`, `reason` (the audit reason codes below, plus `blocked_by_policy`) |
| `cloakspan_tokens_restored_total` | counter | none |
| `cloakspan_tokens_refused_total` | counter | `reason`: `not_minted`, `vault_miss`, `cross_tenant`, `key_unavailable` |
| `cloakspan_requests_in_flight` | gauge | `route` |
| `cloakspan_max_concurrent_requests` | gauge | `route` |
| `cloakspan_detector_overruns_in_flight` | gauge | `route` |

Every label value comes from a fixed list in `gateway/telemetry/metrics.py`;
anything outside it is recorded as `other`. No tenant, key, model,
conversation, path or prompt text is a label or a value. `destination` is one
of `external`, `local`, `mock`, `none`, so a policy destination with another
name is counted as `other`.

### Audit reason codes

Every Chat Completions request writes exactly one audit event before its
response is returned. A refusal or failure sets `error` to one of these codes;
a success and a policy block leave it `null`, as before. Events for requests
refused before the request is validated use fixed placeholders: tenant
`unauthenticated` and key `unknown` when authentication failed, conversation
`anonymous`, model `client-model`, rule `request-refused`, decision `block`,
provider `none`. They never contain the presented credential or an
unvalidated header or field.

| Code | HTTP | Meaning |
|---|---|---|
| `invalid_api_key` | 401 | No valid gateway key |
| `rate_limit_exceeded` | 429 | Over `SAG_RATE_LIMIT_PER_MINUTE` |
| `capacity_exceeded` | 503 | Over `SAG_MAX_CONCURRENT_REQUESTS` |
| `reserved_conversation_scope` | 403 | Conversation id starts with `agent_` |
| `request_too_large` | 413 | Over `SAG_MAX_REQUEST_BYTES` |
| `request_timeout` | 408 | Body not received within `SAG_REQUEST_BODY_TIMEOUT_SECONDS` |
| `invalid_json` | 400 | Body is not JSON |
| `model_not_allowed` | 403 | Key not permitted to use the model |
| `invalid_request`, `streaming_unsupported`, `unknown_field`, `uninspectable_field`, `unsupported_role`, `invalid_message` | 400/422 | Request contract refusals, equal to the response's `error.code` |
| `inspection_failed` | 422 | Content could not be inspected, or a detector failed |
| `detector_timeout` | 503 | Inspection exceeded `SAG_DETECTOR_TIMEOUT_SECONDS` |
| `suspicious_encoding_*` | 422 | Deceptive encoding, as before |
| `local_routing_violation` | 500 | The local-routing tripwire fired. Nothing was sent |
| `vault_error` | 500 | The vault failed while transforming |
| `destination_unavailable` | 500 | Policy chose a destination that is not configured |
| `egress_blocked` | 502 | The destination failed its per-request egress check. Nothing was sent |
| `provider_timeout` | 504 | Provider deadline elapsed |
| `provider_unavailable` | 502 | Provider could not be reached |
| `provider_error` | 4xx/502 | Provider returned an error status |
| `provider_bad_response` | 502 | Provider response not JSON, not an object, too large, or not serialisable back to the client (a lone surrogate, a non-finite number) |
| `restoration_refused` | 502 | Restored content would exceed its size limit |
| `cancelled` | none sent | The client went away, including mid-body |
| `internal_error` | 500 | Anything else |

For the `provider_*` codes and `restoration_refused`, `provider` names the
destination whose client the request was handed to. `cancelled` and
`internal_error` name it only if the request had already been handed over.
Every other code, `egress_blocked` included, has `provider` `none`: nothing
was sent. The metrics
`destination` label is set only for successful requests and is `none` for
every refusal and failure. Provider failures keep `error.code` `upstream_error` in the HTTP
response; the audit event and metrics carry the specific reason. Responses for
paths and methods that do not exist (404, 405) are produced by the framework,
never reach a handler, and write no audit event.

---

## Incident: suspected key compromise

1. Rotate `SAG_VAULT_KEY` additively (above). Live mappings keep working.
2. Rotate `SAG_TOKEN_KEY`. This invalidates every token immediately — accept the
   user-visible breakage; a compromised token key means tokens can be forged.
3. Purge the vault: `DELETE /v1/conversations/{id}` per conversation, or restart
   with the in-memory backend.
4. Preserve the audit stream. It contains no prompt content, so it is safe to
   share with responders, which is the point of the structural guarantee.
5. Follow `docs/incident-response.md` for the rest.

---

## Known operational gaps

Listed rather than discovered:

- **Release artifact assurance remains outstanding.** The existing
  and agent container suites passed on the pinned-base implementation image on
  2026-10-08; see [implementation evidence](agent-compatibility.md#implementation-verification-2026-10-08).
  Signing, build provenance and required CI release checks remain pending.
- **Upgrade and rollback have never been rehearsed** from a previous release
  candidate, which is required before GA.
- **Limits are per process.** The rate limit, concurrency cap and metrics are
  not shared between replicas and reset on restart. There is no per-address or
  unauthenticated rate limit; put one in the reverse proxy.
- **A detector that holds the GIL cannot be timed out.** The Chat Completions
  deadline is checked by the event loop, which a single catastrophic regular
  expression match stops too. Such a match holds its slot, and `/healthz`,
  until it returns. The experimental agent path runs detectors in a process
  that is killed instead.
- **The agent endpoints are outside the new limits and metrics.** They keep
  `SAG_AGENT_MAX_CONCURRENT` and their own audit events, and have no rate
  limit.
- **Metrics have no history.** Counters live in process memory and reset on
  restart; scrape them, or derive the same signals from the audit stream.

## Experimental agent deployment

Responses/Messages are a separate opt-in milestone. Start with a disposable
synthetic workspace and the [client templates](../deployment/clients/README.md).
The public profiles pin Codex CLI 0.161.0 and Claude Code CLI 2.1.293 in the
[support matrix](agent-compatibility.md). Private versions/captures do not block
their implementation; actual CLI evidence and production qualification are
recorded separately. There is no recorded pilot approval.
Upstream provider credentials remain at the gateway, while client gateway keys
are independently revocable. Native Messages uses `SAG_MESSAGES_BASE_URL`,
`SAG_MESSAGES_API_KEY` and `SAG_MESSAGES_MODEL`; Responses uses the external
provider settings. Local routing requires the local endpoint to implement the
chosen native protocol, with no fallback to an external provider.

| Setting | Default / purpose |
|---|---|
| `SAG_ENABLE_RESPONSES`, `SAG_ENABLE_MESSAGES` | `false`; enable only the experimental adapter needed |
| `SAG_AGENT_WORKSPACE_ROOT` | Required existing absolute directory for agent tools |
| `SAG_AGENT_MAX_CONCURRENT` | `4`; bound admitted native agent work |
| `SAG_AGENT_DETECTOR_TIMEOUT_SECONDS` | `15`; terminate isolated detector work when the wall-clock limit expires |
| `SAG_AGENT_STREAM_IDLE_SECONDS` | `120`; maximum wait for upstream stream progress |
| `SAG_AGENT_STREAM_TOTAL_SECONDS` | `600`; maximum total generation duration |
| `SAG_AGENT_MAX_EVENT_BYTES` | `1048576`; maximum upstream SSE frame size |
| `SAG_AGENT_MAX_OUTPUT_BYTES` | `8388608`; maximum restored output size |

Existing input/body caps also apply. Detector isolation, request rejection,
stream failure, restoration refusal and cancellation produce safe agent audit
outcomes. Do not add prompts, mappings, raw private paths or tool arguments to
logs/metrics. A stalled detector is terminated on the native paths; Chat
Completions refuses on its own deadline but cannot terminate the thread (see
[Limits and metrics](#limits-and-metrics)).

Use stable session identities (`X-Session-Id`, `X-Conversation-Id`, public Codex
`session-id`/`thread-id`, legacy `session_id` or native Claude `x-claude-code-session-id`) and
replay original/restored history. Supplied aliases must
agree. The gateway binds a SHA-256 conversation scope to tenant and
`ApiKey.key_id` principal; a raw client session ID is not authorization. Preserve
the key record's `key_id` on credential rotation to retain that principal, and
keep token/vault keys stable across rollout. `DELETE /v1/agent/sessions/{id}`
removes mappings only in the authenticated tenant/principal's derived namespace.
The native Claude agent identity partitions subagent scope. Typed client device
and turn metadata is inspected then consumed locally; prompt cache identifiers
are hashed with authenticated session/routing/policy scope before provider egress.
Caches never skip inspection or reuse another request's restoration provenance.
Legacy Chat Completions and its deletion endpoint refuse IDs beginning `agent_`;
use the agent session API for these mappings.
Vault mappings are still ephemeral;
full inspectable replay can recreate them after restart, while missing history
causes executable restoration refusal. Opaque reasoning/compaction,
provider storage and WebSockets remain disabled without an approved contract.
The public custom-provider Codex profile uses inspectable local text compaction
through ordinary requests. Qualify its automatic trigger/resume workflow without
enabling the opaque compact endpoint. The client examples explicitly raise the
inspected-character cap to one million and bound bodies at 4 MiB for public
CLI tools and long replay; measure detector time and memory before production.

Tool declarations and batches obey the bounded executable-schema, tool-choice,
type/name, parallelism and maximum-call contract; an unsupported schema fails
before provider egress. Sensitive numeric JSON content and ambiguous canonical
originals in a tool-bearing request also fail before egress. Concurrent requests
restore their own provenance originals after authentic vault/canonical checks,
so one request's spelling cannot overwrite another request's executable edit.

Preflight makes network requests only with `--network`; see the examples for
model/workspace/key configuration. It checks authentication, selected model,
native stream completion and a verified harmless local read/result round trip.
Its pass does not qualify a real client, edit/test workflow, compaction or resume.
Run `scripts/benchmark_agents.py` with the same synthetic tasks by size/profile:

```sh
python scripts/benchmark_agents.py --protocol both --profiles deterministic dictionary \
  --sizes 4096 16384 --iterations 20 --output dist/agent-benchmark.json
```

The default benchmark compares direct synthetic provider and gateway runtime
paths without HTTP/TLS/network or a real client/model. It reports inspection,
first text, withheld tool release, total time, estimated usage, failures and
parent Python allocation peak. Cache metrics remain null without cache evidence;
child/native/model RSS and real tokenizer counts must be measured separately.
This is a regression signal on the recorded machine, not published capacity.

**Proposed reference pilot budgets, not measured acceptance:** a single Linux
node with 2 vCPU / 4 GiB RAM, deterministic profile, 4 concurrent sessions;
gateway-added p95 time to first text <=250 ms at 4 KiB and <=750 ms at 16 KiB;
gateway-added post-terminal tool release p95 <=100 ms; total synthetic task
overhead <=10% or 1 second, whichever is larger; zero unsafe tool releases or
detectable-canary leaks and <=1% unexpected failures. Measure optional NER and
larger prompts separately before setting their budgets. Record exact hardware,
image, profile, provider/model, client versions, warm-up/cache behavior, token
changes and complete deployment RSS. The current synthetic script cannot certify
these deployment budgets.

Qualify detector process start methods inside the actual ASGI/container host,
including threaded fork safety, NER startup/serialization and cancellation.
Measure complete parent/child/native RSS under the selected cgroup CPU/memory
limits and at concurrency capacity. A parent `tracemalloc` number or per-process
address-space limit is not evidence of whole-container capacity.

The pinned CLI profiles pass full synthetic read/edit/test/follow-up, automatic
compaction and resumed work. Reproduce that evidence with
`scripts/public_client_check.py --mode gateway --workflow --compact`, explicitly
supplying installed pinned binaries. The support matrix records lowered test
thresholds and estimated usage; qualify live/desktop deployments separately.
Trace telemetry, MCP,
downloads and executed commands for endpoint bypasses and enforce deployment
egress separately. Roll back on canary leaks, unsafe/duplicate tool execution,
failed compaction/resume or resource-budget breaches: disable the affected flags
or restore the tested gateway, preserve compatible keys, and recover through
inspectable history. Never redirect clients around the gateway.
