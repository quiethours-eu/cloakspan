# Configuration

Cloakspan reads configuration from environment variables. Development
mode can generate ephemeral secrets and use the offline mock provider.
`SAG_ENVIRONMENT=production` refuses those fallbacks at startup.

Copy `.env.example` to `.env` for Docker Compose. Do not commit the resulting
file.

## Variables

| Variable | Default | Purpose |
|---|---|---|
| `SAG_ENVIRONMENT` | `development` | Set to `production` to require durable secrets, gateway API keys, and every provider destination used by policy. |
| `SAG_API_KEYS` | none | Comma-separated `key:tenant:application` entries. Production keys need the `sgw_live_` prefix and at least 32 random characters. |
| `SAG_VAULT_KEY` | ephemeral outside production | Root secret for vault key version 1, at least 32 bytes. |
| `SAG_VAULT_KEY_V<n>` | none | Versioned root secret used for additive vault-key rotation, for example `SAG_VAULT_KEY_V2`. |
| `SAG_VAULT_ACTIVE_KEY_VERSION` | highest configured version | Key version used for new vault records. |
| `SAG_TOKEN_KEY` | ephemeral outside production | Root secret used to derive the token HMAC key, at least 32 bytes. |
| `SAG_POLICY_PATH` | bundled default policy | Path to a YAML policy file. [`deployment/policies/default.yaml`](../deployment/policies/default.yaml) shows the format. |
| `SAG_LOCAL_ROUTING` | `off` | GDPR mode: `off`, `detected`, or `all`. Any other value stops startup. See [GDPR mode](#gdpr-mode-sag_local_routing) below. |
| `SAG_EXTERNAL_BASE_URL` | mock outside production | OpenAI-compatible `/v1` base URL for the `external` destination. Ignored under `SAG_LOCAL_ROUTING=all`. |
| `SAG_EXTERNAL_API_KEY` | none | Credential for the external provider. |
| `SAG_EXTERNAL_MODEL` | request model | Optional model override for the external provider. |
| `SAG_LOCAL_BASE_URL` | mock outside production | OpenAI-compatible `/v1` base URL for the `local` destination. Unlike `external`, it may use loopback or private addresses and plain http. With `SAG_LOCAL_ROUTING` on, it is required in every environment and must resolve only to loopback or private-network addresses. |
| `SAG_LOCAL_MODEL` | request model | Optional model override for the local provider. |
| `SAG_EGRESS_ALLOWLIST` | any public host | Comma-separated provider hostnames. Set this in production to pin egress. |
| `SAG_EGRESS_ALLOW_PRIVATE` | `false` | Allows private, loopback, and link-local destinations for every provider. This disables the SSRF address control globally. |
| `SAG_TRUST_ENV_PROXY` | `false` | Allows `HTTP_PROXY`, `HTTPS_PROXY`, and related ambient proxy settings, and a CA bundle from `SSL_CERT_FILE` or `SSL_CERT_DIR`. While `SAG_LOCAL_ROUTING` is on, the local provider ignores the proxy settings and still uses the CA bundle. |
| `SAG_NER_MODEL_PATH` | none | Directory containing a checksum-verified NER model and manifest. Needs the `[ner]` extra installed, which the container image does not include. Required by `SAG_LOCAL_ROUTING=detected`. |
| `SAG_FILTERS_PATH` | none | Path to a versioned YAML file containing custom matchers and actions; see below. |
| `SAG_DICTIONARY_TERMS` | none | Comma-separated confidential terms. |
| `SAG_CUSTOM_PATTERNS` | none | Semicolon-separated `ENTITY=regex` rules. Patterns are trusted configuration and currently have no execution timeout. |
| `SAG_BLOCK_MIXED_SCRIPT` | `false` | Blocks words that mix scripts instead of recording an encoding signal only. |
| `SAG_VAULT_TTL_SECONDS` | `3600` | Mapping lifetime. A higher value retains personal data longer. |
| `SAG_MAX_INPUT_CHARS` | `65536` | Total message characters inspected per request. Raising it increases CPU cost. |
| `SAG_MAX_REQUEST_BYTES` | `1048576` | HTTP body limit enforced while streaming, before JSON parsing. |
| `SAG_REQUEST_TIMEOUT_SECONDS` | `120` | Total provider deadline across attempts. |
| `SAG_BIND_HOST` | `0.0.0.0` from source; Compose publishes on `127.0.0.1` | Uvicorn bind address. |
| `SAG_PORT` | `8080` | Uvicorn port. |
| `SAG_LOG_LEVEL` | `INFO` | Application log level. |

## Unified custom filters

Define identifiers, confidential phrases, or other business data in one YAML
format, independent of country presets. Copy
[`deployment/filters/example.yaml`](../deployment/filters/example.yaml), edit it,
and set `SAG_FILTERS_PATH=/path/to/filters.yaml`. Restart the gateway to load changes.

```yaml
version: 1
filters:
  - name: employee-ids
    entity_type: EMPLOYEE_ID
    match:
      type: regex
      pattern: '\bEMP-[0-9]{6}\b'
    action: transform

  - name: confidential-projects
    entity_type: CONFIDENTIAL_PROJECT
    match:
      type: dictionary
      terms: [Project Aurora, Project Meridian]
      case_sensitive: false
    action: block
```

Each entry creates both a detector and a policy rule. No Python code or separate
policy entry is needed. `transform` replaces detected values with scoped tokens
before forwarding and restores them in the response; `block` refuses the request;
`route_local` transforms and sends it to the `local` destination unless the filter
names another one. A `route_local` rule written in a policy YAML file behaves
differently: without a `destination` it falls back to the policy's
`default_destination`, which is `external` in the shipped policy.

| Field | Meaning |
|---|---|
| `name` | Unique name, 1–64 ASCII letters, digits, underscores or hyphens; first character must be alphanumeric. Audit rule names use `filter:<name>`. |
| `entity_type` | Unique label in this file, matching `[A-Z][A-Z0-9_]{0,63}`, e.g. `EMPLOYEE_ID`. Use a new label to keep handling distinct from existing entities. |
| `match` | `type: regex` with `pattern`, or `type: dictionary` with a non-empty `terms` list. |
| `match.case_sensitive` | Defaults to `true` for regex, `false` for dictionary. Regex inline flags also apply. |
| `action` | `transform` (default), `block`, or `route_local`. |
| `destination` | Optional provider name for transform/local routing. Transform inherits the policy default. Block must omit this field. |
| `priority` | Optional integer 0–1000. Defaults: transform 60, local routing 90, block 100. |
| `enabled` | Boolean, defaults to `true`. Disabled filters are validated but add neither detector nor rule. |

Built-in detectors and the legacy `SAG_DICTIONARY_TERMS` and
`SAG_CUSTOM_PATTERNS` settings remain active alongside this file. Filters apply
to all tenants and applications on the gateway. Matching uses the existing
Unicode-normalized text view and maps replacements back to the original text.
Dictionary entries are literal, match at word boundaries, and prefer the longest
term. Regexes match the whole expression, not just a capture group. Custom
regexes do not add country-specific checksum validation.

Actions use the existing **request-wide policy precedence**: highest priority
wins; block wins equal-priority ties, then rule name sorts alphabetically.
For example, the default Baltic local-routing rule (90) outranks a custom
transform (60). A transform/local decision replaces all detected spans. A rule
using an existing entity label also applies to detections from other detectors
with that label. Review priority overrides against your full policy; a higher
priority can override a lower-priority block. Overlapping detections use the
gateway's existing span conflict resolution.

Missing files, unknown fields, malformed patterns, duplicate YAML keys, duplicate
names/entity labels, and unsupported versions stop startup. Regexes are trusted
operator configuration: the existing length and backtracking-shape checks apply,
but execution has no hard timeout. Test patterns against representative inputs.
The filter file's content hash is included in the audit policy version.

For Docker Compose, create `compose.override.yaml` to mount the file read-only:

```yaml
services:
  gateway:
    environment:
      SAG_FILTERS_PATH: /app/config/filters.yaml
    volumes:
      - ./deployment/filters/example.yaml:/app/config/filters.yaml:ro
```

## GDPR mode (SAG_LOCAL_ROUTING)

`SAG_LOCAL_ROUTING` sends requests that contain detected personal data to a
model you run, instead of to the external provider. The README calls this GDPR
mode. The reasoning behind it is in
[ADR-0017](adr/0017-local-routing-mode.md).

| Value | What can reach `external` |
|---|---|
| `off` (default; unset or empty means the same) | Whatever your policy allows. Nothing changes |
| `detected` | Only requests in which no detector found anything, handled as your policy decides |
| `all` | Nothing. The gateway does not build an external client, and the `SAG_EXTERNAL_*` settings are ignored |

The mode is applied after your policy and your `SAG_FILTERS_PATH` rules have
decided. With it on, the final decision is:

| Your policy decided | `detected`, something detected | `detected`, nothing detected | `all` |
|---|---|---|---|
| `block` | Blocked (403) | Blocked (403) | Blocked (403) |
| Any action with destination `local` | Kept as is | Kept as is | Kept as is |
| `allow`, `transform`, or `route_local` to any other destination | `route_local` to `local` | Kept as is | `route_local` to `local` |

"Something detected" means at least one span from any detector: built-in,
NER, `SAG_FILTERS_PATH`, `SAG_DICTIONARY_TERMS`, or `SAG_CUSTOM_PATTERNS`, of
any entity type, at any score. There is no list of types to keep up to date,
and no rule, filter, priority, application scope, or `min_score` can send such
a request anywhere else. Only a destination spelled exactly `local` is left
alone; `external`, `mock`, an empty destination, and `Local` are all moved.

The mode overrides destinations from the policy and filters. It never lifts a
block, and it never removes pseudonymisation: a request it moves takes the
normal `route_local` path, so every detected value is replaced with a token
before the local model sees it and restored in the reply. A decision that
already goes to `local` keeps its own rule and action. An explicit `allow` rule
to `local` therefore still forwards the original text to your model.

Requests the mode moved carry `X-Policy-Rule: local-routing:detected` or
`local-routing:all`. While the mode is on, every `X-Policy-Version` ends in
`+local-routing:<mode>`, for example
`community-default-v1+local-routing:detected`. The audit event records the
same rule name and version, and `destination` shows where the request went.

If the local model is unreachable, times out, or returns an error, the client
gets 502 or 504 (or the model's own 4xx). The request is never retried against
the external provider.

### Startup refusals

The gateway refuses to start, in development as well as production, when:

| Condition | Message starts with |
|---|---|
| `SAG_LOCAL_ROUTING` has any value other than `off`, `detected`, or `all` (after trimming spaces and ignoring case) | `SAG_LOCAL_ROUTING must be one of: off, detected, all` |
| The mode is on and `SAG_LOCAL_BASE_URL` is not set. The offline mock is never used as the local model in this mode | `SAG_LOCAL_ROUTING=<mode> needs SAG_LOCAL_BASE_URL` |
| `SAG_LOCAL_ROUTING=detected` without an NER model. Names, organisations, places, and street addresses would go undetected. Set `SAG_NER_MODEL_PATH`, or use `all` | `SAG_LOCAL_ROUTING=detected needs an NER model` |
| The local host resolves to any address outside the ranges below | `destination 'local': ... is not loopback or a private network` |

A set but unusable `SAG_NER_MODEL_PATH` already stops startup in every mode,
and so does NER without the `[ner]` extra installed (`NER is enabled but spaCy
is not installed`).
In production, the existing check that refuses a mock-backed destination also
applies: with the default policy, `detected` needs both `SAG_EXTERNAL_BASE_URL`
and `SAG_LOCAL_BASE_URL`, while `all` needs only `SAG_LOCAL_BASE_URL`. If
`SAG_EGRESS_ALLOWLIST` is set, the local hostname must be on it.

### Where the local model may be

With the mode on, every address the `SAG_LOCAL_BASE_URL` host resolves to must
be in one of these ranges:

| Range | What it is |
|---|---|
| `127.0.0.0/8`, `::1/128` | Loopback |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | Private networks (RFC 1918). Docker's `host.docker.internal` usually resolves here |
| `100.64.0.0/10` | Shared address space (RFC 6598), used by Tailscale |
| `fc00::/7` | IPv6 unique local addresses |

IPv4-mapped IPv6 addresses such as `::ffff:10.0.0.5` are checked as the IPv4
address inside them. Everything else is refused, including link-local
addresses (so `169.254.169.254`), public addresses, and a name that resolves to
a mix of private and public addresses. The check runs at startup and again before every
request. Plain http is allowed. The local provider never uses
`HTTP_PROXY`-style settings in this mode, whatever `SAG_TRUST_ENV_PROXY` says.
With that setting on, it still trusts a CA bundle from `SSL_CERT_FILE` or
`SSL_CERT_DIR`, so an https model behind an internal CA keeps working.

A model on a public address is refused even when you run it yourself. Put it
behind a VPN or Tailscale and use the private address. The check sees
addresses, not who owns them: a private address that relays to a cloud API
passes it.

With Docker Compose, set `SAG_LOCAL_ROUTING` in `.env`. Compose still requires
`SAG_EXTERNAL_BASE_URL` to be set; under `all` the gateway ignores it.

The image built from `deployment/docker/Dockerfile` has no NER runtime, so it
starts with `off` or `all` but not with `detected`. For `detected`, run the
gateway from an installation with the `[ner]` extra (`pip install ".[ner]"`)
and point `SAG_NER_MODEL_PATH` at the model directory. In a container you build
yourself, mount that directory read-only.

## Generate production secrets

Generate each secret independently:

```bash
openssl rand -hex 32
openssl rand -hex 32
openssl rand -base64 32
```

Use the first two values for `SAG_VAULT_KEY` and `SAG_TOKEN_KEY`. Prefix the
third value with `sgw_live_` and use it in an `SAG_API_KEYS` entry:

```text
sgw_live_<random>:tenant-a:application-a
```

The vault and token values are root secrets. HKDF derives separate working keys
under different domain strings even if an operator accidentally supplies the
same value, but independent values are still required operational practice.

## Rotate the vault key

Rotation is additive because records are short-lived:

```bash
SAG_VAULT_KEY=<old> \
SAG_VAULT_KEY_V2=<new> \
SAG_VAULT_ACTIVE_KEY_VERSION=2
```

New records use v2. Existing records remain readable under v1 until their TTL
expires. Remove v1 only after one full TTL. Removing a live key raises
`VaultKeyUnavailableError` instead of silently dropping restoration.

Compose passes this first rotation path through directly. For later versions,
add the corresponding `SAG_VAULT_KEY_V<n>` entry in a Compose override. A custom
`SAG_POLICY_PATH` or `SAG_NER_MODEL_PATH` must likewise refer to a path mounted
inside the container, not a path that exists only on the host.

## Production checks

Before starting:

```bash
docker compose config
docker compose up -d
curl -fsS http://127.0.0.1:8080/readyz
```

Keep port 8080 on loopback unless a reviewed TLS reverse proxy controls network
access. Set `SAG_EGRESS_ALLOWLIST` to the exact provider hostnames. Do not enable
`SAG_EGRESS_ALLOW_PRIVATE` merely to make an external-provider configuration
work; it removes the private-address check for every destination.

See [operations](operations.md) for upgrades, rollback, deletion, key rotation,
and alerting.
