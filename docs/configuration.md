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
| `SAG_POLICY_PATH` | bundled default policy | Path to a YAML policy file. |
| `SAG_EXTERNAL_BASE_URL` | mock outside production | OpenAI-compatible `/v1` base URL for the `external` destination. |
| `SAG_EXTERNAL_API_KEY` | none | Credential for the external provider. |
| `SAG_EXTERNAL_MODEL` | request model | Optional model override for the external provider. |
| `SAG_LOCAL_BASE_URL` | mock outside production | OpenAI-compatible `/v1` base URL for the `local` destination. Private addresses require the local policy created by the application. |
| `SAG_LOCAL_MODEL` | request model | Optional model override for the local provider. |
| `SAG_EGRESS_ALLOWLIST` | any public host | Comma-separated provider hostnames. Set this in production to pin egress. |
| `SAG_EGRESS_ALLOW_PRIVATE` | `false` | Allows private, loopback, and link-local destinations for every provider. This disables the SSRF address control globally. |
| `SAG_TRUST_ENV_PROXY` | `false` | Allows `HTTP_PROXY`, `HTTPS_PROXY`, and related ambient proxy settings. |
| `SAG_NER_MODEL_PATH` | none | Directory containing a checksum-verified NER model and manifest. |
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
