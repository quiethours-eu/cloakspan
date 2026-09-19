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

### Latency is higher than expected

Run `make benchmark` on the same documented hardware used for the baseline. The
detection path is single-digit-to-low-double-digit milliseconds; if the total is
much larger, the time is in the provider call, not here.

---

## What to alert on

| Signal | Threshold | Why |
|---|---|---|
| `CrossTenantAccessError` | **any** | Should be structurally impossible. Page |
| `tokens_refused_by_reason.cross_tenant` | **any** | Same |
| `tokens_refused_by_reason.key_unavailable` | any | A key in use was removed |
| `tokens_refused_by_reason.not_minted` | sustained rate | Token probing |
| `encoding_signals.suspicious_encoding_bidi` | sustained rate | Deliberate deception attempts |
| HTTP 422 rate | step change | Usually a client upgrade meeting reject-unknown, not an attack |
| `/readyz` non-200 | 2 consecutive | |

Do **not** alert on `tokens_refused` in total. It spikes on every deploy, and an
alert that cries wolf at each release is an alert that gets muted.

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

- **Container hardening has never been verified on a real build here** — the
  tests exist (`make test-container`) and the registry was unreachable in the
  development environment. Run them before trusting the claims.
- **Upgrade and rollback have never been rehearsed** from a previous release
  candidate, which is required before GA.
- **Error paths write no audit event.** A 422 or a provider failure leaves no
  record you can query.
- **No rate limiting.** Request size is capped; request *rate* is not.
- **Detector timeouts are not implemented.** A pathological input can occupy a
  worker until the client disconnects.
- **No metrics endpoint.** Everything above is derived from the audit stream.
