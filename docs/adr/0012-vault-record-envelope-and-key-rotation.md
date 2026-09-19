# ADR-0012: Vault record envelope, key derivation, nonce generation, and rotation

**Status:** PROPOSED · 2026-08-03 · `REQUIRES_SECURITY_REVIEW`
**Extends ADR-0005.**
**Invariants:** [SI-08](../security-invariants.md#si-08--safe-aead-operation),
[SI-05](../security-invariants.md#si-05--cross-tenant-isolation-is-cryptographic-not-control-flow),
[SI-09](../security-invariants.md#si-09--no-custom-cryptography)

## Context

The vault stores the one unambiguously sensitive thing in the system: the map
from surrogate token back to the real value. ADR-0005 chose AES-256-GCM with
(tenant, conversation, token) as AEAD additional data, and that ships and works.

Three operational properties were never specified, and their absence is now
blocking [SI-08](../security-invariants.md#si-08--safe-aead-operation).

**1. Records have no envelope.** A stored value is a bare `nonce ‖ ciphertext`
([vault/store.py:145](../../gateway/vault/store.py)). There is no key version,
no algorithm identifier, no format version. Nothing in a record says how to
decrypt it.

**2. There is no rotation procedure.** `SAG_VAULT_KEY` is read once at startup
([config.py:185](../../gateway/config.py)). Changing it renders every live
mapping undecryptable. Because `SurrogateVault.get` treats a decryption failure
as "absent" rather than as an error
([vault/store.py:160](../../gateway/vault/store.py)) — which is the correct
choice for tamper resistance — **an operator who rotates the key sees no error at
all.** Tokens simply stop restoring. That is a safe failure and a terrible
operational experience, and it is the reason keys in products shaped like this
never actually get rotated.

**3. Key derivation is unspecified.** `SAG_VAULT_KEY` and `SAG_TOKEN_KEY` are
read as hex or raw bytes and truncated to 32
([config.py:36](../../gateway/config.py)). A short or low-entropy operator
string is accepted as long as it is 32 bytes long, and there is no domain
separation between the two keys beyond the operator setting different values.

Nonce generation is already correct — a fresh 96-bit `os.urandom` per `put`
([vault/store.py:143](../../gateway/vault/store.py)) — and is recorded here so
it is specified rather than incidental.

## Decision

### 1 · Record envelope

Every record becomes a versioned, self-describing structure:

```
record := format_version (1 byte) ‖ key_version (2 bytes, big-endian)
          ‖ nonce (12 bytes) ‖ ciphertext ‖ tag
```

`format_version = 0x01` for AES-256-GCM with a 96-bit random nonce. A record
whose `format_version` is unknown is treated as absent and logged as a
**counter**, never with its content.

The envelope prefix is **not** authenticated by being inside the ciphertext — it
must be readable before decryption — so it is included in the AAD instead. A
record whose envelope is edited fails authentication.

### 2 · AAD

```
aad := "quiethours-vault-v1" ‖ 0x00
       ‖ len(tenant_id)   ‖ tenant_id
       ‖ len(conversation_id) ‖ conversation_id
       ‖ len(token)       ‖ token
       ‖ token_version    ‖ key_version ‖ format_version
```

Length-prefixed and domain-separated for the same reason as the HMAC input in
[ADR-0011](0011-token-format-and-versioning.md): the current `f"{tenant}|{conv}|{token}"`
([vault/store.py:129](../../gateway/vault/store.py)) is ambiguous under a
tenant id containing `|`. No exploit is known against it — tenant ids come from
operator configuration, not from request input — but "not attacker-controlled
today" is a property of the current deployment model, not of the code.

The token version enters the AAD here, closing the SI-05 gap.

### 3 · Key derivation

Operator input is a **root secret**, not a key. Both working keys are derived:

```
vault_key := HKDF-SHA256(ikm = SAG_VAULT_KEY,  info = "quiethours/vault/v1",  len = 32)
token_key := HKDF-SHA256(ikm = SAG_TOKEN_KEY,  info = "quiethours/token/v1",  len = 32)
```

HKDF from `cryptography.hazmat.primitives.kdf.hkdf` — no custom construction
([SI-09](../security-invariants.md#si-09--no-custom-cryptography)). Distinct
`info` strings mean that even an operator who sets both variables to the same
value gets two unrelated keys, which is a mistake worth defending against because
it is easy to make and invisible when made.

Minimum 32 bytes of input is retained and now enforced rather than truncated: a
shorter value is a **startup failure**, not a warning. The current behaviour of
generating an ephemeral key with a warning when the variable is unset
([config.py:47](../../gateway/config.py)) is kept for `make demo` and tests,
but the gateway refuses to start with an ephemeral key when
`SAG_ENVIRONMENT=production`.

### 4 · Rotation

Rotation is **additive, never in place**:

1. The operator sets `SAG_VAULT_KEY_V2` alongside `SAG_VAULT_KEY_V1` and sets
   `SAG_VAULT_ACTIVE_KEY_VERSION=2`.
2. New records are written with `key_version = 2`.
3. Reads try the key named by the record's own `key_version`. Old records
   continue to decrypt.
4. After the vault TTL has elapsed — one hour by default, so a few hours to be
   safe — every live record is v2 and the v1 key may be removed.

No re-encryption pass is needed, because vault records are short-lived by design.
This is the property that makes rotation cheap here and expensive in systems that
retain mappings indefinitely, and it is a further argument for the short TTL in
[ADR-0013](0013-vault-lifetime-deletion-and-restart.md).

**A record whose `key_version` names a key that is not configured is a loud
error**, distinct from "absent": the operator has removed a key that is still in
use. This is the specific failure the current design cannot report.

### 5 · Nonce generation

Fresh 96-bit `os.urandom` per encryption. Never a counter, never derived from
the record key.

A 96-bit random nonce reaches a 2⁻³² collision probability at roughly 2³²
encryptions **under one key**. With a one-hour TTL and per-version keys, a single
key never sees anything close to that. The bound is recorded here so that a
future change to TTL or rotation cadence has to confront it explicitly rather
than discover it.

## Alternatives considered

| Option | Rejected because |
|---|---|
| Keep bare `nonce ‖ ciphertext` | Cannot rotate, cannot migrate, cannot distinguish "wrong key" from "absent". This is the status quo and it is what SI-08 fails on |
| Per-record derived keys (HKDF over the token) | Removes rotation as a concept but makes every read a KDF call, and still needs a version to change the KDF |
| Envelope encryption with a KMS now | Correct for the hosted edition and specified in `docs/tenant-isolation.md`. Overkill for a single-node Community Edition deployment with no KMS available |
| Re-encryption sweep on rotation | Unnecessary given a one-hour TTL, and a sweep is a batch job that reads every plaintext — a new bulk-decryption path that did not previously exist |

## Consequences

**Security.** Closes SI-08. Closes the version half of SI-05. Removes the
"rotation is theoretically possible" hand-wave from the threat model, which is
the kind of claim an assessor tests.

**Operational.** Rotation becomes a documented, rehearsable procedure. Needs a
runbook in `docs/incident-response.md` — key compromise is precisely when this
gets used, under time pressure, by someone who has not done it before.

**Compatibility.** Existing records are unreadable under the new format. With the
default in-memory backend this is a non-event; a file backend would need a
migration or a flush.

**Delivery.** ~2 engineer-days including the rotation tests: encrypt under v1,
rotate, assert old records still read and new records use v2, assert a missing
key version raises rather than returning absent.

**Reversal cost.** Low. The envelope is additive; removing it later is a format
version bump.
