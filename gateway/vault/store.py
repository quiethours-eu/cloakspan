"""Encrypted surrogate mapping vault.

The vault holds the one thing in the system that is unambiguously sensitive:
the map from surrogate token back to the real value. Design constraints:

* **Encrypted at rest, always.** Not "protected by file permissions". The
  one reviewed implementation writes real PII as plaintext JSON and relies on
  mode 0600 -- while its own documentation concedes the mode is ignored on
  Windows. The affected project is deliberately left unnamed pending coordinated
  disclosure.
* **Tenant-scoped by construction.** Every key includes the tenant id, and
  ``get`` refuses to return an entry whose stored tenant does not match the
  caller's. Two independent checks, because cross-tenant leakage is the worst
  outcome the product has.
* **TTL enforced on read**, not only by a sweeper. A sweeper that fails must
  not silently extend the lifetime of real PII.
* **No custom cryptography.** AES-256-GCM via ``cryptography``'s AESGCM.

## Record format

Every record is self-describing, so it can be read without out-of-band
knowledge of which key or which format produced it::

    format_version (1 byte) | key_version (2 bytes BE) | nonce (12) | ciphertext+tag

The header is readable before decryption -- it has to be, to select the key --
so it is bound into the AEAD additional data instead of being inside the
ciphertext. A record whose header is edited fails authentication.

Without this envelope, rotating ``SAG_VAULT_KEY`` renders every live mapping
undecryptable and, because a decryption failure is deliberately treated as
"absent", the operator sees **no error at all** -- tokens simply stop restoring.
That is the specific failure this format exists to make impossible. See
docs/adr/0012-vault-record-envelope-and-key-rotation.md.

Backends: in-memory (default, Community Edition single node). PostgreSQL and
per-tenant KMS envelope encryption are the Cloud Edition path.
"""

from __future__ import annotations

import json
import logging
import os
import struct
import threading
import time
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gateway.domain import RequestContext
from gateway.transformations.tokens import length_prefixed

logger = logging.getLogger("gateway.vault")

DEFAULT_TTL_SECONDS = 3600

#: Record format 1: AES-256-GCM, 96-bit random nonce.
RECORD_FORMAT_VERSION = 1
_NONCE_BYTES = 12
_HEADER = struct.Struct(">BH")  # format_version, key_version
_HEADER_LEN = _HEADER.size

_AAD_DOMAIN = "quiethours/vault"


class VaultError(Exception):
    """Base class for vault failures."""


class CrossTenantAccessError(VaultError):
    """Raised when a lookup would cross a tenant boundary.

    This is a security event, not a normal error: reaching it means either a
    bug in scoping or an active attack. It is always audited.
    """


class VaultKeyUnavailableError(VaultError):
    """Raised when a record names a key version that is not configured.

    Deliberately **not** treated as "absent". An absent record is ordinary; a
    record encrypted under a key the operator has removed while it is still in
    use is a configuration error that will silently break restoration for every
    affected conversation. It must be loud.
    """


@dataclass(frozen=True, slots=True)
class VaultEntry:
    tenant_id: str
    conversation_id: str
    token: str
    value: str
    expires_at: float

    def is_expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at


class KeyRing:
    """The set of vault keys, one per version, with one active for writing.

    Rotation is additive: add version N+1, mark it active, and let existing
    records expire on their TTL. No re-encryption pass is needed because vault
    records are short-lived by design -- which is a further argument for the
    short default TTL.
    """

    def __init__(self, keys: dict[int, bytes], active_version: int) -> None:
        if not keys:
            raise ValueError("key ring must contain at least one key")
        for version, key in keys.items():
            if not 0 <= version <= 0xFFFF:
                raise ValueError(f"key version {version} out of range for a 2-byte field")
            if len(key) != 32:
                raise ValueError(f"vault key v{version} must be exactly 32 bytes (AES-256)")
        if active_version not in keys:
            raise ValueError(f"active key version {active_version} is not in the key ring")
        self._aeads = {version: AESGCM(key) for version, key in keys.items()}
        self._active_version = active_version

    @property
    def active_version(self) -> int:
        return self._active_version

    @property
    def versions(self) -> tuple[int, ...]:
        return tuple(sorted(self._aeads))

    def aead(self, version: int) -> AESGCM:
        try:
            return self._aeads[version]
        except KeyError as exc:
            raise VaultKeyUnavailableError(
                f"record requires vault key version {version}, which is not configured; "
                f"configured versions: {list(self.versions)}"
            ) from exc


class VaultBackend(Protocol):
    """Storage for opaque encrypted blobs.

    Implementations **must** be safe for concurrent use: the pipeline may handle
    several requests for the same conversation at once, and both may write the
    same key. See docs/adr/0014-retry-cancellation-and-provenance.md.
    """

    def put(self, key: str, blob: bytes, expires_at: float) -> None: ...
    def get(self, key: str) -> bytes | None: ...
    def delete(self, key: str) -> None: ...
    def delete_prefix(self, prefix: str) -> int: ...
    def purge_expired(self, now: float) -> int: ...


class InMemoryBackend:
    """Process-local storage. Default for the Community Edition.

    The lock is explicit rather than relying on CPython's per-operation ``dict``
    atomicity: that guarantee is a property of the interpreter, not of the
    protocol, and the next backend will not have it.
    """

    def __init__(self) -> None:
        self._items: dict[str, tuple[bytes, float]] = {}
        self._lock = threading.Lock()

    def put(self, key: str, blob: bytes, expires_at: float) -> None:
        with self._lock:
            self._items[key] = (blob, expires_at)

    def get(self, key: str) -> bytes | None:
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            blob, expires_at = item
            if time.time() >= expires_at:
                # Expire on read. Never return material past its TTL even if the
                # sweeper has not run.
                self._items.pop(key, None)
                return None
            return blob

    def delete(self, key: str) -> None:
        with self._lock:
            self._items.pop(key, None)

    def delete_prefix(self, prefix: str) -> int:
        with self._lock:
            stale = [k for k in self._items if k.startswith(prefix)]
            for key in stale:
                self._items.pop(key, None)
            return len(stale)

    def purge_expired(self, now: float) -> int:
        with self._lock:
            stale = [k for k, (_, exp) in self._items.items() if now >= exp]
            for key in stale:
                self._items.pop(key, None)
            return len(stale)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


class SurrogateVault:
    """Tenant-scoped, encrypted, expiring surrogate mapping store."""

    def __init__(
        self,
        key_ring: KeyRing,
        backend: VaultBackend | None = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self._keys = key_ring
        self._backend = backend or InMemoryBackend()
        self._ttl = ttl_seconds
        #: Records rejected because their format version is unknown to this
        #: build. Counted, never logged with content.
        self.unknown_format_records = 0

    @property
    def key_ring(self) -> KeyRing:
        return self._keys

    @staticmethod
    def conversation_prefix(ctx: RequestContext) -> str:
        return f"{ctx.tenant_id}\x00{ctx.conversation_id}\x00"

    @classmethod
    def _key(cls, ctx: RequestContext, token: str) -> str:
        """Storage key. Tenant and conversation are part of the key itself, so a
        cross-tenant read cannot even address another tenant's entry."""
        return f"{cls.conversation_prefix(ctx)}{token}"

    @staticmethod
    def _aad(
        ctx: RequestContext,
        token: str,
        token_version: str,
        key_version: int,
        format_version: int,
    ) -> bytes:
        """Additional authenticated data.

        Binding the ciphertext to (tenant, conversation, token, token version,
        key version, format version) means a blob moved to another tenant's key
        fails to decrypt rather than decrypting into the wrong context. The AEAD
        does the isolation work, not just our control flow -- which is the claim
        ``test_relocated_blob_fails_to_decrypt_not_merely_compare`` exists to
        prove.

        Length-prefixed for the same reason the HMAC input is: the previous
        ``f"{tenant}|{conv}|{token}"`` form is ambiguous for a tenant id
        containing ``|``.
        """
        body = length_prefixed(
            _AAD_DOMAIN,
            ctx.tenant_id,
            ctx.conversation_id,
            token,
            token_version,
        )
        return body + _HEADER.pack(format_version, key_version)

    def put(
        self,
        ctx: RequestContext,
        token: str,
        value: str,
        token_version: str,
    ) -> None:
        key_version = self._keys.active_version
        expires_at = time.time() + self._ttl
        payload = json.dumps(
            {
                "tenant_id": ctx.tenant_id,
                "conversation_id": ctx.conversation_id,
                "token": token,
                "token_version": token_version,
                "value": value,
                "expires_at": expires_at,
            }
        ).encode("utf-8")

        # Fresh 96-bit nonce per encryption, never a counter and never derived
        # from the record key. Nonce reuse under one key in GCM leaks the
        # authentication key, not merely one plaintext.
        nonce = os.urandom(_NONCE_BYTES)
        aad = self._aad(ctx, token, token_version, key_version, RECORD_FORMAT_VERSION)
        ciphertext = self._keys.aead(key_version).encrypt(nonce, payload, aad)

        record = _HEADER.pack(RECORD_FORMAT_VERSION, key_version) + nonce + ciphertext
        self._backend.put(self._key(ctx, token), record, expires_at)

    def get(self, ctx: RequestContext, token: str, token_version: str) -> str | None:
        """Return the original value, or None if absent or expired.

        Raises :class:`CrossTenantAccessError` if the decrypted entry does not
        belong to the calling tenant. That should be unreachable -- the AAD
        binding makes decryption fail first -- but a defence that is only
        unreachable "by construction" is one refactor away from being reachable.

        Raises :class:`VaultKeyUnavailableError` if the record names a key
        version that is not configured. This is deliberately distinguished from
        "absent": it means the operator removed a key that is still in use.
        """
        record = self._backend.get(self._key(ctx, token))
        if record is None:
            return None
        if len(record) < _HEADER_LEN + _NONCE_BYTES:
            return None

        format_version, key_version = _HEADER.unpack(record[:_HEADER_LEN])
        if format_version != RECORD_FORMAT_VERSION:
            # A record written by a future build. Count it, do not guess at it.
            self.unknown_format_records += 1
            logger.warning(
                "vault record with unsupported format version %d; treating as absent",
                format_version,
            )
            return None

        aead = self._keys.aead(key_version)  # raises VaultKeyUnavailableError
        nonce = record[_HEADER_LEN : _HEADER_LEN + _NONCE_BYTES]
        ciphertext = record[_HEADER_LEN + _NONCE_BYTES :]
        aad = self._aad(ctx, token, token_version, key_version, format_version)

        try:
            plaintext = aead.decrypt(nonce, ciphertext, aad)
        except Exception:
            # Authentication failure: tampering, wrong key, or a blob that
            # belongs to a different context. Treat as absent, never as an
            # opportunity to try harder.
            return None

        entry = json.loads(plaintext)
        if entry["tenant_id"] != ctx.tenant_id:
            raise CrossTenantAccessError("vault entry tenant does not match request tenant")
        if entry["conversation_id"] != ctx.conversation_id:
            raise CrossTenantAccessError(
                "vault entry conversation does not match request conversation"
            )
        if time.time() >= entry["expires_at"]:
            return None
        return entry["value"]

    def delete(self, ctx: RequestContext, token: str) -> None:
        self._backend.delete(self._key(ctx, token))

    def delete_conversation(self, ctx: RequestContext) -> int:
        """Erase every mapping for (tenant, conversation).

        Required for an erasure request to be answerable with something other
        than "wait an hour for the TTL". Returns the number of records removed,
        which is a count and therefore safe to audit.
        """
        return self._backend.delete_prefix(self.conversation_prefix(ctx))

    def purge_expired(self) -> int:
        return self._backend.purge_expired(time.time())
