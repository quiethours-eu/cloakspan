"""Local API-key authentication.

Keys are stored as SHA-256 hashes, never in plaintext, so a leaked config file
or database dump does not hand over working credentials. Comparison is
constant-time.

We hash with plain SHA-256 rather than a password KDF deliberately: these are
high-entropy machine-generated secrets (32 random bytes), not human passwords.
A KDF protects against brute-forcing low-entropy inputs; there is nothing to
brute-force here, and a slow KDF on every request would be a self-inflicted
denial-of-service.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field

KEY_PREFIX = "sgw_live_"


@dataclass(frozen=True, slots=True)
class ApiKey:
    key_id: str
    key_hash: str
    tenant_id: str
    application: str = "default"
    allowed_models: frozenset[str] = field(default_factory=frozenset)

    def permits_model(self, model: str) -> bool:
        return not self.allowed_models or model in self.allowed_models


def generate_key() -> tuple[str, str]:
    """Return (plaintext_key, sha256_hash). The plaintext is shown once."""
    secret = secrets.token_urlsafe(32)
    plaintext = f"{KEY_PREFIX}{secret}"
    return plaintext, hash_key(plaintext)


def hash_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


class ApiKeyStore:
    """In-memory API-key registry for the Community Edition."""

    def __init__(self, keys: list[ApiKey] | None = None) -> None:
        self._by_hash: dict[str, ApiKey] = {k.key_hash: k for k in (keys or [])}

    def add(self, key: ApiKey) -> None:
        self._by_hash[key.key_hash] = key

    def authenticate(self, presented: str) -> ApiKey | None:
        """Look up a presented key in constant time with respect to the secret.

        The dict lookup is on the *hash*, so an attacker cannot learn anything
        from timing about which prefix was close. The explicit
        ``compare_digest`` guards the final confirmation.
        """
        if not presented or not presented.startswith(KEY_PREFIX):
            return None
        presented_hash = hash_key(presented)
        candidate = self._by_hash.get(presented_hash)
        if candidate is None:
            return None
        if not hmac.compare_digest(candidate.key_hash, presented_hash):
            return None
        return candidate

    def __len__(self) -> int:
        return len(self._by_hash)
