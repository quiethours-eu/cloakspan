"""Key derivation.

The operator supplies a **root secret**, not a key. Working keys are derived
from it with HKDF-SHA256 under a distinct ``info`` string per purpose, so that
an operator who sets ``SAG_VAULT_KEY`` and ``SAG_TOKEN_KEY`` to the same value
still gets two unrelated keys.

That mistake is easy to make and invisible when made: nothing would fail, no
test would go red, and the vault key and the token key would be identical --
which means anyone who learns one learns the other. Domain separation costs one
function call and removes the failure mode entirely.

No custom cryptography: HKDF from ``cryptography.hazmat.primitives.kdf.hkdf``
(security invariant SI-09). See docs/adr/0012-vault-record-envelope-and-key-rotation.md.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

#: Minimum accepted root-secret length. Shorter input is a configuration error,
#: not something to pad or truncate silently.
MIN_ROOT_SECRET_BYTES = 32

VAULT_KEY_INFO = b"quiethours/vault/v1"
TOKEN_KEY_INFO = b"quiethours/token/v1"


def derive_key(root_secret: bytes, info: bytes, length: int = 32) -> bytes:
    """Derive a working key from an operator-supplied root secret.

    ``info`` provides domain separation. ``salt`` is deliberately ``None``:
    HKDF's salt is optional and its value must be reproducible across restarts
    for the derived key to be stable, so a random salt would be wrong here and a
    fixed one adds nothing over the ``info`` string.
    """
    if not isinstance(root_secret, bytes):
        raise TypeError("root secret must be bytes")
    if len(root_secret) < MIN_ROOT_SECRET_BYTES:
        raise ValueError(
            f"root secret must be at least {MIN_ROOT_SECRET_BYTES} bytes; got {len(root_secret)}"
        )
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(root_secret)
