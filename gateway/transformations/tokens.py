"""Typed reversible surrogate tokens.

This module exists because every comparable open-source implementation we
reviewed gets this wrong in the same way, and the failure is exploitable.

## The vulnerability we are designing against

Two of the implementations reviewed at pinned commits mint *sequential* tokens
(``<PERSON_1>``, ``<PERSON_2>``, ...) and then restore **any** token they
recognise in the model output, looked up purely by token string.

They are not named here because the flaw is exploitable as described below and
their maintainers have not been contacted. The private review record retains
the necessary provenance for coordinated disclosure.

That combination is exploitable. A user who has seen ``<PERSON_1>`` in one turn
can write ``<PERSON_2>`` into their next prompt and the gateway will helpfully
substitute a real value they were never shown. The attacker does not need to
guess a secret -- they only need to count.

## The two independent defences

**1. Unguessable token identity.** The numeric suffix is replaced by an HMAC
tag derived from ``(tenant_id, conversation_id, entity_type, canonical_value,
token_version)`` under a secret key. An attacker cannot enumerate tokens
because they cannot compute the tag without the key.

**2. Per-request provenance.** Even a *legitimate* token -- one this gateway
really did mint, in this conversation -- is only restored if it appears in the
provenance set of tokens minted while processing **this** request. A token
echoed back from an earlier turn by an attacker is not in that set and is not
restored.

Either defence alone is insufficient:

* HMAC alone still allows replay of a token the user legitimately saw earlier.
* Provenance alone still allows an attacker to guess ``<PERSON_2>`` in the very
  turn where the gateway happens to have minted it.

Together they close both paths, which is why both are implemented here and both
are tested (``tests/test_restoration_safety.py``).

## Token format and versioning

``<ENTITY_TYPE:v1:TAG>`` where ``TAG`` is 32 lower-case hex characters -- 128
bits. The version sits *inside* the token so that the tag width, the derivation,
and the canonicalisation rule can all change without any ambiguity about which
rule produced a given token. A token whose version this build does not know
simply fails ``TOKEN_PATTERN`` and is left verbatim, which is the safe default.

The version is also bound into the HMAC input and into the vault AAD, so a token
cannot be reinterpreted under a different format's rules.

**On the tag width.** 128 bits is the default required by
``docs/security-invariants.md`` SI-06. The earlier implementation used 64 bits on
the argument that this is a *forgery* problem rather than a collision problem --
an attacker must produce a tag matching a specific (tenant, conversation, entity,
value) tuple without the key, *and* land it inside the single request that mints
it, because provenance refuses everything else. That argument is not wrong, but
SI-06 permits a smaller value only with written independent-reviewer approval,
which does not exist. The cost of 128 bits is 16 characters per token, so we pay
it and leave the question open for the reviewer. See
``docs/adr/0011-token-format-and-versioning.md``.

Accidental collisions are additionally guarded by an explicit check in
``TokenMinter.mint`` rather than assumed away.

No custom cryptography: HMAC-SHA256 from ``hmac``/``hashlib`` (stdlib), used in
the standard way. See security invariant SI-09 in docs/security-invariants.md.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import unicodedata
from dataclasses import dataclass, field

from gateway.domain import RequestContext

# Domain separation for the HMAC input. Changing this string invalidates every
# token ever minted, which is exactly what it is for: it guarantees a tag from
# this product cannot be confused with a tag from any other HMAC use of the same
# key material.
_HMAC_DOMAIN = "quiethours/token"


@dataclass(frozen=True, slots=True)
class TokenFormat:
    """One version of the token format."""

    version: str
    tag_bytes: int

    @property
    def tag_hex_length(self) -> int:
        return self.tag_bytes * 2


#: Every format this build can mint or restore. A token naming any other version
#: does not match ``TOKEN_PATTERN`` and is therefore never restored.
TOKEN_FORMATS: dict[str, TokenFormat] = {
    "v1": TokenFormat(version="v1", tag_bytes=16),  # 128-bit tag
}

#: The format new tokens are minted in.
ACTIVE_TOKEN_FORMAT = TOKEN_FORMATS["v1"]

# A minted token looks like: <PERSON:v1:3f9a1c7d2b8e4f60a1b2c3d4e5f60718>
#
# The entity type is upper-case ASCII with underscores; the version is one of
# TOKEN_FORMATS; the tag is lower-case hex of that version's width. Anchored and
# bounded so a malformed, partial, case-modified, or whitespace-padded token
# cannot match -- fuzzed in tests/test_properties_and_fuzz.py and asserted
# directly in tests/test_restoration_safety.py.
TOKEN_PATTERN = re.compile(r"<([A-Z][A-Z0-9_]{0,63}):(v1):([0-9a-f]{32})>")


def canonicalize(value: str) -> str:
    """Normalise a detected value so formatting variants collapse to one token.

    "Ilze Bērziņa", "ILZE BĒRZIŅA", and "Ilze  Bērziņa" must map to the same
    token, or the model sees three different people and our consistency promise
    is broken.

    NFKC first, because an attacker can otherwise evade detection *and* split
    consistency using compatibility characters (fullwidth Latin, ligatures).
    Unicode normalisation happens here and in the detection stage; doing it in
    both places is intentional -- detection needs it to find the value at all,
    and canonicalisation needs it to key the vault.

    Casefold (not lower) because casefold handles non-ASCII correctly.

    This rule is part of the token format: changing it changes every token for
    the same input, which is why it is versioned alongside the tag width.
    """
    normalized = unicodedata.normalize("NFKC", value)
    collapsed = " ".join(normalized.split())
    return collapsed.casefold()


def length_prefixed(*parts: str) -> bytes:
    """Serialise ``parts`` unambiguously for use as a MAC or AEAD input.

    Each part is UTF-8 encoded, prefixed with its byte length, and NUL-joined::

        ("acme", "conv42") -> b"4:acme\\x006:conv42"

    Raw concatenation would be ambiguous: ``("ab", "c")`` and ``("a", "bc")``
    produce the same message, so a tenant named ``acme\\x00x`` could collide with
    tenant ``acme`` in conversation ``x`` -- and a collision here restores one
    customer's data into another customer's response.

    This is security invariant SI-07, and it is the property most likely to be
    quietly broken by a refactor that "simplifies" the join. It is asserted
    directly by ``test_separator_injection_cannot_forge_another_context``.
    """
    return b"\x00".join(
        f"{len(encoded)}:".encode() + encoded for encoded in (p.encode("utf-8") for p in parts)
    )


@dataclass(frozen=True, slots=True)
class SurrogateToken:
    """A minted token plus everything needed to reason about it."""

    token: str
    entity_type: str
    tag: str
    canonical_value: str
    original_value: str
    version: str = ACTIVE_TOKEN_FORMAT.version


class TokenCollisionError(Exception):
    """Raised when two distinct values would produce the same token tag."""


class TokenMinter:
    """Mints typed, unguessable, conversation-scoped tokens.

    One instance per process; the key comes from configuration. The minter
    holds no per-request state -- state lives in :class:`TokenProvenance`,
    which is created fresh for each request.
    """

    def __init__(self, secret_key: bytes, token_format: TokenFormat = ACTIVE_TOKEN_FORMAT) -> None:
        if not isinstance(secret_key, bytes) or len(secret_key) < 32:
            raise ValueError("token secret key must be at least 32 bytes")
        self._key = secret_key
        self._format = token_format

    @property
    def token_version(self) -> str:
        return self._format.version

    def _tag(
        self,
        ctx: RequestContext,
        entity_type: str,
        canonical_value: str,
        token_version: str,
    ) -> str:
        """Derive the unguessable tag.

        Domain-separated and length-prefixed -- see :func:`length_prefixed` for
        why the encoding matters. The token version is part of the input so that
        the same value under two format versions yields unrelated tags.
        """
        message = length_prefixed(
            _HMAC_DOMAIN,
            token_version,
            ctx.tenant_id,
            ctx.conversation_id,
            entity_type,
            canonical_value,
        )
        digest = hmac.new(self._key, message, hashlib.sha256).digest()
        tag_bytes = TOKEN_FORMATS[token_version].tag_bytes
        return digest[:tag_bytes].hex()

    def mint(
        self,
        ctx: RequestContext,
        entity_type: str,
        original_value: str,
        provenance: TokenProvenance,
    ) -> SurrogateToken:
        """Mint (or re-use) the token for ``original_value``.

        Deterministic: the same value in the same conversation always yields the
        same token, which is what lets the model reason about identity across a
        multi-turn conversation. Different tenant or different conversation
        yields a different token, which is what prevents cross-context
        correlation.
        """
        entity_type = entity_type.upper()
        version = self._format.version
        canonical = canonicalize(original_value)
        tag = self._tag(ctx, entity_type, canonical, version)
        token = f"<{entity_type}:{version}:{tag}>"

        existing = provenance.lookup(token)
        if existing is not None:
            if existing.canonical_value != canonical:
                # Two different values produced the same tag. Astronomically
                # unlikely, but we refuse rather than silently corrupt: a
                # collision here would restore the wrong person's data.
                raise TokenCollisionError(
                    f"tag collision for entity type {entity_type}; refusing to mint"
                )
            return existing

        surrogate = SurrogateToken(
            token=token,
            entity_type=entity_type,
            tag=tag,
            canonical_value=canonical,
            original_value=original_value,
            version=version,
        )
        provenance.record(surrogate)
        return surrogate

    def verify(self, ctx: RequestContext, token: str, canonical_value: str) -> bool:
        """Constant-time check that ``token`` is authentic for this context.

        **Not on the request path.** This is a test and debugging affordance,
        called only from ``tests/test_restoration_safety.py``.

        The docstring used to describe it as "defence in depth", implying a
        third runtime layer behind provenance and the vault. There is no such
        layer: `RestorationEngine` never calls this. The property it checks is
        genuinely enforced, but by the vault's AEAD additional authenticated
        data, which binds tenant, conversation, token, and version into the
        decryption itself — a misdirected read produces undecryptable bytes
        rather than failing a comparison we wrote.

        Describing a control as present when only its equivalent is present is
        the kind of claim an assessor checks by grepping for call sites, so it
        is corrected here rather than defended.
        """
        match = TOKEN_PATTERN.fullmatch(token)
        if match is None:
            return False
        entity_type, version, tag = match.group(1), match.group(2), match.group(3)
        if version not in TOKEN_FORMATS:
            return False
        expected = self._tag(ctx, entity_type, canonical_value, version)
        return hmac.compare_digest(tag, expected)


@dataclass(slots=True)
class TokenProvenance:
    """The set of tokens this pipeline minted while handling one request.

    This is the authority for restoration. A token that is not in here is not
    restored -- no matter how well-formed it looks, and no matter that it may be
    a real token from an earlier turn in the same conversation.

    Created fresh per request. Never shared across requests, never persisted.
    Persisting one, or keying it by conversation instead of by request, would
    defeat security invariant SI-03 without touching the restoration code --
    see docs/adr/0014-retry-cancellation-and-provenance.md.
    """

    _by_token: dict[str, SurrogateToken] = field(default_factory=dict)

    def record(self, surrogate: SurrogateToken) -> None:
        self._by_token[surrogate.token] = surrogate

    def lookup(self, token: str) -> SurrogateToken | None:
        return self._by_token.get(token)

    def was_minted_here(self, token: str) -> bool:
        return token in self._by_token

    def tokens(self) -> list[str]:
        return list(self._by_token)

    def __len__(self) -> int:
        return len(self._by_token)
