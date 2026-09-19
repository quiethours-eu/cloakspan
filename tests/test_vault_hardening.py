"""Vault, key-ring, and token-derivation hardening.

These tests cover vault and key-ring edge cases that had previously not executed
under test:

* the AEAD binding, as distinct from the plaintext tenant comparison (SI-05)
* the token collision branch, which is the stated defence against T3 (SI-06)
* the length-prefixed HMAC encoding, which exists to prevent one specific
  forgery and was previously only tested indirectly (SI-07)
* key rotation and unconfigured key versions (SI-08)
* concurrent requests in one conversation (SI-16)

A defence with no failing-when-broken test is an aspiration.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from gateway.crypto import TOKEN_KEY_INFO, VAULT_KEY_INFO, derive_key
from gateway.domain import RequestContext, Span
from gateway.restoration.engine import RestorationEngine
from gateway.transformations.engine import TransformationEngine
from gateway.transformations.tokens import (
    TokenCollisionError,
    TokenMinter,
    TokenProvenance,
    length_prefixed,
)
from gateway.vault.store import (
    RECORD_FORMAT_VERSION,
    KeyRing,
    SurrogateVault,
    VaultKeyUnavailableError,
)

from .conftest import TOKEN_KEY, VAULT_KEY, VAULT_KEY_V2


def _ring(**keys: bytes) -> KeyRing:
    mapping = {int(name[1:]): key for name, key in keys.items()}
    return KeyRing(keys=mapping, active_version=max(mapping))


# ---------------------------------------------------------------------------
# SI-05 -- the cryptographic claim, not the behavioural one
# ---------------------------------------------------------------------------


class TestAeadBindingDoesTheIsolationWork:
    def test_relocated_blob_fails_to_decrypt_not_merely_compare(
        self, ctx, other_tenant_ctx, minter, vault
    ):
        """The threat model says isolation is cryptographic. Prove it.

        Every other cross-tenant test would still pass if the AAD were removed
        and only the plaintext ``tenant_id`` comparison remained. This one would
        not: it decrypts the raw record directly, with the right AAD and with
        the wrong one, and asserts the second fails at the cipher.
        """
        prov = TokenProvenance()
        surrogate = minter.mint(ctx, "EMAIL_ADDRESS", "alice@acme.lv", prov)
        vault.put(ctx, surrogate.token, "alice@acme.lv", surrogate.version)

        record = vault._backend.get(SurrogateVault._key(ctx, surrogate.token))  # noqa: SLF001
        assert record is not None
        nonce, ciphertext = record[3:15], record[15:]

        aead = vault.key_ring.aead(vault.key_ring.active_version)
        right = SurrogateVault._aad(  # noqa: SLF001
            ctx, surrogate.token, surrogate.version, 1, RECORD_FORMAT_VERSION
        )
        wrong = SurrogateVault._aad(  # noqa: SLF001
            other_tenant_ctx, surrogate.token, surrogate.version, 1, RECORD_FORMAT_VERSION
        )

        assert b"alice@acme.lv" in aead.decrypt(nonce, ciphertext, right)
        with pytest.raises(Exception):  # noqa: B017 - cryptography raises InvalidTag
            aead.decrypt(nonce, ciphertext, wrong)

    def test_blob_moved_to_another_tenants_key_is_not_served(
        self, ctx, other_tenant_ctx, minter, vault
    ):
        """Relocate the record inside the backend, then ask as the other tenant.

        Simulates a storage-layer bug or a backup restored into the wrong place:
        the ciphertext is physically addressable by tenant B and still yields
        nothing, because the AAD does not match.
        """
        prov = TokenProvenance()
        surrogate = minter.mint(ctx, "EMAIL_ADDRESS", "alice@acme.lv", prov)
        vault.put(ctx, surrogate.token, "alice@acme.lv", surrogate.version)

        backend = vault._backend  # noqa: SLF001
        record = backend.get(SurrogateVault._key(ctx, surrogate.token))  # noqa: SLF001
        backend.put(
            SurrogateVault._key(other_tenant_ctx, surrogate.token),  # noqa: SLF001
            record,
            2**31,
        )

        assert vault.get(other_tenant_ctx, surrogate.token, surrogate.version) is None

    def test_tampered_ciphertext_is_treated_as_absent(self, ctx, minter, vault):
        prov = TokenProvenance()
        surrogate = minter.mint(ctx, "PERSON", "Ilze", prov)
        vault.put(ctx, surrogate.token, "Ilze", surrogate.version)

        backend = vault._backend  # noqa: SLF001
        key = SurrogateVault._key(ctx, surrogate.token)  # noqa: SLF001
        record = bytearray(backend.get(key))
        record[-1] ^= 0xFF  # flip a bit in the GCM tag
        backend.put(key, bytes(record), 2**31)

        assert vault.get(ctx, surrogate.token, surrogate.version) is None

    def test_tampered_header_is_rejected(self, ctx, minter, vault):
        """The envelope is readable before decryption, so it is in the AAD.

        Editing the key version in the header must not let an attacker steer
        decryption; it must break authentication.
        """
        prov = TokenProvenance()
        surrogate = minter.mint(ctx, "PERSON", "Ilze", prov)
        vault.put(ctx, surrogate.token, "Ilze", surrogate.version)

        backend = vault._backend  # noqa: SLF001
        key = SurrogateVault._key(ctx, surrogate.token)  # noqa: SLF001
        record = bytearray(backend.get(key))
        record[0] = 99  # unsupported format version
        backend.put(key, bytes(record), 2**31)

        assert vault.get(ctx, surrogate.token, surrogate.version) is None
        assert vault.unknown_format_records == 1

    def test_token_version_is_bound_into_the_aad(self, ctx, minter, vault):
        """A record written for one token version must not read back under another."""
        prov = TokenProvenance()
        surrogate = minter.mint(ctx, "PERSON", "Ilze", prov)
        vault.put(ctx, surrogate.token, "Ilze", "v1")

        assert vault.get(ctx, surrogate.token, "v1") == "Ilze"
        assert vault.get(ctx, surrogate.token, "v9") is None


# ---------------------------------------------------------------------------
# SI-06 -- the collision branch
# ---------------------------------------------------------------------------


class TestTokenCollision:
    def test_distinct_values_with_the_same_tag_refuse_to_mint(self, ctx, monkeypatch):
        """Force the branch T3 is closed by, which real inputs never reach.

        Astronomically unlikely is not the same as unreachable, and a defence
        that has never run is a defence nobody has checked.
        """
        minter = TokenMinter(secret_key=TOKEN_KEY)
        monkeypatch.setattr(TokenMinter, "_tag", lambda *_args, **_kwargs: "f" * 32, raising=True)

        prov = TokenProvenance()
        minter.mint(ctx, "PERSON", "Ilze", prov)
        with pytest.raises(TokenCollisionError):
            minter.mint(ctx, "PERSON", "Jānis", prov)

    def test_same_value_under_a_forced_collision_still_reuses(self, ctx, monkeypatch):
        """Re-minting the *same* value is not a collision and must not raise."""
        minter = TokenMinter(secret_key=TOKEN_KEY)
        monkeypatch.setattr(TokenMinter, "_tag", lambda *_args, **_kwargs: "f" * 32, raising=True)
        prov = TokenProvenance()
        first = minter.mint(ctx, "PERSON", "Ilze", prov)
        second = minter.mint(ctx, "PERSON", "ILZE", prov)  # canonicalises the same
        assert first.token == second.token


# ---------------------------------------------------------------------------
# SI-07 -- the encoding that exists to prevent one specific forgery
# ---------------------------------------------------------------------------


class TestUnambiguousDerivation:
    def test_length_prefixing_distinguishes_ambiguous_splits(self):
        assert length_prefixed("ab", "c") != length_prefixed("a", "bc")

    def test_separator_injection_cannot_forge_another_context(self):
        """The attack length-prefixing exists to prevent.

        With naive ``tenant + SEP + conversation`` joining, a tenant id
        containing the separator collides with a different (tenant,
        conversation) pair -- and a collision here restores one customer's data
        into another customer's response.
        """
        minter = TokenMinter(secret_key=TOKEN_KEY)
        sneaky = RequestContext("acme\x00x", "y", "req-1", "key-1")
        honest = RequestContext("acme", "x\x00y", "req-2", "key-2")

        a = minter.mint(sneaky, "PERSON", "Ilze", TokenProvenance())
        b = minter.mint(honest, "PERSON", "Ilze", TokenProvenance())
        assert a.token != b.token

    def test_entity_type_is_part_of_the_derivation(self, ctx, minter):
        a = minter.mint(ctx, "PERSON", "Ilze", TokenProvenance())
        b = minter.mint(ctx, "ORG", "Ilze", TokenProvenance())
        assert a.tag != b.tag


# ---------------------------------------------------------------------------
# SI-08 -- key ring, rotation, nonces
# ---------------------------------------------------------------------------


class TestKeyRotation:
    def test_records_written_under_the_old_key_still_read_after_rotation(self, ctx, minter):
        """The whole point: rotate without a re-encryption pass and without loss."""
        before = SurrogateVault(key_ring=_ring(v1=VAULT_KEY))
        surrogate = minter.mint(ctx, "PERSON", "Ilze", TokenProvenance())
        before.put(ctx, surrogate.token, "Ilze", surrogate.version)
        record = before._backend.get(SurrogateVault._key(ctx, surrogate.token))  # noqa: SLF001

        after = SurrogateVault(key_ring=_ring(v1=VAULT_KEY, v2=VAULT_KEY_V2))
        after._backend.put(  # noqa: SLF001
            SurrogateVault._key(ctx, surrogate.token),
            record,
            2**31,  # noqa: SLF001
        )

        assert after.key_ring.active_version == 2
        assert after.get(ctx, surrogate.token, surrogate.version) == "Ilze"

    def test_new_records_are_written_under_the_active_version(self, ctx, minter):
        vault = SurrogateVault(key_ring=_ring(v1=VAULT_KEY, v2=VAULT_KEY_V2))
        surrogate = minter.mint(ctx, "PERSON", "Ilze", TokenProvenance())
        vault.put(ctx, surrogate.token, "Ilze", surrogate.version)

        record = vault._backend.get(SurrogateVault._key(ctx, surrogate.token))  # noqa: SLF001
        assert record[0] == RECORD_FORMAT_VERSION
        assert int.from_bytes(record[1:3], "big") == 2

    def test_removing_a_key_still_in_use_is_loud_not_silent(self, ctx, minter):
        """The failure the envelope exists to make visible.

        Before versioning, rotating the key made every mapping undecryptable and
        the operator saw *nothing* -- tokens just stopped restoring, which is
        indistinguishable from an attack. Now it raises.
        """
        with_v2 = SurrogateVault(key_ring=_ring(v1=VAULT_KEY, v2=VAULT_KEY_V2))
        surrogate = minter.mint(ctx, "PERSON", "Ilze", TokenProvenance())
        with_v2.put(ctx, surrogate.token, "Ilze", surrogate.version)
        record = with_v2._backend.get(SurrogateVault._key(ctx, surrogate.token))  # noqa: SLF001

        without_v2 = SurrogateVault(key_ring=_ring(v1=VAULT_KEY))
        without_v2._backend.put(  # noqa: SLF001
            SurrogateVault._key(ctx, surrogate.token),
            record,
            2**31,  # noqa: SLF001
        )

        with pytest.raises(VaultKeyUnavailableError):
            without_v2.get(ctx, surrogate.token, surrogate.version)

    def test_restoration_fails_closed_on_a_missing_key(self, ctx, minter):
        """A missing key must refuse, and be counted under its own reason."""
        with_v2 = SurrogateVault(key_ring=_ring(v1=VAULT_KEY, v2=VAULT_KEY_V2))
        prov = TokenProvenance()
        surrogate = minter.mint(ctx, "PERSON", "Ilze", prov)
        with_v2.put(ctx, surrogate.token, "Ilze", surrogate.version)
        record = with_v2._backend.get(SurrogateVault._key(ctx, surrogate.token))  # noqa: SLF001

        without_v2 = SurrogateVault(key_ring=_ring(v1=VAULT_KEY))
        without_v2._backend.put(  # noqa: SLF001
            SurrogateVault._key(ctx, surrogate.token),
            record,
            2**31,  # noqa: SLF001
        )

        outcome = RestorationEngine(without_v2).restore(ctx, f"Hi {surrogate.token}", prov)
        assert outcome.restored == 0
        assert outcome.reasons() == {"key_unavailable": 1}
        assert "Ilze" not in outcome.text

    def test_key_ring_rejects_an_active_version_it_does_not_hold(self):
        with pytest.raises(ValueError, match="active key version"):
            KeyRing(keys={1: VAULT_KEY}, active_version=7)

    def test_key_ring_rejects_a_wrong_length_key(self):
        with pytest.raises(ValueError, match="32 bytes"):
            KeyRing(keys={1: b"short"}, active_version=1)


class TestNonces:
    def test_nonces_are_unique_across_many_encryptions(self, ctx, minter):
        """GCM nonce reuse under one key leaks the authentication key.

        Not a probabilistic assertion about 96-bit randomness -- a check that
        nothing in ``put`` derives or caches the nonce.
        """
        vault = SurrogateVault(key_ring=_ring(v1=VAULT_KEY))
        prov = TokenProvenance()
        nonces = set()
        for index in range(250):
            surrogate = minter.mint(ctx, "PERSON", f"Person {index}", prov)
            vault.put(ctx, surrogate.token, f"Person {index}", surrogate.version)
            record = vault._backend.get(  # noqa: SLF001
                SurrogateVault._key(ctx, surrogate.token)  # noqa: SLF001
            )
            nonces.add(record[3:15])
        assert len(nonces) == 250

    def test_the_same_value_re_encrypts_under_a_fresh_nonce(self, ctx, minter):
        vault = SurrogateVault(key_ring=_ring(v1=VAULT_KEY))
        surrogate = minter.mint(ctx, "PERSON", "Ilze", TokenProvenance())
        key = SurrogateVault._key(ctx, surrogate.token)  # noqa: SLF001

        vault.put(ctx, surrogate.token, "Ilze", surrogate.version)
        first = vault._backend.get(key)[3:15]  # noqa: SLF001
        vault.put(ctx, surrogate.token, "Ilze", surrogate.version)
        second = vault._backend.get(key)[3:15]  # noqa: SLF001

        assert first != second


class TestKeyDerivation:
    def test_one_root_secret_yields_unrelated_vault_and_token_keys(self):
        """Guards the operator mistake of setting both variables to one value."""
        root = b"\x07" * 32
        assert derive_key(root, VAULT_KEY_INFO) != derive_key(root, TOKEN_KEY_INFO)

    def test_derivation_is_deterministic_across_restarts(self):
        root = b"\x07" * 32
        assert derive_key(root, VAULT_KEY_INFO) == derive_key(root, VAULT_KEY_INFO)

    def test_short_root_secret_is_refused(self):
        with pytest.raises(ValueError, match="at least 32 bytes"):
            derive_key(b"too short", VAULT_KEY_INFO)


# ---------------------------------------------------------------------------
# SI-13 / ADR-0013 -- deletion
# ---------------------------------------------------------------------------


class TestDeletion:
    def test_deleting_a_conversation_removes_only_that_conversation(self, ctx, minter):
        vault = SurrogateVault(key_ring=_ring(v1=VAULT_KEY))
        other_conv = RequestContext(ctx.tenant_id, "conv-2", "req-9", ctx.api_key_id)

        kept = minter.mint(other_conv, "PERSON", "Jānis", TokenProvenance())
        vault.put(other_conv, kept.token, "Jānis", kept.version)
        for name in ("Ilze", "Anna"):
            surrogate = minter.mint(ctx, "PERSON", name, TokenProvenance())
            vault.put(ctx, surrogate.token, name, surrogate.version)

        assert vault.delete_conversation(ctx) == 2
        assert vault.get(other_conv, kept.token, kept.version) == "Jānis"

    def test_purge_expired_reports_a_count(self, ctx, minter):
        vault = SurrogateVault(key_ring=_ring(v1=VAULT_KEY), ttl_seconds=0)
        for name in ("Ilze", "Anna"):
            surrogate = minter.mint(ctx, "PERSON", name, TokenProvenance())
            vault.put(ctx, surrogate.token, name, surrogate.version)
        assert vault.purge_expired() == 2


# ---------------------------------------------------------------------------
# SI-16 -- concurrency
# ---------------------------------------------------------------------------


class TestConcurrency:
    def test_concurrent_requests_in_one_conversation_do_not_share_provenance(
        self, ctx, minter, vault
    ):
        """Same value, same conversation, two requests at once.

        Both must mint the same token (determinism is the multi-turn promise)
        and each must restore only through its own provenance set.
        """
        transformer = TransformationEngine(minter, vault)
        restorer = RestorationEngine(vault)
        text = "alice@acme.lv"
        span = Span(0, len(text), "EMAIL_ADDRESS", text)

        def one_request() -> tuple[str, TokenProvenance]:
            prov = TokenProvenance()
            result = transformer.transform(ctx, text, [span], prov)
            return result.text, prov

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: one_request(), range(16)))

        tokens = {token for token, _ in results}
        assert len(tokens) == 1, "determinism: one value, one token"

        for token, prov in results:
            assert restorer.restore(ctx, token, prov).text == text

        foreign = TokenProvenance()
        only_token = next(iter(tokens))
        assert restorer.restore(ctx, only_token, foreign).restored == 0

    def test_concurrent_cross_tenant_requests_do_not_interfere(
        self, ctx, other_tenant_ctx, minter, vault
    ):
        transformer = TransformationEngine(minter, vault)
        text = "alice@acme.lv"
        span = Span(0, len(text), "EMAIL_ADDRESS", text)

        def one(context: RequestContext) -> str:
            return transformer.transform(context, text, [span], TokenProvenance()).text

        with ThreadPoolExecutor(max_workers=8) as pool:
            contexts = [ctx, other_tenant_ctx] * 8
            tokens = list(pool.map(one, contexts))

        assert len(set(tokens)) == 2, "one token per tenant, and never shared"
        assert vault.get(ctx, tokens[0], "v1") == text
        assert vault.get(ctx, tokens[1], "v1") is None


# ---------------------------------------------------------------------------
# SI-04 -- the scope validation that had no test
# ---------------------------------------------------------------------------


class TestRequestContextValidation:
    @pytest.mark.parametrize("field", ["tenant_id", "conversation_id", "request_id", "api_key_id"])
    def test_empty_scope_field_is_refused(self, field):
        values = {
            "tenant_id": "t",
            "conversation_id": "c",
            "request_id": "r",
            "api_key_id": "k",
        }
        values[field] = ""
        with pytest.raises(ValueError, match=field):
            RequestContext(**values)
