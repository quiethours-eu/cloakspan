"""Restoration safety — the security core.

These tests encode a vulnerability class found repeatedly during comparative
review.
If any of these fail, the product's central claim is false.
"""

from __future__ import annotations

from gateway.domain import RequestContext, Span
from gateway.restoration.engine import RestorationEngine
from gateway.transformations.engine import TransformationEngine
from gateway.transformations.tokens import (
    TokenMinter,
    TokenProvenance,
    canonicalize,
)
from gateway.vault.store import KeyRing, SurrogateVault

from .conftest import OTHER_TOKEN_KEY, VAULT_KEY

# A well-formed token of the current format that was never minted here: correct
# entity type, correct version, correct tag width, wrong provenance.
FORGED_TOKEN = "<PERSON:v1:deadbeefdeadbeefdeadbeefdeadbeef>"


def _span(text: str, entity_type: str = "EMAIL_ADDRESS") -> Span:
    return Span(start=0, end=len(text), entity_type=entity_type, text=text)


class TestConsistency:
    def test_same_value_maps_consistently_within_a_conversation(self, ctx, minter):
        prov = TokenProvenance()
        first = minter.mint(ctx, "PERSON", "Ilze Bērziņa", prov)
        second = minter.mint(ctx, "PERSON", "Ilze Bērziņa", prov)
        assert first.token == second.token

    def test_formatting_variants_collapse_to_one_token(self, ctx, minter):
        prov = TokenProvenance()
        a = minter.mint(ctx, "PERSON", "Ilze Bērziņa", prov)
        b = minter.mint(ctx, "PERSON", "ILZE  BĒRZIŅA", prov)
        assert a.token == b.token, "capitalisation/whitespace variants must share a token"

    def test_same_value_differs_across_tenants(self, ctx, other_tenant_ctx, minter):
        a = minter.mint(ctx, "PERSON", "Ilze", TokenProvenance())
        b = minter.mint(other_tenant_ctx, "PERSON", "Ilze", TokenProvenance())
        assert a.token != b.token, "cross-tenant correlation must not be possible"

    def test_same_value_differs_across_conversations(self, ctx, minter):
        other_conv = RequestContext(
            tenant_id=ctx.tenant_id,
            conversation_id="conv-2",
            request_id="req-9",
            api_key_id=ctx.api_key_id,
        )
        a = minter.mint(ctx, "PERSON", "Ilze", TokenProvenance())
        b = minter.mint(other_conv, "PERSON", "Ilze", TokenProvenance())
        assert a.token != b.token

    def test_tokens_are_not_sequential(self, ctx, minter):
        """The vulnerability enabler in every reviewed project.

        Sequential tokens let an attacker enumerate. Ours must not be
        predictable from one another.
        """
        prov = TokenProvenance()
        tokens = [minter.mint(ctx, "PERSON", f"Person {i}", prov).token for i in range(5)]
        assert len(set(tokens)) == 5
        for token in tokens:
            tag = token.split(":")[2].rstrip(">")
            assert not any(str(n) == tag for n in range(10))
            assert len(tag) == 32, "128-bit tag (SI-06)"


class TestAttackerInjectedTokens:
    """The headline attack: the user writes a token they were never given."""

    def test_fake_but_well_formed_token_is_not_restored(self, ctx, vault):
        restorer = RestorationEngine(vault)
        outcome = restorer.restore(ctx, f"Contact {FORGED_TOKEN} now", TokenProvenance())

        assert FORGED_TOKEN in outcome.text, "forged token must be left verbatim"
        assert outcome.restored == 0
        assert outcome.refused_not_minted == 1
        assert outcome.reasons() == {"not_minted": 1}

    def test_token_from_an_earlier_turn_is_not_replayed(self, ctx, minter, vault):
        """A *real* token, from this tenant and conversation, still fails.

        This is why the provenance set exists and the vault alone is not
        enough. The token below was legitimately minted -- just not by the
        request that is now trying to restore it.
        """
        transformer = TransformationEngine(minter, vault)
        turn_one = TokenProvenance()
        result = transformer.transform(ctx, "alice@acme.lv", [_span("alice@acme.lv")], turn_one)
        real_token = result.text
        assert real_token.startswith("<EMAIL_ADDRESS:")

        # The vault genuinely holds this token for this tenant+conversation.
        assert vault.get(ctx, real_token, "v1") == "alice@acme.lv"

        # A new request replays it. Fresh provenance -> refused.
        turn_two = TokenProvenance()
        outcome = RestorationEngine(vault).restore(ctx, f"Echo {real_token}", turn_two)

        assert outcome.restored == 0
        assert outcome.refused_not_minted == 1
        assert real_token in outcome.text
        assert "alice@acme.lv" not in outcome.text

    def test_malformed_tokens_are_not_restored(self, ctx, vault):
        restorer = RestorationEngine(vault)
        tag = "deadbeefdeadbeefdeadbeefdeadbeef"
        malformed = [
            "<PERSON:v1:>",
            "<PERSON:v1:xyz>",
            f"<PERSON:v1:{tag.upper()}>",  # upper case: not our alphabet
            f"<person:v1:{tag}>",  # lower-case entity type
            "<PERSON:v1:deadbeef>",  # too short
            f"<PERSON:v1:{tag}",  # unterminated
            f"PERSON:v1:{tag}>",  # no opening bracket
            f"<:v1:{tag}>",  # no entity type
            f"<PERSON:{tag}>",  # legacy v0 shape: no version
            f"<PERSON:v2:{tag}>",  # unknown format version
            f"<PERSON:V1:{tag}>",  # upper-case version marker
        ]
        for token in malformed:
            outcome = restorer.restore(ctx, f"text {token} text", TokenProvenance())
            assert outcome.restored == 0, f"{token!r} must not restore"
            assert token in outcome.text

    def test_whitespace_and_case_modified_tokens_are_not_restored(self, ctx, minter, vault):
        """A real token, mutated in ways a model or a user might produce.

        Each variant must fail ``TOKEN_PATTERN`` outright rather than being
        normalised into a match -- "helpfully" accepting near-misses is how a
        restoration path becomes forgiving enough to attack.
        """
        prov = TokenProvenance()
        real = minter.mint(ctx, "PERSON", "Ilze", prov).token
        vault.put(ctx, real, "Ilze", "v1")

        entity, version, tag = real[1:-1].split(":")
        variants = [
            f"< {entity}:{version}:{tag}>",
            f"<{entity} :{version}:{tag}>",
            f"<{entity}:{version}: {tag}>",
            f"<{entity}:{version}:{tag} >",
            f"<{entity.lower()}:{version}:{tag}>",
            f"<{entity}:{version}:{tag.upper()}>",
            f"<{entity}::{version}:{tag}>",
            f"<{entity}:{version}:{tag[:16]}​{tag[16:]}>",  # zero-width split
        ]
        for variant in variants:
            outcome = RestorationEngine(vault).restore(ctx, f"Hi {variant}", prov)
            assert outcome.restored == 0, f"{variant!r} must not restore"
            assert "Ilze" not in outcome.text

    def test_a_real_token_still_restores_when_surrounded_by_extra_brackets(
        self, ctx, minter, vault
    ):
        """``<<TOKEN>>`` **does** restore, and that is correct.

        Written down because it looks like a bypass and is not: the inner
        substring is a token this request genuinely minted, and the surrounding
        brackets are ordinary adjacent text. Refusing here would mean refusing
        any token a model chose to quote or emphasise, which breaks legitimate
        responses without closing anything -- the attacker's problem is
        producing a token in provenance, and decoration does not help them.
        """
        prov = TokenProvenance()
        real = minter.mint(ctx, "PERSON", "Ilze", prov).token
        vault.put(ctx, real, "Ilze", "v1")

        outcome = RestorationEngine(vault).restore(ctx, f"Hi <<{real}>>", prov)
        assert outcome.restored == 1
        assert outcome.text == "Hi <<Ilze>>"

    def test_hallucinated_token_shape_is_left_alone(self, ctx, vault):
        hallucinated = "<CUSTOMER_ID:v1:0123456789abcdef0123456789abcdef>"
        outcome = RestorationEngine(vault).restore(
            ctx, f"The model invented {hallucinated}.", TokenProvenance()
        )
        assert outcome.restored == 0
        assert hallucinated in outcome.text


class TestCrossTenantIsolation:
    def test_vault_does_not_serve_another_tenant(self, ctx, other_tenant_ctx, minter, vault):
        prov = TokenProvenance()
        surrogate = minter.mint(ctx, "EMAIL_ADDRESS", "alice@acme.lv", prov)
        vault.put(ctx, surrogate.token, "alice@acme.lv", surrogate.version)

        # Tenant B asks for tenant A's token. The AEAD is bound to the tenant,
        # so this cannot decrypt.
        assert vault.get(other_tenant_ctx, surrogate.token, surrogate.version) is None

    def test_restoration_cannot_cross_tenants_even_with_forged_provenance(
        self, ctx, other_tenant_ctx, minter, vault
    ):
        """Worst case: attacker somehow gets a valid token into provenance."""
        prov_a = TokenProvenance()
        surrogate = minter.mint(ctx, "EMAIL_ADDRESS", "alice@acme.lv", prov_a)
        vault.put(ctx, surrogate.token, "alice@acme.lv", surrogate.version)

        forged_prov = TokenProvenance()
        forged_prov.record(surrogate)

        outcome = RestorationEngine(vault).restore(
            other_tenant_ctx, f"Value: {surrogate.token}", forged_prov
        )
        assert outcome.restored == 0
        assert "alice@acme.lv" not in outcome.text

    def test_a_different_token_key_cannot_verify(self, ctx):
        """Tokens minted under one key must not validate under another."""
        good = TokenMinter(b"\x02" * 32)
        evil = TokenMinter(OTHER_TOKEN_KEY)
        surrogate = good.mint(ctx, "PERSON", "Ilze", TokenProvenance())
        assert good.verify(ctx, surrogate.token, canonicalize("Ilze"))
        assert not evil.verify(ctx, surrogate.token, canonicalize("Ilze"))


class TestExpiry:
    @staticmethod
    def _expiring_vault() -> SurrogateVault:
        return SurrogateVault(
            key_ring=KeyRing(keys={1: VAULT_KEY}, active_version=1), ttl_seconds=0
        )

    def test_mappings_expire(self, ctx, minter):
        vault = self._expiring_vault()
        surrogate = minter.mint(ctx, "PERSON", "Ilze", TokenProvenance())
        vault.put(ctx, surrogate.token, "Ilze", surrogate.version)
        assert vault.get(ctx, surrogate.token, surrogate.version) is None

    def test_expired_mapping_is_not_restored(self, ctx, minter):
        vault = self._expiring_vault()
        prov = TokenProvenance()
        surrogate = minter.mint(ctx, "PERSON", "Ilze", prov)
        vault.put(ctx, surrogate.token, "Ilze", surrogate.version)

        outcome = RestorationEngine(vault).restore(ctx, f"Hi {surrogate.token}", prov)
        assert outcome.restored == 0
        assert outcome.refused_unknown == 1
        assert outcome.reasons() == {"vault_miss": 1}
        assert "Ilze" not in outcome.text


class TestRoundTrip:
    def test_repeated_entities_restore_correctly(self, ctx, minter, vault):
        transformer = TransformationEngine(minter, vault)
        text = "Email alice@acme.lv, then alice@acme.lv again."
        spans = [
            Span(6, 19, "EMAIL_ADDRESS", "alice@acme.lv"),
            Span(26, 39, "EMAIL_ADDRESS", "alice@acme.lv"),
        ]
        prov = TokenProvenance()
        result = transformer.transform(ctx, text, spans, prov)

        assert "alice@acme.lv" not in result.text
        assert len(prov) == 1, "one distinct value -> one token"

        restored = RestorationEngine(vault).restore(ctx, result.text, prov)
        assert restored.text == text
        assert restored.restored == 2

    def test_offsets_are_not_corrupted_by_replacement(self, ctx, minter, vault):
        transformer = TransformationEngine(minter, vault)
        text = "a@b.lv and c@d.lv and e@f.lv"
        spans = [
            Span(0, 6, "EMAIL_ADDRESS", "a@b.lv"),
            Span(11, 17, "EMAIL_ADDRESS", "c@d.lv"),
            Span(22, 28, "EMAIL_ADDRESS", "e@f.lv"),
        ]
        prov = TokenProvenance()
        result = transformer.transform(ctx, text, spans, prov)

        for original in ("a@b.lv", "c@d.lv", "e@f.lv"):
            assert original not in result.text
        assert result.text.count("<EMAIL_ADDRESS:") == 3
        assert " and " in result.text

        restored = RestorationEngine(vault).restore(ctx, result.text, prov)
        assert restored.text == text
