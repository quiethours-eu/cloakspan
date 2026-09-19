"""Leakage regression suite.

The single question this suite answers: **did the original sensitive value ever
reach the provider?**

It is answered by inspecting `MockProvider.received` — the exact payload the
provider was handed. Asserting on the gateway's *own* report of what it did
would be circular; asserting on what the provider actually received is not.

Every test here is a release gate. A failure means the product's core claim is
false for that input class.
"""

from __future__ import annotations

import json

import pytest

from gateway.inspection.pipeline import PolicyBlockedError
from tests.conftest import VALID_LT_CODE, VALID_LV_CODE


def payload(content: str, model: str = "gpt-4o-mini") -> dict:
    return {"model": model, "messages": [{"role": "user", "content": content}]}


def provider_saw(provider) -> str:
    """Everything the provider received, flattened, for substring assertions."""
    return json.dumps(provider.received, ensure_ascii=False)


class TestSecretsNeverReachProvider:
    @pytest.mark.parametrize(
        "secret",
        [
            "AKIAIOSFODNN7EXAMPLE",
            "ASIAIOSFODNN7EXAMPLE",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        ],
    )
    async def test_secret_is_blocked_and_never_forwarded(
        self, pipeline, ctx, mock_provider, secret
    ):
        with pytest.raises(PolicyBlockedError):
            await pipeline.process(ctx, payload(f"Here is my credential: {secret}"))

        assert mock_provider.received == [], "a blocked request must not reach any provider"

    async def test_private_key_is_blocked(self, pipeline, ctx, mock_provider):
        key = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEAxGZ8f2qkT9vN3pQ7rY1sL0mW4dK6bH8cV5nR2tJ9uX3wZ0aB\n"
            "-----END RSA PRIVATE KEY-----"
        )
        with pytest.raises(PolicyBlockedError):
            await pipeline.process(ctx, payload(f"Deploy with:\n{key}"))
        assert mock_provider.received == []


class TestPseudonymisationPreventsLeakage:
    async def test_email_does_not_reach_provider_in_original_form(
        self, pipeline, ctx, mock_provider
    ):
        result = await pipeline.process(ctx, payload("Write to alice@acme.lv about the invoice."))

        assert "alice@acme.lv" not in provider_saw(mock_provider)
        assert "<EMAIL_ADDRESS:" in provider_saw(mock_provider)
        assert result.decision_action == "transform"

    async def test_iban_does_not_reach_provider(self, pipeline, ctx, mock_provider):
        # A structurally valid Latvian IBAN (mod-97 correct).
        iban = "LV80BANK0000435195001"
        await pipeline.process(ctx, payload(f"Transfer to {iban} please."))
        assert iban not in provider_saw(mock_provider)

    async def test_payment_card_does_not_reach_provider(self, pipeline, ctx, mock_provider):
        card = "4111111111111111"  # Luhn-valid test number
        await pipeline.process(ctx, payload(f"Charge card {card}."))
        assert card not in provider_saw(mock_provider)

    async def test_repeated_value_is_consistently_replaced(self, pipeline, ctx, mock_provider):
        await pipeline.process(
            ctx, payload("Email alice@acme.lv. Remind me: alice@acme.lv is the contact.")
        )
        saw = provider_saw(mock_provider)
        assert "alice@acme.lv" not in saw
        assert saw.count("<EMAIL_ADDRESS:") == 2


class TestLocalRouting:
    async def test_baltic_id_routes_to_local_and_not_external(
        self, pipeline, ctx, mock_provider, local_provider
    ):
        result = await pipeline.process(
            ctx, payload(f"The client's personal code is {VALID_LV_CODE}.")
        )

        assert result.decision_action == "route_local"
        assert result.provider == "local"
        assert mock_provider.received == [], "must not reach the external destination"
        assert local_provider.received, "must reach the local destination"

    async def test_baltic_id_is_still_pseudonymised_when_routed_locally(
        self, pipeline, ctx, local_provider
    ):
        """Local routing is not a licence to send raw identifiers.

        Even the local model gets tokens. Defence in depth: 'local' may be a
        shared internal endpoint, and its logs are still logs.
        """
        await pipeline.process(ctx, payload(f"Personal code {VALID_LV_CODE}."))
        assert VALID_LV_CODE not in provider_saw(local_provider)


class TestCustomerDefinedData:
    async def test_dictionary_term_does_not_leak(self, ctx, policy, vault, minter, audit_sink):
        from gateway.detectors.deterministic import default_detectors
        from gateway.inspection.pipeline import SecurityPipeline
        from gateway.restoration.engine import RestorationEngine
        from gateway.routing.base import MockProvider
        from gateway.transformations.engine import TransformationEngine
        from recognizers.custom.customer_rules import DictionaryDetector

        provider = MockProvider()
        pipeline = SecurityPipeline(
            detectors=[*default_detectors(), DictionaryDetector(["Project Aurora"])],
            policy=policy,
            transformer=TransformationEngine(minter, vault),
            restorer=RestorationEngine(vault),
            providers={"mock": provider, "local": MockProvider()},
            audit_sink=audit_sink,
        )

        await pipeline.process(ctx, payload("Summarise the Project Aurora roadmap."))
        assert "Project Aurora" not in provider_saw(provider)
        assert "<CUSTOMER_TERM:" in provider_saw(provider)

    async def test_custom_regex_term_does_not_leak(self, ctx, policy, vault, minter, audit_sink):
        from gateway.detectors.deterministic import default_detectors
        from gateway.inspection.pipeline import SecurityPipeline
        from gateway.restoration.engine import RestorationEngine
        from gateway.routing.base import MockProvider
        from gateway.transformations.engine import TransformationEngine
        from recognizers.custom.customer_rules import CustomRegexDetector

        provider = MockProvider()
        pipeline = SecurityPipeline(
            detectors=[
                *default_detectors(),
                CustomRegexDetector(r"AUR-[0-9]{6}", "CUSTOMER_TERM"),
            ],
            policy=policy,
            transformer=TransformationEngine(minter, vault),
            restorer=RestorationEngine(vault),
            providers={"mock": provider, "local": MockProvider()},
            audit_sink=audit_sink,
        )

        await pipeline.process(ctx, payload("Check contract AUR-123456 status."))
        assert "AUR-123456" not in provider_saw(provider)


class TestUnicodeEvasion:
    async def test_fullwidth_digits_do_not_evade_detection(self, pipeline, ctx, mock_provider):
        """Fullwidth digits render like ASCII to a human but do not match [0-9].

        NFKC normalisation before detection is what closes this. Without it,
        an attacker (or a careless copy-paste from a CJK document) bypasses
        every numeric detector we own.
        """
        fullwidth = VALID_LT_CODE.translate({ord(str(d)): chr(0xFF10 + d) for d in range(10)})
        assert fullwidth != VALID_LT_CODE

        await pipeline.process(ctx, payload(f"Code: {fullwidth}"))
        saw = provider_saw(mock_provider)
        assert fullwidth not in saw
        assert VALID_LT_CODE not in saw

    async def test_undetected_text_is_forwarded_byte_identical(self, pipeline, ctx, mock_provider):
        """SI-17. This assertion is the inverse of what it used to be.

        The earlier design normalised the text and forwarded the *normalised*
        text, so this test asserted that ``ＨＥＲＥ`` arrived as ``HERE``. That
        bought "the provider only sees what we inspected" by silently rewriting
        the customer's content -- a transformation they could not see and could
        not have consented to.

        Phase 4 replaced it with a detection *view* plus an offset map, so
        detection still runs on normalised text while the provider receives the
        client's bytes unchanged. Both invariants now hold at once: every index
        of the original is covered by the map, so "unchanged" does not mean
        "unscanned".
        """
        original = "Nothing sensitive ＨＥＲＥ"
        await pipeline.process(ctx, payload(original))
        saw = provider_saw(mock_provider)

        assert original in saw, "undetected text must reach the provider unchanged"
        assert "HERE" not in saw, "the gateway must not silently rewrite customer text"

    async def test_cyrillic_homoglyph_does_not_evade_detection(self, pipeline, ctx, mock_provider):
        """The attack NFKC alone could never catch.

        ``З`` (U+0417) is not a compatibility character, so NFKC leaves it
        alone -- which is why this evaded every numeric detector before
        confusable folding existed.
        """
        homoglyph = VALID_LV_CODE.replace("3", "З", 1)
        assert homoglyph != VALID_LV_CODE

        await pipeline.process(ctx, payload(f"Kods: {homoglyph}"))
        saw = provider_saw(mock_provider)
        assert homoglyph not in saw, "the homoglyph form must be replaced"
        assert VALID_LV_CODE not in saw

    async def test_zero_width_insertion_does_not_evade_detection(
        self, pipeline, ctx, mock_provider
    ):
        """An invisible character between digits used to break every match.

        The replacement must also *remove* the zero-width characters: leaving
        them beside the token would tell an attacker their insertion survived.
        """
        split = VALID_LV_CODE[:4] + "​" + VALID_LV_CODE[4:]

        await pipeline.process(ctx, payload(f"Kods: {split}"))
        saw = provider_saw(mock_provider)
        assert VALID_LV_CODE not in saw
        assert "​" not in saw, "invisible characters must go with the span"


class TestFailClosed:
    async def test_non_text_content_is_refused_not_forwarded(self, pipeline, ctx, mock_provider):
        from gateway.inspection.pipeline import DetectionError

        multimodal = {
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "alice@acme.lv"}],
                }
            ],
        }
        with pytest.raises(DetectionError):
            await pipeline.process(ctx, multimodal)
        assert mock_provider.received == []

    async def test_oversized_request_is_refused(self, pipeline, ctx, mock_provider):
        from gateway.inspection.pipeline import DetectionError

        with pytest.raises(DetectionError):
            await pipeline.process(ctx, payload("x" * 300_000))
        assert mock_provider.received == []
