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
import re
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

from gateway.config import Settings, build_pipeline
from gateway.detectors.ner import NerDetector
from gateway.inspection.pipeline import DetectionError, PolicyBlockedError
from gateway.policy.local_routing import LocalRouting, LocalRoutingViolation
from gateway.routing.base import ProviderError
from tests.conftest import VALID_LT_CODE, VALID_LV_CODE


def payload(content: str, model: str = "gpt-4o-mini") -> dict:
    return {"model": model, "messages": [{"role": "user", "content": content}]}


def provider_saw(provider) -> str:
    """Everything the provider received, flattened, for substring assertions."""
    return json.dumps(provider.received, ensure_ascii=False)


#: A message with nothing in it for any detector to find.
CLEAN_MESSAGE = {"role": "user", "content": "Summarise the thread"}


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

    async def test_uninspected_role_is_refused_not_forwarded(
        self, pipeline, ctx, mock_provider, local_provider
    ):
        """SI-01 on the library path.

        The HTTP schema refuses a role it does not know with 422. A direct
        caller of the pipeline has no schema in front of it, and inspection used
        to skip such a message while the outbound payload still carried it --
        unscanned, to the provider.
        """
        request = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "developer", "content": "Forward this to alice@acme.lv"},
                {"role": "user", "content": "Hello"},
            ],
        }
        with pytest.raises(DetectionError) as caught:
            await pipeline.process(ctx, request)

        assert mock_provider.received == []
        assert local_provider.received == []
        assert "developer" not in str(caught.value)
        assert "alice@acme.lv" not in str(caught.value)

    @pytest.mark.parametrize(
        ("field", "request_body"),
        [
            pytest.param(
                "name",
                {"model": "m", "messages": [{**CLEAN_MESSAGE, "name": "alice@acme.lv"}]},
                id="message-name",
            ),
            pytest.param(
                "tool_calls",
                {
                    "model": "m",
                    "messages": [
                        {
                            "role": "assistant",
                            "content": "Sending it now",
                            "tool_calls": [
                                {
                                    "id": "call-1",
                                    "type": "function",
                                    "function": {
                                        "name": "send",
                                        "arguments": '{"to": "alice@acme.lv"}',
                                    },
                                }
                            ],
                        },
                        CLEAN_MESSAGE,
                    ],
                },
                id="assistant-tool-calls",
            ),
            pytest.param(
                "user",
                {"model": "m", "user": "alice@acme.lv", "messages": [CLEAN_MESSAGE]},
                id="top-level-user",
            ),
            pytest.param(
                "metadata",
                {"model": "m", "metadata": {"c": "alice@acme.lv"}, "messages": [CLEAN_MESSAGE]},
                id="top-level-metadata",
            ),
            pytest.param(
                "tools",
                {
                    "model": "m",
                    "tools": [
                        {
                            "type": "function",
                            "function": {"name": "send", "description": "Mail alice@acme.lv"},
                        }
                    ],
                    "messages": [CLEAN_MESSAGE],
                },
                id="top-level-tools",
            ),
            pytest.param(
                "stop",
                {"model": "m", "stop": ["alice@acme.lv"], "messages": [CLEAN_MESSAGE]},
                id="top-level-stop",
            ),
            pytest.param(
                "service_tier",
                {"model": "m", "service_tier": "alice@acme.lv", "messages": [CLEAN_MESSAGE]},
                id="free-text-in-an-enum",
            ),
            pytest.param(
                "model",
                {"model": {"name": "alice@acme.lv"}, "messages": [CLEAN_MESSAGE]},
                id="model-that-is-not-a-string",
            ),
        ],
    )
    async def test_uninspected_field_is_refused_not_forwarded(
        self, pipeline, ctx, mock_provider, local_provider, field, request_body
    ):
        """SI-01 on the library path, for fields as for roles.

        Inspection reads a message's `role` and `content` and nothing else, and
        the outbound payload is copied from the request. With no schema in
        front, an address the detectors catch in `content` used to reach the
        provider unscanned from any other field, on a request that looked clean.
        """
        with pytest.raises(DetectionError) as caught:
            await pipeline.process(ctx, request_body)

        assert mock_provider.received == []
        assert local_provider.received == []
        assert field not in str(caught.value)
        assert "alice@acme.lv" not in str(caught.value)


# ---------------------------------------------------------------------------
# SAG_LOCAL_ROUTING ("GDPR mode")
# ---------------------------------------------------------------------------

#: An IP literal on loopback: the provider builds with no DNS and no connection,
#: and the tests swap in a recording provider before anything is sent.
LOCAL_URL = "http://127.0.0.1:11434/v1"

_EXTERNAL_CATCH_ALL = {
    "name": "clean-requests-external",
    "priority": 10,
    "action": {"type": "allow", "destination": "external"},
}

#: Shaped like the enumerated preset the mode replaces: one local rule at 90
#: and an external catch-all. Its local rule sorts after every `filter:` name,
#: which is how a filter at the same priority wins the tie.
PRESET_SHAPED_POLICY = {
    "version": "preset-shaped-v1",
    "default_destination": "external",
    "rules": [
        {
            "name": "personal-data-local",
            "priority": 90,
            "match": {"entities": ["EMAIL_ADDRESS", "PERSON", "EMPLOYEE_ID"]},
            "action": {"type": "route_local", "destination": "local"},
        },
        _EXTERNAL_CATCH_ALL,
    ],
}

EMPLOYEE_ID_MATCH = {"type": "regex", "pattern": r"\bEMP-[0-9]{6}\b"}


class KnownNames:
    """Stands in for an NER model: recognises the given names wherever they occur."""

    def __init__(self, *names: str) -> None:
        self._names = names

    def entities(self, text: str) -> list[tuple[int, int, str, float]]:
        return [
            (match.start(), match.end(), "PER", 0.6)
            for name in self._names
            for match in re.finditer(re.escape(name), text)
        ]


class ExplodingNer:
    def entities(self, text: str) -> list[tuple[int, int, str, float]]:
        raise RuntimeError("model failed")


class FailingLocal:
    """A local model that times out. Counts calls, so a retry would show."""

    name = "local"

    def __init__(self) -> None:
        self.calls = 0

    async def chat_completion(self, payload: dict) -> dict:
        self.calls += 1
        raise ProviderError("upstream timed out after 120.0s", 504)


@dataclass(frozen=True)
class RouteAround:
    """A request with detected data that its policy sends to `external`.

    Each is a way round the enumerated preset this mode replaces, set up so
    that without the mode it really does reach `external` -- which
    ``test_each_case_needs_the_mode`` checks. ``tokens`` must reach the local
    model; ``values`` must not.
    """

    id: str
    text: str
    tokens: tuple[str, ...]
    values: tuple[str, ...]
    names: tuple[str, ...] = ()
    policy: dict | None = None
    filters: tuple[dict, ...] = ()
    custom_patterns: tuple[tuple[str, str], ...] = ()

    def settings(self, directory: Path) -> dict:
        settings: dict = {"custom_patterns": self.custom_patterns}
        if self.policy is not None:
            settings["policy_path"] = directory / "policy.yaml"
            settings["policy_path"].write_text(yaml.safe_dump(self.policy), encoding="utf-8")
        if self.filters:
            settings["filters_path"] = directory / "filters.yaml"
            settings["filters_path"].write_text(
                yaml.safe_dump({"version": 1, "filters": list(self.filters)}), encoding="utf-8"
            )
        return settings


ROUTE_AROUND_CASES = [
    RouteAround(
        id="ner-name",
        text="Please write to Anna Berzina today",
        tokens=("PERSON",),
        values=("Anna Berzina",),
        names=("Anna Berzina",),
    ),
    RouteAround(
        id="legacy-custom-pattern",
        text="Employee EMP-123456 asked for leave",
        tokens=("EMPLOYEE_ID",),
        values=("EMP-123456",),
        custom_patterns=(("EMPLOYEE_ID", r"EMP-[0-9]{6}"),),
    ),
    RouteAround(
        # HOSTREF outscores the IP address inside it, so only HOSTREF is left.
        id="unlisted-type-wins-conflict-over-ip",
        text="Contact HOST=10.0.0.5 is down",
        tokens=("HOSTREF",),
        values=("10.0.0.5",),
        custom_patterns=(("HOSTREF", r"HOST=\S+"),),
    ),
    RouteAround(
        # CASE_REF outscores the NER PERSON span it overlaps, so PERSON is gone.
        id="unlisted-type-wins-conflict-over-person",
        text="Case Anna Berzina requires review",
        tokens=("CASE_REF",),
        values=("Case Anna",),
        names=("Anna Berzina",),
        custom_patterns=(("CASE_REF", r"Case [A-Z][a-z]+"),),
    ),
    RouteAround(
        # At 95 the filter outranks baltic-ids-local-only (90) in default.yaml.
        id="filter-to-external-at-95",
        text=f"Employee EMP-123456, personal code {VALID_LV_CODE}",
        tokens=("EMPLOYEE_ID", "LV_PERSONAL_CODE"),
        values=("EMP-123456", VALID_LV_CODE),
        filters=(
            {
                "name": "employee-ids",
                "entity_type": "EMPLOYEE_ID",
                "match": EMPLOYEE_ID_MATCH,
                "destination": "external",
                "priority": 95,
            },
        ),
    ),
    RouteAround(
        id="filter-to-external-wins-the-tie-at-90",
        text="Employee EMP-123456 wrote from alex@example.com",
        tokens=("EMPLOYEE_ID", "EMAIL_ADDRESS"),
        values=("EMP-123456", "alex@example.com"),
        policy=PRESET_SHAPED_POLICY,
        filters=(
            {
                "name": "employee-ids",
                "entity_type": "EMPLOYEE_ID",
                "match": EMPLOYEE_ID_MATCH,
                "destination": "external",
                "priority": 90,
            },
        ),
    ),
    RouteAround(
        id="filter-reusing-the-email-label",
        text="Mail alex@example.com now",
        tokens=("EMAIL_ADDRESS",),
        values=("alex@example.com",),
        policy=PRESET_SHAPED_POLICY,
        filters=(
            {
                "name": "mail-out",
                "entity_type": "EMAIL_ADDRESS",
                "match": {"type": "regex", "pattern": r"[a-z]+@example\.com"},
                "destination": "external",
                "priority": 95,
            },
        ),
    ),
    RouteAround(
        id="application-scoped-allow-at-999",
        text="Mail alex@example.com now",
        tokens=("EMAIL_ADDRESS",),
        values=("alex@example.com",),
        policy={
            **PRESET_SHAPED_POLICY,
            "rules": [
                {
                    "name": "test-app-external",
                    "priority": 999,
                    "match": {"applications": ["test-app"]},
                    "action": {"type": "allow", "destination": "external"},
                },
                *PRESET_SHAPED_POLICY["rules"],
            ],
        },
    ),
    RouteAround(
        # `mach` is not `match`: the loader reads a rule with no conditions.
        id="typo-makes-a-catch-all",
        text="Mail alex@example.com now",
        tokens=("EMAIL_ADDRESS",),
        values=("alex@example.com",),
        policy={
            "version": "typo-v1",
            "rules": [
                {
                    "name": "mail-external",
                    "priority": 100,
                    "mach": {"entities": ["EMAIL_ADDRESS"]},
                    "action": {"type": "allow", "destination": "external"},
                },
                PRESET_SHAPED_POLICY["rules"][0],
            ],
        },
    ),
    RouteAround(
        id="route-local-without-a-destination",
        text="Mail alex@example.com now",
        tokens=("EMAIL_ADDRESS",),
        values=("alex@example.com",),
        policy={
            "version": "no-destination-v1",
            "default_destination": "external",
            "rules": [
                {
                    "name": "personal-data-local",
                    "priority": 90,
                    "match": {"entities": ["EMAIL_ADDRESS"]},
                    "action": {"type": "route_local"},
                },
                _EXTERNAL_CATCH_ALL,
            ],
        },
    ),
    RouteAround(
        # The IP detector scores 0.6, below the rule's threshold.
        id="span-below-min-score",
        text="Server 10.0.0.5 is down",
        tokens=("IP_ADDRESS",),
        values=("10.0.0.5",),
        policy={
            "version": "min-score-v1",
            "default_destination": "external",
            "rules": [
                {
                    "name": "addresses-local",
                    "priority": 90,
                    "match": {"entities": ["IP_ADDRESS"], "min_score": 0.9},
                    "action": {"type": "route_local", "destination": "local"},
                },
                _EXTERNAL_CATCH_ALL,
            ],
        },
    ),
    RouteAround(
        # No destination falls back to default.yaml's `external`.
        id="filter-without-a-destination",
        text="Employee EMP-123456 asked for leave",
        tokens=("EMPLOYEE_ID",),
        values=("EMP-123456",),
        filters=(
            {"name": "employee-ids", "entity_type": "EMPLOYEE_ID", "match": EMPLOYEE_ID_MATCH},
        ),
    ),
]


class TestLocalRoutingMode:
    """SAG_LOCAL_ROUTING: detected data reaches no provider but `local`.

    Every pipeline is built through ``build_pipeline`` from files in a temporary
    directory, so the real policy loader, filter loader, composition order, and
    startup checks all run. Assertions are on what each provider received.
    """

    @pytest.fixture
    def gateway(self, monkeypatch, mock_provider, local_provider, audit_sink):
        def build(mode: LocalRouting, *, ner=None, **settings):
            if ner is not None:
                monkeypatch.setattr(
                    "gateway.config.build_ner_detector", lambda path: NerDetector(ner)
                )
            pipeline = build_pipeline(
                Settings(local_routing=mode, local_base_url=LOCAL_URL, **settings),
                audit_sink=audit_sink,
            )
            pipeline._providers.update({"external": mock_provider, "local": local_provider})
            return pipeline

        return build

    @pytest.mark.parametrize("case", ROUTE_AROUND_CASES, ids=lambda case: case.id)
    async def test_detected_keeps_the_request_on_the_local_model(
        self, gateway, tmp_path, ctx, case, mock_provider, local_provider
    ):
        pipeline = gateway(
            LocalRouting.DETECTED, ner=KnownNames(*case.names), **case.settings(tmp_path)
        )

        result = await pipeline.process(ctx, payload(case.text))

        assert mock_provider.received == [], "nothing may reach the external provider"
        assert result.rule_name == "local-routing:detected"
        saw = provider_saw(local_provider)
        for token_type in case.tokens:
            assert f"<{token_type}:v1:" in saw, f"the local model must receive {token_type} tokens"
        for value in case.values:
            assert value not in saw, "the local model receives tokens, not values"

    @pytest.mark.parametrize("case", ROUTE_AROUND_CASES, ids=lambda case: case.id)
    async def test_each_case_needs_the_mode(
        self, gateway, tmp_path, ctx, case, mock_provider, local_provider
    ):
        """Not a leak test: it keeps the cases above honest.

        With the mode off, each request goes to `external` -- which is what
        makes it a way round the policy, and the test above more than vacuous.
        """
        pipeline = gateway(LocalRouting.OFF, ner=KnownNames(*case.names), **case.settings(tmp_path))

        await pipeline.process(ctx, payload(case.text))

        assert mock_provider.received, f"{case.id} no longer reaches external without the mode"
        assert local_provider.received == []

    async def test_all_needs_no_detection_to_keep_a_name_local(
        self, gateway, ctx, mock_provider, local_provider
    ):
        """No NER model, so the name is not detected -- and still stays local.

        Nothing was detected, so nothing is tokenised: the operator's own model
        receives the text as written, as `allow` would have sent it.
        """
        text = "Please write to Anna Berzina today"
        result = await gateway(LocalRouting.ALL).process(ctx, payload(text))

        assert mock_provider.received == []
        assert result.rule_name == "local-routing:all"
        assert local_provider.received[0]["messages"][0]["content"] == text

    async def test_all_still_pseudonymises_what_it_detects(
        self, gateway, ctx, mock_provider, local_provider
    ):
        await gateway(LocalRouting.ALL).process(ctx, payload("Mail alice@acme.lv today"))

        assert mock_provider.received == []
        assert "<EMAIL_ADDRESS:v1:" in provider_saw(local_provider)
        assert "alice@acme.lv" not in provider_saw(local_provider)

    async def test_a_clean_request_still_reaches_external_unchanged(
        self, gateway, ctx, mock_provider, local_provider
    ):
        """No over-routing: `detected` moves only what detection found."""
        text = "Explain what a mutex is"
        result = await gateway(LocalRouting.DETECTED, ner=KnownNames()).process(ctx, payload(text))

        assert result.rule_name == "default-allow"
        assert mock_provider.received[0]["messages"][0]["content"] == text
        assert local_provider.received == []

    async def test_a_local_failure_is_never_retried_externally(self, gateway, ctx, mock_provider):
        pipeline = gateway(LocalRouting.DETECTED, ner=KnownNames())
        failing = FailingLocal()
        pipeline._providers["local"] = failing

        with pytest.raises(ProviderError) as caught:
            await pipeline.process(ctx, payload("Mail alice@acme.lv today"))

        assert caught.value.status_code == 504
        assert failing.calls == 1
        assert mock_provider.received == []

    async def test_a_detector_failure_reaches_no_provider(
        self, gateway, ctx, mock_provider, local_provider
    ):
        pipeline = gateway(LocalRouting.DETECTED, ner=ExplodingNer())

        with pytest.raises(DetectionError):
            await pipeline.process(ctx, payload("Please write to Anna Berzina today"))

        assert mock_provider.received == []
        assert local_provider.received == []

    async def test_the_tripwire_fails_closed_if_the_rewrite_regresses(
        self, gateway, monkeypatch, ctx, mock_provider, local_provider
    ):
        """Fault injection: the engine stops rewriting, the pipeline still refuses."""
        pipeline = gateway(LocalRouting.DETECTED, ner=KnownNames())
        monkeypatch.setattr(
            "gateway.policy.engine.apply_local_routing",
            lambda mode, decision, inspection: decision,
        )

        with pytest.raises(LocalRoutingViolation):
            await pipeline.process(ctx, payload("Mail alice@acme.lv today"))

        assert mock_provider.received == []
        assert local_provider.received == []

    @pytest.mark.parametrize("mode", [LocalRouting.DETECTED, LocalRouting.ALL])
    async def test_the_tripwire_fails_closed_if_the_predicate_regresses(
        self, gateway, monkeypatch, ctx, mode, mock_provider, local_provider
    ):
        """Fault injection one level down: the mode's own "must this stay
        local?" answers no, so the engine moves nothing. The tripwire does not
        ask that question of it, so it still refuses."""
        pipeline = gateway(mode, ner=KnownNames())
        monkeypatch.setattr(LocalRouting, "requires_local", lambda self, inspection: False)

        with pytest.raises(LocalRoutingViolation):
            await pipeline.process(ctx, payload("Mail alice@acme.lv today"))

        assert mock_provider.received == []
        assert local_provider.received == []

    async def test_detected_refuses_a_field_it_does_not_inspect(
        self, gateway, ctx, mock_provider, local_provider
    ):
        """The address rides in `user` beside clean `content`. Detection never
        reads `user`, so the request would look clean and go external."""
        request = {
            "model": "m",
            "user": "alice@acme.lv",
            "messages": [{"role": "user", "content": "Explain what a mutex is"}],
        }

        with pytest.raises(DetectionError):
            await gateway(LocalRouting.DETECTED, ner=KnownNames()).process(ctx, request)

        assert mock_provider.received == []
        assert local_provider.received == []

    async def test_the_audit_event_records_where_a_moved_request_went(
        self, gateway, ctx, audit_sink
    ):
        """The evidence a DPO reads, with no change to the audit schema."""
        await gateway(LocalRouting.DETECTED, ner=KnownNames()).process(
            ctx, payload("Mail alice@acme.lv today")
        )

        event = audit_sink.events[-1]
        assert event.schema_version == 3
        assert event.destination == "local"
        assert event.provider == "local"
        assert event.rule_name == "local-routing:detected"
        assert event.policy_version == "community-default-v1+local-routing:detected"
        assert event.entity_counts == {"EMAIL_ADDRESS": 1}
