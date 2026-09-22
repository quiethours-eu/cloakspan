"""The request contract, asserted field by field against the published doc.

``docs/openai-compatibility.md`` had a "Conformance status" table where every
interesting row said ⚠️ **No** — the contract was documented and not enforced.
These tests are what let that table say ✅, and they are written from the
document so the two cannot drift apart silently.

The centrepiece is
``TestNothingReachesTheProviderUninspected::test_only_inspected_or_minted_text_reaches_the_provider``:
the property form of SI-01, which the invariant-test matrix named as the single
highest-value untested statement in the product. It would have caught both
historical bypasses without anyone enumerating them.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gateway.api.app import create_app
from gateway.api.schema import (
    ACCEPTED_ROLES,
    MAX_MESSAGES,
    UNINSPECTABLE_FIELDS,
    UNINSPECTABLE_MESSAGE_FIELDS,
    ChatCompletionRequest,
    ChatMessage,
    RequestRejected,
    accepts_request_fields,
    parse_chat_completion_request,
)
from gateway.config import Settings
from gateway.inspection.pipeline import INSPECTED_INPUT_ROLES, INSPECTED_MESSAGE_FIELDS
from gateway.transformations.tokens import TOKEN_PATTERN

from .conftest import TEST_API_KEY

CANARY = "canary-must-not-leak@secret.example"


@pytest.fixture
def client(pipeline, key_store) -> TestClient:
    app = create_app(pipeline=pipeline, key_store=key_store, settings=Settings())
    return TestClient(app)


def auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {TEST_API_KEY}"}


def body(**extra: Any) -> dict[str, Any]:
    return {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hello"}],
        **extra,
    }


# ---------------------------------------------------------------------------
# Reject-unknown
# ---------------------------------------------------------------------------


class TestUnknownFields:
    @pytest.mark.parametrize(
        "field", ["wibble", "base_url", "api_base", "provider", "x", "Stream", "MESSAGES"]
    )
    def test_an_unrecognised_top_level_field_is_refused(self, client, field):
        response = client.post("/v1/chat/completions", json=body(**{field: "x"}), headers=auth())
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "unknown_field"

    def test_an_unrecognised_message_field_is_refused(self, client):
        payload = body()
        payload["messages"][0]["wibble"] = "x"
        response = client.post("/v1/chat/completions", json=payload, headers=auth())
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "unknown_field"

    @given(field=st.text(min_size=1, max_size=20).filter(lambda s: s.isidentifier()))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_any_field_not_on_the_model_is_refused(self, field):
        """Property form: the allowlist is the model, not a denylist."""
        if field in ChatCompletionRequest.model_fields:
            return
        with pytest.raises(RequestRejected) as caught:
            parse_chat_completion_request(body(**{field: 1}))
        assert caught.value.code in ("unknown_field", "uninspectable_field")


class TestRecognisedButRefusedFields:
    @pytest.mark.parametrize("field", sorted(UNINSPECTABLE_FIELDS))
    def test_each_uninspectable_field_is_refused_with_its_reason(self, client, field):
        response = client.post(
            "/v1/chat/completions", json=body(**{field: [{"a": 1}]}), headers=auth()
        )
        assert response.status_code == 422
        payload = response.json()["error"]
        assert payload["code"] == "uninspectable_field"
        assert field in payload["message"], "the error must name the field"

    @pytest.mark.parametrize("field", sorted(UNINSPECTABLE_MESSAGE_FIELDS))
    def test_each_uninspectable_message_field_is_refused(self, client, field):
        payload = body()
        payload["messages"][0][field] = "x"
        response = client.post("/v1/chat/completions", json=payload, headers=auth())
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "uninspectable_field"

    def test_the_two_codes_mean_different_things(self, client):
        """`unknown_field` is "we do not recognise this"; `uninspectable_field`
        is "we recognise it and refuse it". Collapsing them would make every
        integration question the same question."""
        unknown = client.post("/v1/chat/completions", json=body(zzz=1), headers=auth())
        refused = client.post("/v1/chat/completions", json=body(tools=[]), headers=auth())
        assert unknown.json()["error"]["code"] == "unknown_field"
        assert refused.json()["error"]["code"] == "uninspectable_field"

    @pytest.mark.parametrize(
        ("field", "value"),
        [("user", CANARY), ("stop", CANARY), ("stop", [CANARY])],
    )
    def test_free_text_control_fields_never_reach_the_provider(
        self, client, mock_provider, field, value
    ):
        response = client.post("/v1/chat/completions", json=body(**{field: value}), headers=auth())

        assert response.status_code == 422
        assert response.json()["error"]["code"] == "uninspectable_field"
        assert mock_provider.received == []


class TestRoles:
    @pytest.mark.parametrize("role", ["system", "user", "assistant", "tool"])
    def test_accepted_roles_pass(self, client, role):
        payload = body()
        payload["messages"][0]["role"] = role
        assert client.post("/v1/chat/completions", json=payload, headers=auth()).status_code == 200

    @pytest.mark.parametrize("role", ["developer", "function", "system ", "USER", "", "wizard"])
    def test_other_roles_are_refused(self, client, role):
        """`developer` is the one that matters: OpenAI itself uses it now, so a
        gateway that silently forwarded unknown roles would leak on a routine
        client upgrade."""
        payload = body()
        payload["messages"][0]["role"] = role
        response = client.post("/v1/chat/completions", json=payload, headers=auth())
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "unsupported_role"


class TestContent:
    @pytest.mark.parametrize(
        "content", [[{"type": "text", "text": "x"}], None, 42, {"text": "x"}, True]
    )
    def test_non_string_content_is_refused(self, client, content):
        payload = body()
        payload["messages"][0]["content"] = content
        response = client.post("/v1/chat/completions", json=payload, headers=auth())
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "inspection_failed"

    def test_an_empty_message_list_is_refused(self, client):
        response = client.post(
            "/v1/chat/completions", json={"model": "m", "messages": []}, headers=auth()
        )
        assert response.status_code == 422

    def test_a_non_object_message_has_the_documented_error_code(self, client):
        response = client.post(
            "/v1/chat/completions",
            json={"model": "m", "messages": ["not an object"]},
            headers=auth(),
        )

        assert response.status_code == 422
        assert response.json()["error"]["code"] == "invalid_message"

    def test_too_many_messages_are_refused(self, client):
        """A million empty messages is a cheap denial of service, and the
        character limit does not bound it."""
        payload = {
            "model": "m",
            "messages": [{"role": "user", "content": "x"}] * (MAX_MESSAGES + 1),
        }
        response = client.post("/v1/chat/completions", json=payload, headers=auth())
        assert response.status_code == 422

    def test_a_non_object_body_is_a_400(self, client):
        response = client.post("/v1/chat/completions", json=["not", "an", "object"], headers=auth())
        assert response.status_code == 400


class TestStreaming:
    def test_stream_true_is_refused_with_its_own_code(self, client):
        response = client.post("/v1/chat/completions", json=body(stream=True), headers=auth())
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "streaming_unsupported"

    def test_stream_false_is_accepted_and_not_forwarded(self, client, mock_provider):
        response = client.post("/v1/chat/completions", json=body(stream=False), headers=auth())
        assert response.status_code == 200
        assert "stream" not in mock_provider.received[-1], (
            "a field we refuse must not be carried outbound"
        )

    def test_stream_options_is_refused(self, client):
        response = client.post(
            "/v1/chat/completions", json=body(stream_options={"a": 1}), headers=auth()
        )
        assert response.status_code == 422


class TestAcceptedParametersAreForwarded:
    def test_sampling_parameters_reach_the_provider(self, client, mock_provider):
        client.post(
            "/v1/chat/completions",
            json=body(temperature=0.3, top_p=0.9, max_tokens=64, seed=7),
            headers=auth(),
        )
        sent = mock_provider.received[-1]
        assert sent["temperature"] == 0.3
        assert sent["top_p"] == 0.9
        assert sent["max_tokens"] == 64
        assert sent["seed"] == 7

    def test_service_tier_is_an_enum_not_a_free_text_channel(self, client, mock_provider):
        refused = client.post(
            "/v1/chat/completions", json=body(service_tier=CANARY), headers=auth()
        )
        accepted = client.post(
            "/v1/chat/completions", json=body(service_tier="auto"), headers=auth()
        )

        assert refused.status_code == 422
        assert len(mock_provider.received) == 1
        assert accepted.status_code == 200
        assert mock_provider.received[0]["service_tier"] == "auto"

    def test_unset_optional_fields_are_not_invented(self, client, mock_provider):
        client.post("/v1/chat/completions", json=body(), headers=auth())
        sent = mock_provider.received[-1]
        assert set(sent) == {"model", "messages"}, (
            "the outbound payload must carry only what the client sent"
        )


# ---------------------------------------------------------------------------
# SI-01, as a property
# ---------------------------------------------------------------------------


class TestNothingReachesTheProviderUninspected:
    """The exit criterion: *no accepted field can bypass inspection*."""

    @staticmethod
    def _strings(value: Any):
        """Every string anywhere in the outbound payload."""
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for item in value.values():
                yield from TestNothingReachesTheProviderUninspected._strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from TestNothingReachesTheProviderUninspected._strings(item)

    def test_only_inspected_or_minted_text_reaches_the_provider(self, client, mock_provider):
        """The statement the invariant-test matrix called the highest-value gap.

        For any accepted payload, every string the provider receives came from a
        message we inspected, or is a token we minted. It would have caught both
        historical bypasses -- unknown roles and unknown top-level fields --
        without anyone enumerating either of them.
        """
        inspected = f"Mail {CANARY} about Project Aurora"
        response = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": "You are helpful."},
                    {"role": "user", "content": inspected},
                ],
                "temperature": 0.2,
            },
            headers=auth(),
        )
        assert response.status_code == 200

        sent = mock_provider.received[-1]
        origins = {"You are helpful.", "gpt-4o-mini", "system", "user"}

        for string in self._strings(sent):
            if string in origins:
                continue
            assert CANARY not in string

            # Anything else must be transformed message content. Split it on
            # the tokens we minted; every remaining literal fragment has to come
            # from text we inspected. Comparing the *whole* string after
            # deleting tokens would be wrong -- deletion leaves the gap closed
            # up, so the result is not a substring of the original.
            for fragment in TOKEN_PATTERN.split(string)[::4]:
                assert fragment in inspected, (
                    f"fragment {fragment!r} reached the provider but was never inspected"
                )

    def test_a_rejected_request_reaches_no_provider_at_all(self, client, mock_provider):
        for payload in (
            {"model": "m", "messages": [{"role": "developer", "content": CANARY}]},
            {"model": "m", "messages": [{"role": "user", "content": "x"}], "tools": [CANARY]},
            {"model": "m", "messages": [{"role": "user", "content": "x", "name": CANARY}]},
            {"model": "m", "messages": [{"role": "user", "content": "x"}], "wibble": CANARY},
        ):
            response = client.post("/v1/chat/completions", json=payload, headers=auth())
            assert response.status_code == 422

        assert mock_provider.received == [], "nothing rejected may reach a provider"

    @given(
        extra_key=st.text(min_size=1, max_size=12).filter(str.isidentifier),
        extra_value=st.text(max_size=40),
    )
    @settings(max_examples=80, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_no_generated_extra_field_survives_validation(self, extra_key, extra_value):
        if extra_key in ChatCompletionRequest.model_fields:
            return
        try:
            validated = parse_chat_completion_request(body(**{extra_key: extra_value}))
        except RequestRejected:
            return
        assert extra_key not in validated.to_payload(), (
            "a field that survived validation must still not be forwarded"
        )


class TestErrorsCarryNoContent:
    @pytest.mark.parametrize(
        "payload",
        [
            {"model": "m", "messages": [{"role": "developer", "content": CANARY}]},
            {"model": "m", "messages": [{"role": "user", "content": [CANARY]}]},
            {"model": "m", "messages": [{"role": "user", "content": "x"}], "tools": [CANARY]},
        ],
    )
    def test_a_rejection_never_echoes_the_message(self, client, payload):
        """An error path is still a log path, and a 422 body is read by humans."""
        response = client.post("/v1/chat/completions", json=payload, headers=auth())
        assert response.status_code == 422
        assert CANARY not in json.dumps(response.json())


# ---------------------------------------------------------------------------
# Direct callers of the pipeline
# ---------------------------------------------------------------------------


class TestDirectCallersGetTheSameContract:
    """``SecurityPipeline.process`` with no schema in front of it.

    The pipeline copies the request it is given and inspects message `content`
    only, so it has to refuse what this schema refuses. The leakage evidence is
    ``evals/leakage/test_leakage_regression.py::TestFailClosed``.
    """

    def test_the_pipeline_reads_the_message_fields_and_roles_the_schema_accepts(self):
        assert INSPECTED_MESSAGE_FIELDS == set(ChatMessage.model_fields)
        assert INSPECTED_INPUT_ROLES == ACCEPTED_ROLES

    @pytest.mark.parametrize(
        "fields",
        [
            {},
            {"model": "m"},
            {"temperature": 0.2, "top_p": 1, "n": 1, "seed": 7, "logprobs": False},
            {"service_tier": "auto", "stream": False, "max_tokens": None},
        ],
    )
    def test_the_accepted_fields_pass(self, fields):
        assert accepts_request_fields({"messages": [], **fields})

    @pytest.mark.parametrize(
        "fields",
        [
            {"user": CANARY},
            {"wibble": 1},
            {"Model": "m"},
            {"model": {"name": CANARY}},
            {"service_tier": CANARY},
            {"temperature": CANARY},
            {"stream": CANARY},
        ],
    )
    def test_any_other_field_or_value_fails(self, fields):
        """Unknown names, and known names holding text the schema would refuse.
        `service_tier` stays an enum on this path for the reason given in
        ``TestAcceptedParametersAreForwarded``: it must not be a free-text
        channel."""
        assert not accepts_request_fields({"messages": [], **fields})
