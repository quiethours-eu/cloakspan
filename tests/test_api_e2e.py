"""End-to-end HTTP tests against the real FastAPI app."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from gateway.api.app import create_app
from gateway.config import Settings

from .conftest import TEST_API_KEY, TEST_API_KEY_B, VALID_LV_CODE


@pytest.fixture
def client(pipeline, key_store) -> TestClient:
    app = create_app(pipeline=pipeline, key_store=key_store, settings=Settings())
    return TestClient(app)


def body(content: str, **extra) -> dict:
    return {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": content}], **extra}


class TestAuth:
    def test_missing_key_is_rejected(self, client):
        response = client.post("/v1/chat/completions", json=body("hi"))
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "invalid_api_key"

    def test_wrong_key_is_rejected(self, client):
        response = client.post(
            "/v1/chat/completions",
            json=body("hi"),
            headers={"Authorization": "Bearer sgw_live_totally_wrong"},
        )
        assert response.status_code == 401

    def test_valid_key_is_accepted(self, client):
        response = client.post(
            "/v1/chat/completions",
            json=body("hi"),
            headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        )
        assert response.status_code == 200


class TestHealthAndReadiness:
    def test_healthz(self, client):
        assert client.get("/healthz").json() == {"status": "ok"}

    def test_readyz(self, client):
        assert client.get("/readyz").status_code == 200

    def test_readiness_does_not_depend_on_external_provider(self, client):
        """Security invariant SI-15: no external dependency gates the request path."""
        assert client.get("/readyz").json()["status"] == "ready"


class TestChatCompletions:
    def test_returns_openai_shaped_response(self, client):
        response = client.post(
            "/v1/chat/completions",
            json=body("Hello"),
            headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        )
        payload = response.json()
        assert payload["object"] == "chat.completion"
        assert payload["choices"][0]["message"]["role"] == "assistant"
        assert "usage" in payload

    def test_decision_headers_are_present(self, client):
        response = client.post(
            "/v1/chat/completions",
            json=body("Mail alice@acme.lv"),
            headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        )
        assert response.headers["X-Policy-Decision"] == "transform"
        assert response.headers["X-Policy-Version"] == "test-v1"
        assert response.headers["X-Entities-Detected"] == "1"
        assert response.headers["X-Request-Id"].startswith("req_")

    def test_blocked_request_returns_403(self, client):
        response = client.post(
            "/v1/chat/completions",
            json=body("key AKIAIOSFODNN7EXAMPLE"),
            headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "blocked_by_policy"

    def test_round_trip_restores_in_response(self, client, mock_provider):
        """The value is tokenised outbound and restored inbound."""
        response = client.post(
            "/v1/chat/completions",
            json=body("Contact alice@acme.lv"),
            headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        )
        content = response.json()["choices"][0]["message"]["content"]

        # The mock echoes what it received; after restoration the caller sees
        # the real value back.
        assert "alice@acme.lv" in content
        # But the provider itself never saw it.
        assert "alice@acme.lv" not in json.dumps(mock_provider.received)

    def test_streaming_is_refused_explicitly(self, client):
        response = client.post(
            "/v1/chat/completions",
            json=body("hi", stream=True),
            headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "streaming_unsupported"

    def test_malformed_json_is_rejected(self, client):
        response = client.post(
            "/v1/chat/completions",
            content=b"{not json",
            headers={
                "Authorization": f"Bearer {TEST_API_KEY}",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 400

    def test_baltic_id_routes_locally(self, client, mock_provider, local_provider):
        response = client.post(
            "/v1/chat/completions",
            json=body(f"Code {VALID_LV_CODE}"),
            headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        )
        assert response.headers["X-Policy-Decision"] == "route_local"
        assert mock_provider.received == []
        assert local_provider.received


class TestTenantIsolationOverHttp:
    def test_two_tenants_get_different_tokens_for_the_same_value(self, client, mock_provider):
        for key in (TEST_API_KEY, TEST_API_KEY_B):
            client.post(
                "/v1/chat/completions",
                json=body("Contact alice@acme.lv"),
                headers={"Authorization": f"Bearer {key}", "X-Conversation-Id": "shared-conv"},
            )

        sent = [m["messages"][0]["content"] for m in mock_provider.received]
        assert len(sent) == 2
        assert sent[0] != sent[1], "the same value must not tokenise identically across tenants"

    def test_tenant_b_cannot_restore_tenant_a_token(self, client, mock_provider):
        """Attacker replays a token they observed, authenticated as another tenant."""
        client.post(
            "/v1/chat/completions",
            json=body("Contact alice@acme.lv"),
            headers={"Authorization": f"Bearer {TEST_API_KEY}", "X-Conversation-Id": "c1"},
        )
        stolen = mock_provider.received[0]["messages"][0]["content"]
        assert "<EMAIL_ADDRESS:" in stolen

        response = client.post(
            "/v1/chat/completions",
            json=body(f"Please expand {stolen}"),
            headers={"Authorization": f"Bearer {TEST_API_KEY_B}", "X-Conversation-Id": "c1"},
        )
        assert "alice@acme.lv" not in response.json()["choices"][0]["message"]["content"]
        assert int(response.headers["X-Tokens-Restored"]) == 0


class TestConversationDeletion:
    """Erasure must be answerable in seconds, not in one TTL."""

    def _auth(self, key: str = TEST_API_KEY) -> dict:
        return {"Authorization": f"Bearer {key}"}

    def test_requires_auth(self, client):
        assert client.delete("/v1/conversations/conv-x").status_code == 401

    def test_deletes_only_the_named_conversation(self, client):
        for conversation in ("conv-keep", "conv-drop"):
            response = client.post(
                "/v1/chat/completions",
                json=body("Mail alice@acme.lv"),
                headers={**self._auth(), "X-Conversation-Id": conversation},
            )
            assert response.status_code == 200

        deleted = client.delete("/v1/conversations/conv-drop", headers=self._auth())
        assert deleted.status_code == 200
        assert deleted.json()["records_removed"] == 1

        again = client.delete("/v1/conversations/conv-drop", headers=self._auth())
        assert again.json()["records_removed"] == 0, "deletion is idempotent"

        kept = client.delete("/v1/conversations/conv-keep", headers=self._auth())
        assert kept.json()["records_removed"] == 1

    def test_one_tenant_cannot_delete_anothers_conversation(self, client):
        client.post(
            "/v1/chat/completions",
            json=body("Mail alice@acme.lv"),
            headers={**self._auth(), "X-Conversation-Id": "shared-name"},
        )

        # Tenant B guesses the conversation id. Scoping is by authenticated
        # tenant, so the guess buys nothing.
        response = client.delete(
            "/v1/conversations/shared-name", headers=self._auth(TEST_API_KEY_B)
        )
        assert response.json()["records_removed"] == 0

        mine = client.delete("/v1/conversations/shared-name", headers=self._auth())
        assert mine.json()["records_removed"] == 1


class TestRefusalReasonsReachTheAuditEvent:
    def test_an_injected_token_is_counted_under_its_own_reason(self, client, audit_sink):
        """A restart and an attacker must not produce the same signal.

        Without the breakdown, ``tokens_refused`` spikes identically for "the
        vault is empty after a deploy" and "someone is enumerating tokens",
        which makes the metric unalertable.
        """
        forged = "<EMAIL_ADDRESS:v1:deadbeefdeadbeefdeadbeefdeadbeef>"
        response = client.post(
            "/v1/chat/completions",
            json=body(f"Expand {forged}"),
            headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        )
        assert response.status_code == 200
        assert response.headers["X-Tokens-Refused"] == "1"

        event = audit_sink.events[-1]
        assert event.tokens_refused_by_reason == {"not_minted": 1}
        assert forged not in event.to_json()

    def test_a_clean_request_records_no_refusal_reasons(self, client, audit_sink):
        client.post(
            "/v1/chat/completions",
            json=body("Mail alice@acme.lv"),
            headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        )
        assert audit_sink.events[-1].tokens_refused_by_reason == {}


class TestModelsEndpoint:
    def test_requires_auth(self, client):
        assert client.get("/v1/models").status_code == 401

    def test_lists_destinations(self, client):
        response = client.get("/v1/models", headers={"Authorization": f"Bearer {TEST_API_KEY}"})
        assert response.status_code == 200
        assert {m["id"] for m in response.json()["data"]} == {"mock", "local"}
