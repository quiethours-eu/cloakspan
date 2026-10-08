"""Public client controls remain scoped and do not become provider telemetry."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from gateway.api.app import create_app
from gateway.auth.keys import ApiKey, hash_key
from gateway.config import Settings
from gateway.routing.responses import MockAgentProvider
from gateway.sessions.scope import SessionScopeError, session_scope
from tests.fixtures import TEST_API_KEY, TEST_API_KEY_B


def public_app(pipeline, key_store, tmp_path, protocol):
    provider = MockAgentProvider(protocol)
    app = create_app(
        pipeline,
        key_store,
        Settings(
            enable_responses=protocol == "responses",
            enable_messages=protocol == "messages",
            agent_workspace_root=str(tmp_path),
        ),
        agent_providers={protocol: {"mock": provider, "local": provider}},
    )
    return TestClient(app), provider


def test_codex_cache_and_attribution_are_local_and_principal_scoped(pipeline, key_store, tmp_path):
    client, provider = public_app(pipeline, key_store, tmp_path, "responses")
    key_store.add(ApiKey("second-principal", hash_key(TEST_API_KEY_B), "tenant-a"))
    body = {
        "model": "gpt-5.1",
        "input": "Owner: owner@example.test",
        "reasoning": {"effort": "none"},
        "include": ["reasoning.encrypted_content"],
        "prompt_cache_key": "public-cache-id",
        "client_metadata": {"session_id": "public-client-session"},
    }

    def send(key, session):
        return client.post(
            "/v1/responses",
            json=body,
            headers={"Authorization": f"Bearer {key}", "session-id": session},
        )

    for key, session in (
        (TEST_API_KEY, "public-session"),
        (TEST_API_KEY, "public-session"),
        (TEST_API_KEY_B, "public-session"),
        (TEST_API_KEY, "other-session"),
    ):
        result = send(key, session)
        assert result.status_code == 200
        assert result.headers["x-session-id"] == session
        assert "owner@example.test" in json.dumps(result.json())
    cache_keys = [item["prompt_cache_key"] for item in provider.received]
    assert cache_keys[0] == cache_keys[1]
    assert len(set(cache_keys)) == 3
    assert all(value.startswith("cache_") for value in cache_keys)
    for outbound in provider.received:
        serialized = json.dumps(outbound)
        assert "client_metadata" not in outbound
        assert "public-cache-id" not in serialized
        assert "public-client-session" not in serialized
        assert "owner@example.test" not in serialized


@pytest.mark.parametrize("stream", [False, True])
def test_claude_controls_are_validated_and_only_supported_betas_reach_provider(
    pipeline, key_store, tmp_path, stream
):
    client, provider = public_app(pipeline, key_store, tmp_path, "messages")
    identity = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    result = client.post(
        "/v1/messages?beta=true",
        headers={
            "x-api-key": TEST_API_KEY,
            "x-claude-code-session-id": identity,
            "anthropic-beta": "claude-code-20250219,effort-2025-11-24",
            "anthropic-version": "2023-06-01",
            "x-arbitrary-private-header": "PRIVATE_HEADER_CANARY",
        },
        json={
            "model": "claude-sonnet-4-6",
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 256,
            "stream": stream,
            "thinking": {"type": "disabled"},
            "output_config": {"effort": "low"},
            "metadata": {
                "user_id": json.dumps(
                    {"device_id": "a" * 64, "account_uuid": "", "session_id": identity}
                )
            },
        },
    )
    assert result.status_code == 200
    assert result.headers["x-session-id"] == identity
    assert provider.received_betas == [("claude-code-20250219", "effort-2025-11-24")]
    assert "metadata" not in provider.received[0]
    assert provider.received[0]["thinking"] == {"type": "disabled"}
    assert "PRIVATE_HEADER_CANARY" not in json.dumps(provider.received)
    assert pipeline.audit.events[-1].error is None


@pytest.mark.parametrize(
    "headers",
    [
        {"anthropic-beta": "claude-code-20250219,foreign-private-beta"},
        {"anthropic-beta": "compact-2026-09-04"},
        {"anthropic-beta": "effort-2025-11-24,"},
        {"x-session-id": "another-session", "x-claude-code-session-id": "native-session"},
        {"x-claude-code-agent-id": "../foreign-agent"},
    ],
)
def test_invalid_native_controls_cause_zero_provider_calls(pipeline, key_store, tmp_path, headers):
    client, provider = public_app(pipeline, key_store, tmp_path, "messages")
    result = client.post(
        "/v1/messages",
        headers={"x-api-key": TEST_API_KEY, **headers},
        json={
            "model": "claude-sonnet-4-6",
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 256,
        },
    )
    assert result.status_code in {400, 422}
    assert provider.received == []
    assert pipeline.audit.events[-1].error is not None


def test_native_subagents_cannot_share_parent_or_sibling_scope():
    key = ApiKey("principal", hash_key(TEST_API_KEY), "tenant")
    parent = session_scope(key, ["native-session"])[1]
    first = session_scope(key, ["native-session"], agent_id="first-agent")[1]
    second = session_scope(key, ["native-session"], agent_id="second-agent")[1]
    assert len({parent, first, second}) == 3
    assert first == session_scope(key, ["native-session"], agent_id="first-agent")[1]
    with pytest.raises(SessionScopeError):
        session_scope(key, ["native-session"], agent_id="unsafe/agent")


def test_native_subagent_deletion_does_not_delete_parent(pipeline, key_store, tmp_path):
    client, provider = public_app(pipeline, key_store, tmp_path, "messages")
    headers = {"x-api-key": TEST_API_KEY, "x-claude-code-session-id": "native-session"}
    body = {
        "model": "claude-sonnet-4-6",
        "messages": [{"role": "user", "content": "owner@example.test"}],
        "max_tokens": 256,
    }
    assert client.post("/v1/messages", headers=headers, json=body).status_code == 200
    assert (
        client.post(
            "/v1/messages", headers={**headers, "x-claude-code-agent-id": "child"}, json=body
        ).status_code
        == 200
    )
    deleted = client.delete(
        "/v1/agent/sessions/native-session",
        headers={"x-api-key": TEST_API_KEY, "x-claude-code-agent-id": "child"},
    )
    assert deleted.status_code == 200
    assert deleted.json()["records_removed"] == 1
    parent_deleted = client.delete(
        "/v1/agent/sessions/native-session", headers={"x-api-key": TEST_API_KEY}
    )
    assert parent_deleted.json()["records_removed"] == 1
    assert len(provider.received) == 2


@pytest.mark.parametrize("protocol", ["responses", "messages"])
def test_input_limit_uses_native_compaction_error_without_egress(
    pipeline, key_store, tmp_path, protocol
):
    client, provider = public_app(pipeline, key_store, tmp_path, protocol)
    client.app.state.agent_runtime.preparation.max_input_chars = 64
    content = "Synthetic history " * 10
    body = (
        {"model": "gpt-5.1", "input": content}
        if protocol == "responses"
        else {
            "model": "claude-sonnet-4-6",
            "messages": [{"role": "user", "content": content}],
            "max_tokens": 256,
        }
    )
    result = client.post(
        f"/v1/{protocol}", json=body, headers={"Authorization": f"Bearer {TEST_API_KEY}"}
    )
    assert result.status_code == 400
    assert result.json()["error"]["code"] == "context_length_exceeded"
    assert "prompt is too long" in result.json()["error"]["message"]
    assert content not in result.text
    assert not provider.received
    assert pipeline.audit.events[-1].error == "context_length_exceeded"
