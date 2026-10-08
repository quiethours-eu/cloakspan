"""Resource, disconnect, and principal isolation invariants of agent entrypoints."""

from __future__ import annotations

import asyncio
import multiprocessing
import pickle
import struct
import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from starlette.requests import ClientDisconnect

from gateway.api.app import create_app
from gateway.auth.keys import ApiKey, hash_key
from gateway.config import ConfigurationError, Settings
from gateway.inspection.agent import inspect_isolated
from gateway.inspection.preparation import DetectionError
from gateway.routing.responses import MockAgentProvider
from gateway.sessions.scope import SessionScopeError, session_scope
from tests.fixtures import TEST_API_KEY


def agent_app(pipeline, key_store, tmp_path, **limits):
    provider = MockAgentProvider(protocol="responses")
    app = create_app(
        pipeline,
        key_store,
        Settings(enable_responses=True, agent_workspace_root=str(tmp_path), **limits),
        agent_providers={"responses": {"mock": provider, "local": provider}},
    )
    return app, provider


class HangingDetector:
    def detect(self, text):
        time.sleep(60)
        return []


def partial_ipc(connection, *args):
    serialized = pickle.dumps((True, []))
    connection._send(struct.pack("!i", len(serialized)))
    time.sleep(0.2)
    connection._send(serialized)


async def test_detector_timeout_kills_worker_without_blocking_health():
    before = {child.pid for child in multiprocessing.active_children()}
    started = time.monotonic()
    task = asyncio.create_task(
        inspect_isolated([HangingDetector()], ["input"], mixed_script=False, deadline_seconds=0.04)
    )
    await asyncio.sleep(0.01)
    assert not task.done()
    with pytest.raises(DetectionError):
        await task
    assert time.monotonic() - started < 0.5
    assert {child.pid for child in multiprocessing.active_children()} <= before


@pytest.mark.skipif(
    "fork" not in multiprocessing.get_all_start_methods(), reason="fork IPC fixture"
)
async def test_partial_detector_ipc_obeys_deadline(monkeypatch):
    monkeypatch.setattr("gateway.inspection.agent._inspect_worker", partial_ipc)
    started = time.monotonic()
    with pytest.raises(DetectionError):
        await inspect_isolated([], [], mixed_script=False, deadline_seconds=0.04)
    assert time.monotonic() - started < 0.15


@pytest.mark.parametrize("disconnect_at", ["headers", "event"])
async def test_stream_disconnect_releases_capacity_and_audits_cancellation(
    pipeline, key_store, tmp_path, disconnect_at
):
    app, provider = agent_app(pipeline, key_store, tmp_path)
    body = b'{"model":"mock-model","input":"Hello","stream":true}'
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "method": "POST",
        "scheme": "http",
        "path": "/v1/responses",
        "raw_path": b"/v1/responses",
        "query_string": b"",
        "headers": [
            (b"authorization", f"Bearer {TEST_API_KEY}".encode()),
            (b"content-type", b"application/json"),
        ],
        "client": ("127.0.0.1", 1),
        "server": ("127.0.0.1", 80),
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        if disconnect_at == "headers" or message["type"] == "http.response.body":
            raise OSError("Client disconnected during response delivery")

    with pytest.raises(ClientDisconnect):
        await app(scope, receive, send)
    assert app.state.agent_runtime.active == 0
    assert len(provider.received) == (disconnect_at == "event")
    assert len(pipeline.audit.events) == 1
    assert pipeline.audit.events[-1].error == "cancelled"


def test_provider_selection_failure_is_audited(pipeline, key_store, tmp_path):
    app, provider = agent_app(pipeline, key_store, tmp_path)
    del app.state.agent_runtime.providers["responses"]["mock"]
    result = TestClient(app).post(
        "/v1/responses",
        json={"model": "mock-model", "input": "Hello"},
        headers={"Authorization": f"Bearer {TEST_API_KEY}"},
    )
    assert result.status_code == 502
    assert pipeline.audit.events[-1].error == "response_failed"
    assert not provider.received
    assert app.state.agent_runtime.active == 0


def test_session_scope_binds_principal_and_fork():
    key = ApiKey("principal-a", hash_key(TEST_API_KEY), "tenant")
    assert session_scope(key, ["session-1"])[1] == session_scope(key, ["session-1", "session-1"])[1]
    assert (
        session_scope(key, ["session-1"])[1]
        != session_scope(replace(key, key_id="principal-b"), ["session-1"])[1]
    )
    assert session_scope(key, ["session-1"])[1] != session_scope(key, ["fork-1"])[1]
    with pytest.raises(SessionScopeError):
        session_scope(key, ["session-1", "session-2"])


def test_session_deletion_failures_and_revocation_audited(pipeline, key_store, tmp_path):
    app, _ = agent_app(pipeline, key_store, tmp_path)
    client = TestClient(app)
    assert client.delete("/v1/agent/sessions/session-1").status_code == 401
    assert pipeline.audit.events[-1].error == "invalid_api_key"
    assert key_store.revoke("key-a")
    assert key_store.authenticate(TEST_API_KEY) is None
    assert not key_store.revoke("key-a")


@pytest.mark.parametrize(
    "variable,value",
    [
        ("SAG_ENABLE_RESPONSES", "tru"),
        ("SAG_AGENT_MAX_CONCURRENT", "0"),
        ("SAG_AGENT_STREAM_IDLE_SECONDS", "nan"),
    ],
)
def test_agent_configuration_fails_closed(variable, value):
    with pytest.raises(ConfigurationError):
        Settings.from_mapping({variable: value})


def test_concurrent_canonical_values_restore_request_bytes(pipeline, ctx):
    from gateway.domain import Span
    from gateway.transformations.tokens import TokenProvenance

    transformer = pipeline.preparation._transformer
    provenance_a, provenance_b = TokenProvenance(), TokenProvenance()
    text_a, text_b = "Alex@example.com", "alex@example.com"
    token_a = transformer.transform(
        ctx, text_a, [Span(0, len(text_a), "EMAIL_ADDRESS", text_a)], provenance_a
    ).text
    other_request = replace(ctx, request_id="concurrent-request")
    token_b = transformer.transform(
        other_request, text_b, [Span(0, len(text_b), "EMAIL_ADDRESS", text_b)], provenance_b
    ).text
    assert token_a == token_b
    assert pipeline.restorer.restore(ctx, token_a, provenance_a).text == text_a
    assert pipeline.restorer.restore(other_request, token_b, provenance_b).text == text_b
    pipeline.vault.delete_conversation(ctx)
    outcome = pipeline.restorer.restore(ctx, token_a, provenance_a)
    assert outcome.text == token_a
    assert outcome.refused_unknown == 1


def test_ambiguous_canonical_spellings_fail_before_egress(pipeline, key_store, tmp_path):
    app, provider = agent_app(pipeline, key_store, tmp_path)
    response = TestClient(app).post(
        "/v1/responses",
        headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        json={
            "model": "mock-model",
            "input": "Alex@example.com alex@example.com",
            "tools": [{"type": "function", "name": "read_file", "parameters": {"type": "object"}}],
        },
    )
    assert response.status_code == 422
    assert provider.received == []


def test_legacy_endpoints_cannot_select_agent_namespace(pipeline, key_store, tmp_path):
    app, _ = agent_app(pipeline, key_store, tmp_path)
    key = key_store.authenticate(TEST_API_KEY)
    _, scope = session_scope(key, ["private-session"])
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {TEST_API_KEY}"}
    assert client.delete(f"/v1/conversations/{scope}", headers=headers).status_code == 403
    headers["X-Conversation-Id"] = scope
    response = client.post(
        "/v1/chat/completions",
        headers=headers,
        json={"model": "mock", "messages": [{"role": "user", "content": "Hello"}]},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "reserved_conversation_scope"
