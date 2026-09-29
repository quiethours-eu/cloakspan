"""Local preview contract and isolation regression tests."""

from __future__ import annotations

import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from gateway.config import Settings, build_detectors, load_policy_and_filters
from gateway.playground.app import create_playground_app
from gateway.playground.preview import inspect_locally
from gateway.playground.worker import WorkerBusy, WorkerSupervisor, WorkerUnavailable
from gateway.policy.engine import PolicyEngine
from gateway.policy.local_routing import LocalRouting

BASE = "http://127.0.0.1:8765"
AUTH = {"Authorization": "Bearer test-session-code"}
POST_HEADERS = {**AUTH, "Origin": BASE}


def _inspect(client: TestClient, text: str, **context):
    return client.post(
        "/api/inspect",
        headers=POST_HEADERS,
        json={
            "text": text,
            "role": context.get("role", "user"),
            "application": context.get("application", "default"),
        },
    )


def test_playground_is_authenticated_local_and_provider_free(caplog, capsys):
    app = create_playground_app(
        Settings(external_api_key="provider-secret-canary"),
        port=8765,
        access_code="test-session-code",
    )
    assert app.state.supervisor.settings.external_api_key == ""
    with TestClient(app, base_url=BASE) as client:
        assert client.get("/").status_code == 200
        assert client.get("/api/status").status_code == 401
        assert client.get("/api/status", headers=AUTH).json()["worker"] == "ready"
        assert (
            client.get("/api/status", headers={**AUTH, "Host": "evil.example"}).status_code == 403
        )
        assert (
            client.post(
                "/api/inspect",
                headers={**AUTH, "Origin": "http://evil.example"},
                json={"text": "hello", "role": "user", "application": "default"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/inspect",
                headers=POST_HEADERS,
                json={"text": "hello", "role": "user", "application": "default", "extra": "secret"},
            ).status_code
            == 422
        )
        assert (
            client.post(
                "/api/inspect",
                headers={**POST_HEADERS, "Content-Type": "application/json"},
                content=b"{",
            ).status_code
            == 422
        )
        assert (
            client.post(
                "/api/inspect",
                headers=POST_HEADERS,
                content=b"x" * (256 * 1024 + 1),
            ).status_code
            == 413
        )

        clean = _inspect(client, "Public announcement")
        assert clean.status_code == 200
        assert clean.json()["provider_contacted"] is False
        assert clean.json()["decision"]["effective_action"] == "allow"
        assert clean.json()["outbound_preview"]["text"] == "Public announcement"

        transformed = _inspect(client, "😀 Contact alex@example.com")
        assert transformed.status_code == 200
        result = transformed.json()
        assert result["detections"][0]["start"] == 10
        assert result["outbound_preview"]["text"].startswith("😀 Contact <EMAIL_ADDRESS:v1:")
        repeated = _inspect(client, "😀 Contact alex@example.com").json()
        assert repeated["outbound_preview"]["text"] != result["outbound_preview"]["text"]

        blocked = _inspect(client, "AKIAIOSFODNN7EXAMPLE")
        assert blocked.status_code == 200
        assert blocked.json()["decision"]["effective_action"] == "block"
        assert blocked.json()["outbound_preview"] is None
    captured = capsys.readouterr()
    assert "AKIAIOSFODNN7EXAMPLE" not in caplog.text + captured.out + captured.err
    assert "provider-secret-canary" not in caplog.text + captured.out + captured.err


def test_default_gateway_has_no_playground_routes():
    from gateway.api.app import create_app

    app = create_app(settings=Settings())
    paths = {route.path for route in app.routes}
    assert "/api/inspect" not in paths
    assert "/api/status" not in paths


def test_preview_uses_policy_and_local_routing_without_provider_construction(monkeypatch):
    import gateway.config as config

    def forbidden(*_args, **_kwargs):
        raise AssertionError("provider assembly was reached")

    monkeypatch.setattr(config, "build_providers", forbidden)
    settings = Settings(local_routing=LocalRouting.ALL, local_model="my-local-model")
    policy, filters = load_policy_and_filters(settings)
    detectors = build_detectors(settings, filters=filters)
    result = inspect_locally(
        settings, detectors, policy, "Email alex@example.com", "user", "default"
    )
    assert result["decision"]["base_action"] == "transform"
    assert result["decision"]["effective_action"] == "route_local"
    assert result["decision"]["destination"] == "local"
    assert result["outbound_preview"]["model"] == "my-local-model"
    assert "alex@example.com" not in result["outbound_preview"]["text"]


def test_allow_with_detection_keeps_original_text():
    settings = Settings()
    policy = PolicyEngine.from_dict(
        {
            "version": "allow-preview",
            "default_destination": "external",
            "rules": [{"name": "allow", "priority": 1, "action": {"type": "allow"}}],
        }
    )
    text = "Email alex@example.com"
    result = inspect_locally(settings, build_detectors(settings), policy, text, "user", "default")
    assert result["detections"][0]["entity_type"] == "EMAIL_ADDRESS"
    assert result["decision"]["effective_action"] == "allow"
    assert result["outbound_preview"]["text"] == text


def test_preview_vault_records_are_disposed(monkeypatch):
    import gateway.playground.preview as preview

    created = []
    original_vault = preview.SurrogateVault

    def capture_vault(*args, **kwargs):
        vault = original_vault(*args, **kwargs)
        created.append(vault)
        return vault

    monkeypatch.setattr(preview, "SurrogateVault", capture_vault)
    settings = Settings()
    policy, filters = load_policy_and_filters(settings)
    detectors = build_detectors(settings, filters=filters)
    for _ in range(2):
        inspect_locally(settings, detectors, policy, "alex@example.com", "user", "default")
    assert len(created) == 2
    assert all(len(vault._backend) == 0 for vault in created)


def test_preview_applies_custom_filter_precedence(tmp_path):
    path = tmp_path / "filters.yaml"
    path.write_text(
        "version: 1\nfilters:\n  - name: private-reference\n"
        "    entity_type: PRIVATE_REFERENCE\n"
        "    match:\n      type: dictionary\n      terms: [example-reference]\n"
        "    action: block\n",
        encoding="utf-8",
    )
    settings = Settings(filters_path=path)
    policy, filters = load_policy_and_filters(settings)
    result = inspect_locally(
        settings,
        build_detectors(settings, filters=filters),
        policy,
        "example-reference",
        "user",
        "default",
    )
    assert result["decision"]["effective_rule"] == "filter:private-reference"
    assert result["decision"]["effective_action"] == "block"
    assert result["outbound_preview"] is None


def _test_worker(connection, _settings):
    """Picklable worker used to prove a hung child is killed and replaced."""
    from gateway.playground.worker import _receive, _send

    _send(connection, {"ready": True}, 1024)
    try:
        while True:
            job = _receive(connection, 256 * 1024 + 1024)
            if job["text"] == "hang":
                time.sleep(5)
            _send(connection, {"ok": job["text"]}, 1024)
    except EOFError:
        pass
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_worker_timeout_reaps_child_and_next_job_succeeds(monkeypatch):
    import gateway.playground.worker as worker

    monkeypatch.setattr(worker, "_worker_main", _test_worker)
    monkeypatch.setattr(worker, "INSPECT_TIMEOUT_SECONDS", 0.2)
    supervisor = WorkerSupervisor(Settings())
    await supervisor.start()
    first_pid = supervisor._process.pid
    try:
        pending = asyncio.create_task(
            supervisor.inspect({"text": "hang", "role": "user", "application": "default"})
        )
        await asyncio.sleep(0.05)
        with pytest.raises(WorkerBusy):
            await supervisor.inspect({"text": "quick", "role": "user", "application": "default"})
        with pytest.raises(WorkerUnavailable):
            await pending
        for _ in range(30):
            if supervisor.ready:
                break
            await asyncio.sleep(0.1)
        assert supervisor.ready
        assert supervisor._process.pid != first_pid
        assert await supervisor.inspect(
            {"text": "quick", "role": "user", "application": "default"}
        ) == {"ok": "quick"}
    finally:
        await supervisor.close()
