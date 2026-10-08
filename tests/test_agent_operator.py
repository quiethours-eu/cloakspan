"""Operator probes execute only their own fixture and make no support claim."""

from __future__ import annotations

import json
import re

import httpx
import pytest

from gateway.routing.responses import MockAgentProvider
from scripts.agent_preflight import PreflightError, main, probe, tool_call, validate_url
from scripts.benchmark_agents import measure


def test_preflight_is_offline_without_explicit_opt_in(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError("offline preflight attempted network")

    monkeypatch.setattr(httpx, "AsyncClient", forbidden)
    assert main([]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "skip"


@pytest.mark.parametrize(
    "url",
    [
        "http://public.example/v1",
        "https://gateway.example/v1?key=PRIVATE_CANARY",
        "https://PRIVATE_CANARY@gateway.example/v1",
        "https://gateway.example/v1#PRIVATE_CANARY",
    ],
)
def test_preflight_refuses_credential_bearing_or_cleartext_remote_urls(url):
    with pytest.raises(PreflightError, match="^invalid_gateway_url$"):
        validate_url(url)


def test_preflight_does_not_trust_provider_selected_tool_path():
    response = {
        "output": [
            {
                "type": "function_call",
                "call_id": "call1",
                "name": "read_file",
                "arguments": '{"path":"/private/PRIVATE_CANARY"}',
            }
        ]
    }
    with pytest.raises(PreflightError, match="^read_tool_arguments_refused$"):
        tool_call(response, "responses", "generated/sample.txt")
    response["output"].append(dict(response["output"][0]))
    with pytest.raises(PreflightError, match="^expected_read_tool_missing$"):
        tool_call(response, "responses", "generated/sample.txt")


@pytest.mark.parametrize("protocol", ["responses", "messages"])
async def test_native_preflight_runs_verified_read_and_replays_result(tmp_path, protocol):
    requests = []

    async def handler(request):
        if request.url.path == "/readyz":
            return httpx.Response(200, json={"status": "ok"})
        assert request.headers["authorization"] == "Bearer synthetic-gateway-key"
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "synthetic-model"}]})
        body = json.loads(request.content)
        requests.append((request.headers["x-session-id"], body))
        history = body["input" if protocol == "responses" else "messages"]
        if len(requests) == 1:
            path = re.fullmatch(
                r"Call read_file with path (.+)\. Do not guess file contents\.",
                history[0]["content"],
            )[1]
            assert (tmp_path / path).is_file()
            call = (
                {
                    "type": "function_call",
                    "id": "fc_test",
                    "call_id": "call_test",
                    "name": "read_file",
                    "arguments": json.dumps({"path": path}),
                    "status": "completed",
                }
                if protocol == "responses"
                else {
                    "type": "tool_use",
                    "id": "call_test",
                    "name": "read_file",
                    "input": {"path": path},
                }
            )
            output = [call]
        elif protocol == "responses":
            assert history[1]["call_id"] == history[2]["call_id"] == "call_test"
            output = [
                {
                    "id": "msg_result",
                    "type": "message",
                    "role": "assistant",
                    "status": "completed",
                    "content": [
                        {"type": "output_text", "text": history[2]["output"], "annotations": []}
                    ],
                }
            ]
        else:
            assert (
                history[1]["content"][0]["id"]
                == history[2]["content"][0]["tool_use_id"]
                == "call_test"
            )
            output = [{"type": "text", "text": history[2]["content"][0]["content"]}]
        if protocol == "responses":
            completed = {
                "id": "resp_test",
                "object": "response",
                "created_at": 0,
                "status": "completed",
                "model": "synthetic-model",
                "output": output,
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            }
        else:
            completed = {
                "id": "msg_test",
                "type": "message",
                "role": "assistant",
                "model": "synthetic-model",
                "content": output,
                "stop_reason": "tool_use" if len(requests) == 1 else "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 1},
            }
        provider = MockAgentProvider(protocol=protocol, response=completed)
        encoded = b"".join([chunk async for chunk in provider.stream(body)])
        return httpx.Response(
            200,
            content=encoded,
            headers={
                "content-type": "text/event-stream",
                "X-Session-Id": request.headers["X-Session-Id"],
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        report = await probe(
            client,
            gateway_url="https://gateway.example",
            model="synthetic-model",
            protocol=protocol,
            workspace=tmp_path,
            gateway_key="synthetic-gateway-key",
        )
    assert report["status"] == "pass"
    assert "unqualified" in report["qualification"]
    assert len(requests) == 2 and requests[0][0] == requests[1][0]
    assert list(tmp_path.iterdir()) == []


async def test_preflight_redacts_remote_error_and_cleans_fixture(tmp_path):
    async def handler(request):
        if request.url.path == "/readyz":
            return httpx.Response(200)
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "synthetic-model"}]})
        return httpx.Response(502, json={"error": "PRIVATE_CANARY"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(PreflightError, match="^endpoint_request_failed$"):
            await probe(
                client,
                gateway_url="https://gateway.example",
                model="synthetic-model",
                protocol="responses",
                workspace=tmp_path,
                gateway_key="synthetic-gateway-key",
            )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("protocol", ["responses", "messages"])
async def test_synthetic_benchmark_exercises_gateway_not_only_direct_mock(protocol):
    report = await measure(protocol, "deterministic", 512, 1)
    assert report["prompt_bytes"] == 512
    assert report["metrics"]["gateway"]["failure_rate"] == 0
    assert report["metrics"]["gateway"]["inspection_ms"]["p50"] > 0
    assert report["metrics"]["gateway"]["tool_release_after_provider_terminal_ms"]["p50"] >= 0
    assert report["metrics"]["gateway"]["cache_read_tokens"] is None
