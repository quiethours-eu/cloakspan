"""Opt-in synthetic agent endpoint probes; this does not qualify a coding client."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gateway.streaming.sse import json_object, parse_sse  # noqa: E402

MAX_OUTPUT_BYTES = 8_388_608
FOLLOWUP = "Reply with exactly the file contents; do not call another tool."
PATH_SCHEMA = {
    "type": "object",
    "properties": {"path": {"type": "string"}},
    "required": ["path"],
    "additionalProperties": False,
}


class PreflightError(Exception):
    """Only fixed, safe codes are printed; never remote diagnostics or arguments."""


def validate_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.hostname
        or parsed.scheme not in {"http", "https"}
        or (parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"})
    ):
        raise PreflightError("invalid_gateway_url")
    return value.rstrip("/")


def _base(url: str) -> str:
    return url[:-3] if url.endswith("/v1") else url


async def read_stream(response: httpx.Response, protocol: str) -> dict[str, Any]:
    if response.status_code != 200:
        raise PreflightError("endpoint_request_failed")
    if response.headers.get("content-type", "").split(";", 1)[0] != "text/event-stream":
        raise PreflightError("stream_content_type_failed")
    size = 0

    async def bounded():
        nonlocal size
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > MAX_OUTPUT_BYTES:
                raise PreflightError("stream_output_limit")
            yield chunk

    result: dict[str, Any] | None = None
    blocks: dict[int, dict[str, Any]] = {}
    arguments: dict[int, str] = {}
    stopped = False
    async for frame in parse_sse(bounded()):
        if frame.heartbeat:
            continue
        if frame.data == "[DONE]":
            if result is None:
                raise PreflightError("stream_terminal_missing")
            continue
        event = json_object(frame.data)
        kind = event.get("type")
        if kind in {"error", "response.failed", "response.incomplete"}:
            raise PreflightError("stream_remote_failure")
        if protocol == "responses":
            if kind == "response.completed":
                if result is not None:
                    raise PreflightError("stream_duplicate_terminal")
                result = event.get("response")
                if not isinstance(result, dict) or result.get("status") != "completed":
                    raise PreflightError("stream_terminal_invalid")
        elif kind == "message_start":
            if result is not None:
                raise PreflightError("stream_duplicate_start")
            result = event.get("message")
            if not isinstance(result, dict):
                raise PreflightError("stream_message_invalid")
        elif kind == "content_block_start":
            index = event.get("index")
            block = event.get("content_block")
            if not isinstance(index, int) or index in blocks or not isinstance(block, dict):
                raise PreflightError("stream_block_invalid")
            blocks[index] = dict(block)
            arguments[index] = ""
        elif kind == "content_block_delta":
            index = event.get("index")
            delta = event.get("delta", {})
            if index not in blocks or not isinstance(delta, dict):
                raise PreflightError("stream_block_invalid")
            if delta.get("type") == "text_delta":
                blocks[index]["text"] = blocks[index].get("text", "") + delta["text"]
            elif delta.get("type") == "input_json_delta":
                arguments[index] += delta["partial_json"]
        elif kind == "message_delta" and result is not None:
            result.update(event.get("delta", {}))
            result.setdefault("usage", {}).update(event.get("usage", {}))
        elif kind == "message_stop":
            if stopped or result is None:
                raise PreflightError("stream_terminal_invalid")
            stopped = True
    if protocol == "responses":
        if result is None:
            raise PreflightError("stream_terminal_missing")
    else:
        if result is None or not stopped or not result.get("stop_reason"):
            raise PreflightError("stream_terminal_missing")
        for index, value in arguments.items():
            if value:
                blocks[index]["input"] = json_object(value)
        result["content"] = [blocks[index] for index in sorted(blocks)]
    return result


def tool_call(response: dict[str, Any], protocol: str, expected_path: str) -> dict[str, Any]:
    source = response.get("output" if protocol == "responses" else "content", [])
    calls = [item for item in source if item.get("type") in {"function_call", "tool_use"}]
    if len(calls) != 1 or calls[0].get("name") != "read_file":
        raise PreflightError("expected_read_tool_missing")
    call = calls[0]
    arguments = json_object(call["arguments"]) if protocol == "responses" else call.get("input")
    identity = call.get("call_id" if protocol == "responses" else "id")
    if arguments != {"path": expected_path} or not isinstance(identity, str) or not identity:
        raise PreflightError("read_tool_arguments_refused")
    return call


def response_text(response: dict[str, Any], protocol: str) -> str:
    if protocol == "messages":
        return "".join(
            b.get("text", "") for b in response.get("content", []) if b["type"] == "text"
        )
    return "".join(
        part.get("text", "")
        for item in response.get("output", [])
        if item.get("type") == "message"
        for part in item.get("content", [])
        if part.get("type") == "output_text"
    )


async def probe(
    client: httpx.AsyncClient,
    *,
    gateway_url: str,
    model: str,
    protocol: str,
    workspace: Path,
    gateway_key: str,
) -> dict[str, Any]:
    base = _base(validate_url(gateway_url))
    headers = {
        "Authorization": f"Bearer {gateway_key}",
        "X-Session-Id": "preflight-" + secrets.token_hex(8),
    }
    if protocol == "messages":
        headers["anthropic-version"] = "2023-06-01"
    ready = await client.get(f"{base}/readyz")
    if ready.status_code != 200:
        raise PreflightError("gateway_not_ready")
    models = await client.get(f"{base}/v1/models", headers=headers)
    if models.status_code != 200:
        raise PreflightError("gateway_authentication_failed")
    if model not in {item.get("id") for item in models.json().get("data", [])}:
        raise PreflightError("selected_model_not_advertised")
    workspace = await asyncio.to_thread(workspace.resolve)
    if not await asyncio.to_thread(workspace.is_dir):
        raise PreflightError("workspace_missing")

    with tempfile.TemporaryDirectory(prefix="cloakspan-preflight-", dir=workspace) as directory:
        fixture = Path(directory) / "sample.txt"
        marker = "CLOAKSPAN_SYNTHETIC_ROUNDTRIP_" + secrets.token_hex(8)
        await asyncio.to_thread(fixture.write_text, marker, encoding="utf-8")
        path = fixture.relative_to(workspace).as_posix()
        prompt = f"Call read_file with path {path}. Do not guess file contents."
        if protocol == "responses":
            history: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
            payload = {
                "model": model,
                "input": history,
                "stream": True,
                "store": False,
                "tools": [
                    {
                        "type": "function",
                        "name": "read_file",
                        "description": "Read a local synthetic test file.",
                        "parameters": PATH_SCHEMA,
                    }
                ],
                "tool_choice": {"type": "function", "name": "read_file"},
            }
        else:
            history = [{"role": "user", "content": prompt}]
            payload = {
                "model": model,
                "messages": history,
                "stream": True,
                "max_tokens": 512,
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read a local synthetic test file.",
                        "input_schema": PATH_SCHEMA,
                    }
                ],
                "tool_choice": {"type": "tool", "name": "read_file"},
            }
        endpoint = f"{base}/v1/{protocol}"
        async with client.stream("POST", endpoint, headers=headers, json=payload) as result:
            if (
                result.status_code == 200
                and result.headers.get("X-Session-Id") != headers["X-Session-Id"]
            ):
                raise PreflightError("session_identity_not_confirmed")
            first = await read_stream(result, protocol)
        call = tool_call(first, protocol, path)
        # Execute only the file created here, after exact argument validation.
        # Never evaluate provider-selected commands or read provider-selected files.
        contents = await asyncio.to_thread(fixture.read_text, encoding="utf-8")
        if protocol == "responses":
            replay = {key: call[key] for key in ("type", "call_id", "name", "arguments")}
            history.extend(
                [
                    replay,
                    {
                        "type": "function_call_output",
                        "call_id": call["call_id"],
                        "output": contents,
                    },
                    {
                        "role": "user",
                        "content": FOLLOWUP,
                    },
                ]
            )
        else:
            history.extend(
                [
                    {
                        "role": "assistant",
                        "content": [{key: call[key] for key in ("type", "id", "name", "input")}],
                    },
                    {
                        "role": "user",
                        "content": [
                            {"type": "tool_result", "tool_use_id": call["id"], "content": contents},
                            {
                                "type": "text",
                                "text": FOLLOWUP,
                            },
                        ],
                    },
                ]
            )
        payload.pop("tool_choice")
        async with client.stream("POST", endpoint, headers=headers, json=payload) as result:
            if (
                result.status_code == 200
                and result.headers.get("X-Session-Id") != headers["X-Session-Id"]
            ):
                raise PreflightError("session_identity_not_confirmed")
            second = await read_stream(result, protocol)
        source = second.get("output" if protocol == "responses" else "content", [])
        if any(item.get("type") in {"function_call", "tool_use"} for item in source):
            raise PreflightError("unexpected_followup_tool")
        if response_text(second, protocol).strip() != marker:
            raise PreflightError("tool_result_not_used")
    return {
        "status": "pass",
        "protocol": protocol,
        "checks": [
            "readiness",
            "gateway_authentication",
            "advertised_model",
            "stable_session_replay",
            "native_stream_completion",
            "validated_local_read",
            "tool_result_used",
        ],
        "qualification": "synthetic endpoint preflight only; real clients remain unqualified",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--network",
        action="store_true",
        help="Explicitly make synthetic authenticated gateway requests.",
    )
    parser.add_argument("--gateway-url", default="http://127.0.0.1:8080")
    parser.add_argument("--protocol", choices=["responses", "messages"], default="responses")
    parser.add_argument("--model")
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--key-env", default="CLOAKSPAN_GATEWAY_KEY")
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args(argv)
    if not args.network:
        print(
            json.dumps(
                {
                    "status": "skip",
                    "code": "network_opt_in_required",
                    "qualification": "no network probes run",
                }
            )
        )
        return 0
    key = os.environ.get(args.key_env, "")
    if not key or not args.model or args.workspace is None or args.timeout <= 0:
        print(json.dumps({"status": "fail", "code": "preflight_configuration_missing"}))
        return 1

    async def run():
        async with httpx.AsyncClient(
            timeout=args.timeout, trust_env=False, follow_redirects=False
        ) as client:
            async with asyncio.timeout(args.timeout):
                return await probe(
                    client,
                    gateway_url=args.gateway_url,
                    model=args.model,
                    protocol=args.protocol,
                    workspace=args.workspace.resolve(),
                    gateway_key=key,
                )

    try:
        report = asyncio.run(run())
    except PreflightError as exc:
        report = {"status": "fail", "code": str(exc)}
    except Exception:
        report = {"status": "fail", "code": "preflight_probe_failed"}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
