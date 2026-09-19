"""Request-body limits must hold before JSON parsing or inspection."""

from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI

from gateway.api.app import create_app
from gateway.config import Settings

from .conftest import TEST_API_KEY


def _chat_body(content: str) -> bytes:
    return json.dumps(
        {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": content}],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()


async def _post_chunks(
    app: FastAPI,
    chunks: list[bytes],
    *,
    authorization: str | None = TEST_API_KEY,
    content_length: int | None = None,
) -> tuple[int, dict[str, Any], int]:
    """Drive ASGI directly so tests can observe how many chunks were consumed."""
    request_headers = [(b"host", b"testserver"), (b"content-type", b"application/json")]
    if authorization is not None:
        request_headers.append((b"authorization", f"Bearer {authorization}".encode()))
    if content_length is not None:
        request_headers.append((b"content-length", str(content_length).encode()))

    chunks_read = 0
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        nonlocal chunks_read
        if chunks_read >= len(chunks):
            return {"type": "http.disconnect"}
        chunk = chunks[chunks_read]
        chunks_read += 1
        return {
            "type": "http.request",
            "body": chunk,
            "more_body": chunks_read < len(chunks),
        }

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/v1/chat/completions",
            "raw_path": b"/v1/chat/completions",
            "query_string": b"",
            "headers": request_headers,
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "root_path": "",
        },
        receive,
        send,
    )

    start = next(message for message in sent if message["type"] == "http.response.start")
    response_body = b"".join(
        message.get("body", b"") for message in sent if message["type"] == "http.response.body"
    )
    return start["status"], json.loads(response_body), chunks_read


def _app(pipeline, key_store, max_request_bytes: int) -> FastAPI:
    return create_app(
        pipeline=pipeline,
        key_store=key_store,
        settings=Settings(max_request_bytes=max_request_bytes),
    )


def test_request_byte_limit_defaults_to_one_mebibyte_and_loads_from_env(monkeypatch):
    assert Settings().max_request_bytes == 1_048_576

    monkeypatch.setenv("SAG_MAX_REQUEST_BYTES", "2048")
    assert Settings.from_env().max_request_bytes == 2048


async def test_exact_utf8_byte_boundary_is_accepted(pipeline, key_store):
    encoded = _chat_body("Sveiki, ž")
    app = _app(pipeline, key_store, len(encoded))

    status, _, chunks_read = await _post_chunks(app, [encoded])

    assert status == 200
    assert chunks_read == 1


async def test_oversized_body_is_openai_shaped_and_never_inspected(
    pipeline, key_store, mock_provider, audit_sink
):
    encoded = _chat_body("Sveiki, ž")
    app = _app(pipeline, key_store, len(encoded) - 1)

    status, response, _ = await _post_chunks(app, [encoded])

    assert status == 413
    assert response == {
        "error": {
            "message": "Request body exceeds the maximum allowed size.",
            "type": "invalid_request_error",
            "param": None,
            "code": "request_too_large",
        }
    }
    assert mock_provider.received == []
    assert audit_sink.events == []


async def test_chunked_body_stops_being_read_when_limit_is_crossed(pipeline, key_store):
    app = _app(pipeline, key_store, 64)
    chunks = [b"{" + (b" " * 31), b" " * 33, b"this chunk must not be consumed"]

    status, response, chunks_read = await _post_chunks(app, chunks)

    assert status == 413
    assert response["error"]["code"] == "request_too_large"
    assert chunks_read == 2


async def test_oversized_content_length_is_rejected_without_reading(pipeline, key_store):
    app = _app(pipeline, key_store, 64)

    status, response, chunks_read = await _post_chunks(app, [b"{}"], content_length=65)

    assert status == 413
    assert response["error"]["code"] == "request_too_large"
    assert chunks_read == 0


async def test_authentication_still_happens_before_body_rejection(pipeline, key_store):
    app = _app(pipeline, key_store, 64)

    status, response, chunks_read = await _post_chunks(
        app,
        [b"{}"],
        authorization=None,
        content_length=65,
    )

    assert status == 401
    assert response["error"]["code"] == "invalid_api_key"
    assert chunks_read == 0


async def test_malformed_json_under_the_limit_keeps_existing_400(pipeline, key_store):
    app = _app(pipeline, key_store, 64)

    status, response, chunks_read = await _post_chunks(app, [b"{not json"])

    assert status == 400
    assert response["error"] == {
        "message": "Request body is not valid JSON.",
        "type": "invalid_request_error",
        "param": None,
        "code": None,
    }
    assert chunks_read == 1
