"""Native agent transport contracts exercise real HTTP adapters offline."""

from __future__ import annotations

import asyncio
import json
import ssl
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest

from gateway.protocols.base import MAX_COLLECTION, MAX_DEPTH
from gateway.protocols.messages import SUPPORTED_MESSAGES_BETAS
from gateway.routing.base import ProviderError, verification_context
from gateway.routing.egress import EgressBlockedError, EgressPolicy
from gateway.routing.messages import MessagesProvider
from gateway.routing.responses import MockAgentProvider, ResponsesProvider

LOCAL = EgressPolicy(name="test", allow_private=True)
PROVIDER_KEY = "test-native-provider-secret"
CANARY = "test-secret-prompt-value"


async def no_sleep(_seconds: float) -> None:
    return None


def provider_for(provider_type, handler, **kwargs):
    return provider_type(
        base_url="http://127.0.0.1:11434/v1",
        egress=kwargs.pop("egress", LOCAL),
        transport=httpx.MockTransport(handler),
        sleep=kwargs.pop("sleep", no_sleep),
        jitter=lambda maximum: maximum,
        **kwargs,
    )


class ScriptStream(httpx.AsyncByteStream):
    def __init__(
        self,
        chunks: list[bytes],
        error: Exception | None = None,
        wait: asyncio.Event | None = None,
    ) -> None:
        self.chunks = chunks
        self.error = error
        self.wait = wait
        self.closed = False
        self.reads = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            self.reads += 1
            yield chunk
        if self.wait is not None:
            await self.wait.wait()
        if self.error is not None:
            raise self.error

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.parametrize("provider_type", [ResponsesProvider, MessagesProvider])
class TestAgentTransport:
    async def test_native_endpoint_auth_and_model_override(self, provider_type):
        captured: list[httpx.Request] = []

        def handler(request):
            captured.append(request)
            return httpx.Response(200, json={"id": "native", "new_field": True})

        provider = provider_for(
            provider_type, handler, api_key=PROVIDER_KEY, model_override="configured-model"
        )
        payload = {"model": "requested", "input": "<EMAIL_1>", "stream": True}
        try:
            assert await provider.complete(payload) == {"id": "native", "new_field": True}
            request = captured[0]
            expected_endpoint = "responses" if provider_type is ResponsesProvider else "messages"
            assert request.url.path == f"/v1/{expected_endpoint}"
            assert json.loads(request.content) == {
                **payload,
                "model": "configured-model",
                "stream": False,
            }
            if provider_type is MessagesProvider:
                assert request.headers["x-api-key"] == PROVIDER_KEY
                assert request.headers["anthropic-version"] == "2023-06-01"
                assert "Authorization" not in request.headers
                assert "anthropic-beta" not in request.headers
            else:
                assert request.headers["Authorization"] == f"Bearer {PROVIDER_KEY}"
            assert payload["model"] == "requested"
            assert payload["stream"] is True
        finally:
            await provider.aclose()

    async def test_pool_is_reused_and_close_is_idempotent(self, provider_type):
        provider = provider_for(provider_type, lambda r: httpx.Response(200, json={"ok": True}))
        await provider.complete({})
        first = provider._pooled_client()
        await provider.complete({})
        assert provider._pooled_client() is first
        assert provider._trust_env is False
        assert first.follow_redirects is False
        await provider.aclose()
        assert first.is_closed
        assert provider._client is None
        await provider.aclose()

    async def test_real_client_keeps_tls_and_proxy_policy(self, provider_type):
        provider = provider_type("https://8.8.8.8/v1")
        try:
            client = provider._pooled_client()
            assert provider._transport is None
            assert client._trust_env is False
            assert client.follow_redirects is False
            context = client._transport._pool._ssl_context
            assert context is verification_context(False)
            assert context.verify_mode == ssl.CERT_REQUIRED
            assert context.check_hostname is True
        finally:
            await provider.aclose()

    async def test_separate_provider_instances_have_separate_pools(self, provider_type):
        def handler(request):
            return httpx.Response(200, json={"ok": True})

        first = provider_for(provider_type, handler)
        second = provider_for(provider_type, handler)
        try:
            assert first._pooled_client() is not second._pooled_client()
        finally:
            await first.aclose()
            await second.aclose()

    @pytest.mark.parametrize("streaming", [False, True])
    @pytest.mark.parametrize("retry_status", [429, 500, 502, 503, 504])
    async def test_retry_preserves_exact_transformed_payload(
        self, provider_type, streaming, retry_status
    ):
        seen: list[bytes] = []
        policies: list[str] = []

        class CountingPolicy(EgressPolicy):
            def validate(self, url):
                policies.append(url)

        def handler(request):
            seen.append(request.content)
            if len(seen) == 1:
                return httpx.Response(retry_status, content=CANARY.encode())
            if streaming:
                return httpx.Response(
                    200,
                    headers={"Content-Type": "text/event-stream; charset=utf-8"},
                    content=b"data: {}\n\n",
                )
            return httpx.Response(200, json={"ok": True})

        provider = provider_for(provider_type, handler, egress=CountingPolicy())
        body = {"input": [{"content": "<EMAIL_1>"}], "model": "m"}
        try:
            if streaming:
                assert b"".join([chunk async for chunk in provider.stream(body)]) == b"data: {}\n\n"
            else:
                assert await provider.complete(body) == {"ok": True}
            assert len(seen) == 2
            assert seen[0] == seen[1]
            assert len(policies) == 3  # startup, first attempt, retry
            assert "stream" not in body
        finally:
            await provider.aclose()

    async def test_connect_error_retries_but_write_and_read_errors_do_not(self, provider_type):
        for error_type, expected in (
            (httpx.ConnectError, 3),
            (httpx.WriteError, 1),
            (httpx.ReadError, 1),
            (httpx.ReadTimeout, 1),
        ):
            attempts: list[httpx.Request] = []

            def handler(request, exception=error_type, recorded=attempts):
                recorded.append(request)
                raise exception(f"{PROVIDER_KEY} {CANARY}", request=request)

            provider = provider_for(provider_type, handler)
            try:
                with pytest.raises(ProviderError) as caught:
                    await provider.complete({"input": CANARY})
                assert len(attempts) == expected
                assert PROVIDER_KEY not in str(caught.value)
                assert CANARY not in str(caught.value)
            finally:
                await provider.aclose()

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 422, 501, 302])
    async def test_unsafe_status_is_not_retried_or_followed(self, provider_type, status):
        attempts: list[httpx.Request] = []
        body = ScriptStream([f"{CANARY} {PROVIDER_KEY}".encode()])

        def handler(request):
            attempts.append(request)
            return httpx.Response(
                status, headers={"Location": "http://169.254.169.254/"}, stream=body
            )

        provider = provider_for(provider_type, handler)
        try:
            with pytest.raises(ProviderError) as caught:
                await provider.complete({"input": CANARY})
            assert len(attempts) == 1
            assert body.reads == 0
            assert body.closed
            assert CANARY not in str(caught.value)
            assert PROVIDER_KEY not in str(caught.value)
        finally:
            await provider.aclose()

    async def test_deadline_shrinks_across_retries(self, provider_type):
        observed: list[float] = []

        def handler(request):
            observed.append(request.extensions["timeout"]["read"])
            return httpx.Response(503)

        provider = provider_for(provider_type, handler, timeout_seconds=37)
        try:
            with pytest.raises(ProviderError):
                await provider.complete({})
            assert len(observed) == 3
            assert 36 < observed[0] <= 37
            assert observed[0] > observed[-1]
        finally:
            await provider.aclose()

    async def test_total_body_deadline_closes_without_retry(self, provider_type):
        body = ScriptStream([b'{"ok":'], wait=asyncio.Event())
        attempts: list[httpx.Request] = []

        def handler(request):
            attempts.append(request)
            return httpx.Response(200, stream=body)

        provider = provider_for(provider_type, handler, timeout_seconds=0.02)
        try:
            with pytest.raises(ProviderError) as caught:
                await provider.complete({})
            assert caught.value.status_code == 504
            assert len(attempts) == 1
            assert body.closed
        finally:
            await provider.aclose()

    @pytest.mark.parametrize("response", [b"not-json", b"[]", b'"text"', b"42"])
    async def test_malformed_json_is_safe_provider_error(self, provider_type, response):
        provider = provider_for(provider_type, lambda r: httpx.Response(200, content=response))
        try:
            with pytest.raises(ProviderError) as caught:
                await provider.complete({})
            assert caught.value.status_code == 502
        finally:
            await provider.aclose()

    @pytest.mark.parametrize(
        "encoding",
        ["utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be", "latin-1"],
    )
    async def test_response_requires_utf8_even_if_json_decoder_accepts_other_encodings(
        self, provider_type, encoding
    ):
        raw = json.dumps({"text": f"{CANARY} é"}, ensure_ascii=False).encode(encoding)
        provider = provider_for(provider_type, lambda r: httpx.Response(200, content=raw))
        try:
            with pytest.raises(ProviderError, match="invalid UTF-8 JSON") as caught:
                await provider.complete({})
            assert caught.value.status_code == 502
            assert CANARY not in str(caught.value)
        finally:
            await provider.aclose()

    @pytest.mark.parametrize(
        "raw",
        [
            b'{"a":1,"a":2}',
            b'{"a":1,"\\u0061":2}',
            b'{"nested":{"a":1,"a":2}}',
            b'{"number":NaN}',
            b'{"number":Infinity}',
            b'{"number":-Infinity}',
            b'{"number":1e999}',
            b'{"number":-1e999}',
            b'{"text":"\\ud800"}',
            b'{"\\udfff":1}',
            b'{"text":"\xff"}',
        ],
    )
    async def test_ambiguous_or_invalid_json_is_closed_without_retry(self, provider_type, raw):
        attempts: list[httpx.Request] = []
        body = ScriptStream([raw])

        def handler(request):
            attempts.append(request)
            return httpx.Response(200, stream=body)

        provider = provider_for(provider_type, handler, api_key=PROVIDER_KEY)
        try:
            with pytest.raises(ProviderError, match="invalid UTF-8 JSON") as caught:
                await provider.complete({"input": CANARY})
            assert caught.value.status_code == 502
            assert CANARY not in str(caught.value)
            assert PROVIDER_KEY not in str(caught.value)
            assert len(attempts) == 1
            assert body.closed
        finally:
            await provider.aclose()

    @pytest.mark.parametrize(
        "raw",
        [
            ('{"a":' + "[" * (MAX_DEPTH + 1) + "0" + "]" * (MAX_DEPTH + 1) + "}").encode(),
            json.dumps({"a": [0] * (MAX_COLLECTION + 1)}).encode(),
            json.dumps({str(index): 0 for index in range(MAX_COLLECTION + 1)}).encode(),
        ],
    )
    async def test_response_tree_limits_are_enforced(self, provider_type, raw):
        provider = provider_for(provider_type, lambda r: httpx.Response(200, content=raw))
        try:
            with pytest.raises(ProviderError, match="invalid UTF-8 JSON"):
                await provider.complete({})
        finally:
            await provider.aclose()

    async def test_valid_utf8_response_retains_response_cap_and_unicode(self, provider_type):
        # Responses use the 8MiB transport cap, not the 4MiB request JSON cap.
        response = {"text": "x" * (5 * 1024 * 1024), "unicode": "é😀"}
        provider = provider_for(provider_type, lambda r: httpx.Response(200, json=response))
        try:
            assert await provider.complete({}) == response
        finally:
            await provider.aclose()

    async def test_egress_change_blocks_before_any_bytes_reach_transport(
        self, provider_type, monkeypatch
    ):
        addresses = ["8.8.8.8"]
        sent: list[httpx.Request] = []
        monkeypatch.setattr("gateway.routing.egress._resolve", lambda host: list(addresses))

        def handler(request):
            sent.append(request)
            return httpx.Response(200, json={"ok": True})

        provider = provider_type(
            "https://upstream.example/v1", transport=httpx.MockTransport(handler)
        )
        addresses[:] = ["169.254.169.254"]
        try:
            with pytest.raises(EgressBlockedError):
                await provider.complete({})
            assert sent == []
        finally:
            await provider.aclose()

    @pytest.mark.parametrize("streaming", [False, True])
    async def test_response_size_is_bounded_incrementally(self, provider_type, streaming):
        body = ScriptStream([b"1234", b"5678", b"9", b"unused"])
        provider = provider_for(
            provider_type,
            lambda r: httpx.Response(
                200, headers={"Content-Type": "text/event-stream"}, stream=body
            ),
            max_response_bytes=8,
        )
        try:
            with pytest.raises(ProviderError, match="exceeded"):
                if streaming:
                    _ = [chunk async for chunk in provider.stream({})]
                else:
                    await provider.complete({})
            assert body.reads == 3
            assert body.closed
        finally:
            await provider.aclose()

    @pytest.mark.parametrize("content_type", [None, "application/json", "text/html"])
    async def test_stream_requires_native_sse_before_reading_body(
        self, provider_type, content_type
    ):
        body = ScriptStream([CANARY.encode()])
        headers = {} if content_type is None else {"Content-Type": content_type}
        provider = provider_for(
            provider_type, lambda r: httpx.Response(200, headers=headers, stream=body)
        )
        try:
            with pytest.raises(ProviderError, match="event stream"):
                _ = [chunk async for chunk in provider.stream({})]
            assert body.reads == 0
            assert body.closed
        finally:
            await provider.aclose()

    @pytest.mark.parametrize("delivered", [False, True])
    async def test_stream_body_failure_never_retries(self, provider_type, delivered):
        calls: list[httpx.Request] = []
        body = ScriptStream(
            [b"data: {}\n\n"] if delivered else [],
            error=httpx.ReadError(f"{CANARY} {PROVIDER_KEY}"),
        )

        def handler(request):
            calls.append(request)
            return httpx.Response(200, headers={"Content-Type": "text/event-stream"}, stream=body)

        provider = provider_for(provider_type, handler)
        try:
            with pytest.raises(ProviderError) as caught:
                _ = [chunk async for chunk in provider.stream({})]
            assert len(calls) == 1
            assert CANARY not in str(caught.value)
            assert PROVIDER_KEY not in str(caught.value)
            assert body.closed
        finally:
            await provider.aclose()

    async def test_client_cancellation_releases_stream_and_keeps_pool_usable(self, provider_type):
        waiting = asyncio.Event()
        delivered = asyncio.Event()
        body = ScriptStream([b"data: {}\n\n"], wait=waiting)
        attempts: list[httpx.Request] = []

        def handler(request):
            attempts.append(request)
            if len(attempts) > 1:
                return httpx.Response(200, json={"after": "cancel"})
            return httpx.Response(200, headers={"Content-Type": "text/event-stream"}, stream=body)

        provider = provider_for(provider_type, handler)

        async def consume():
            async for _ in provider.stream({}):
                delivered.set()

        task = asyncio.create_task(consume())
        try:
            await asyncio.wait_for(delivered.wait(), 1)
            pool = provider._pooled_client()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert body.closed
            assert await provider.complete({}) == {"after": "cancel"}
            assert provider._pooled_client() is pool
        finally:
            task.cancel()
            await provider.aclose()


async def test_messages_count_tokens_uses_native_transformed_body_and_no_stream_field():
    captured: list[httpx.Request] = []

    def handler(request):
        captured.append(request)
        return httpx.Response(200, json={"input_tokens": 12})

    provider = provider_for(MessagesProvider, handler, api_key=PROVIDER_KEY)
    payload = {"model": "m", "messages": [{"role": "user", "content": "<EMAIL_1>"}]}
    try:
        assert await provider.count_tokens(payload) == {"input_tokens": 12}
        assert captured[0].url.path == "/v1/messages/count_tokens"
        assert json.loads(captured[0].content) == payload
        assert captured[0].headers["anthropic-version"] == "2023-06-01"
    finally:
        await provider.aclose()


@pytest.mark.parametrize("operation", ["complete", "stream", "count_tokens"])
async def test_messages_beta_controls_are_request_local_and_keep_fixed_auth(operation):
    captured: list[httpx.Request] = []
    arrived = asyncio.Event()
    betas = ("claude-code-20250219", "effort-2025-11-24")

    async def handler(request):
        captured.append(request)
        if len(captured) == 2:
            arrived.set()
        await asyncio.wait_for(arrived.wait(), 1)
        if operation == "stream":
            return httpx.Response(
                200, headers={"Content-Type": "text/event-stream"}, content=b"data: {}\n\n"
            )
        return httpx.Response(200, json={"input_tokens": 1})

    provider = provider_for(MessagesProvider, handler, api_key=PROVIDER_KEY)

    async def invoke(label, beta_controls):
        call = getattr(provider, operation)({"model": label}, betas=beta_controls)
        if operation == "stream":
            return b"".join([chunk async for chunk in call])
        return await call

    try:
        await asyncio.gather(invoke("with-beta", betas), invoke("without-beta", ()))
        by_model = {json.loads(request.content)["model"]: request for request in captured}
        assert by_model["with-beta"].headers["anthropic-beta"] == ",".join(betas)
        assert "anthropic-beta" not in by_model["without-beta"].headers
        for request in captured:
            assert request.headers["x-api-key"] == PROVIDER_KEY
            assert request.headers["anthropic-version"] == "2023-06-01"
            assert "Authorization" not in request.headers
        assert "anthropic-beta" not in provider._headers()
    finally:
        await provider.aclose()


@pytest.mark.parametrize("operation", ["complete", "stream", "count_tokens"])
@pytest.mark.parametrize(
    "betas",
    [
        ("context-management-2025-06-27",),
        ("unknown-beta",),
        ("effort-2025-11-24\r\nx-api-key: stolen",),
        ("effort-2025-11-24", "effort-2025-11-24"),
        (None,),
        (["effort-2025-11-24"],),
        "effort-2025-11-24",
        ["effort-2025-11-24"],
    ],
)
async def test_messages_unsupported_beta_controls_fail_before_transport(operation, betas):
    sent: list[httpx.Request] = []

    def handler(request):
        sent.append(request)
        return httpx.Response(200, json={})

    provider = provider_for(MessagesProvider, handler)
    try:
        with pytest.raises(ProviderError, match="unsupported native Messages beta") as caught:
            call = getattr(provider, operation)({}, betas=betas)
            if operation == "stream":
                _ = [chunk async for chunk in call]
            else:
                await call
        assert caught.value.status_code == 400
        assert sent == []
    finally:
        await provider.aclose()


@pytest.mark.parametrize("streaming", [False, True])
async def test_messages_retry_reuses_beta_controls_and_transformed_body(streaming):
    captured: list[httpx.Request] = []
    betas = tuple(sorted(SUPPORTED_MESSAGES_BETAS))

    def handler(request):
        captured.append(request)
        if len(captured) == 1:
            return httpx.Response(503, content=CANARY.encode())
        if streaming:
            return httpx.Response(
                200, headers={"Content-Type": "text/event-stream"}, content=b"data: {}\n\n"
            )
        return httpx.Response(200, json={"ok": True})

    provider = provider_for(MessagesProvider, handler, api_key=PROVIDER_KEY)
    try:
        if streaming:
            _ = [chunk async for chunk in provider.stream({"messages": ["<EMAIL_1>"]}, betas=betas)]
        else:
            await provider.complete({"messages": ["<EMAIL_1>"]}, betas=betas)
        assert len(captured) == 2
        assert captured[0].content == captured[1].content
        assert captured[0].headers["anthropic-beta"] == captured[1].headers["anthropic-beta"]
        assert captured[0].headers["anthropic-beta"] == ",".join(betas)
    finally:
        await provider.aclose()


@pytest.mark.parametrize("provider_type", [ResponsesProvider, MessagesProvider])
async def test_stream_explicit_close_releases_upstream_after_one_chunk(provider_type):
    body = ScriptStream([b"data: {}\n\n", b"data: unused\n\n"])
    provider = provider_for(
        provider_type,
        lambda r: httpx.Response(200, headers={"Content-Type": "text/event-stream"}, stream=body),
    )
    chunks = provider.stream({})
    try:
        assert await anext(chunks) == b"data: {}\n\n"
        await chunks.aclose()
        assert body.closed
        assert body.reads == 1
    finally:
        await chunks.aclose()
        await provider.aclose()


async def test_mock_messages_records_beta_controls_separately_from_payload():
    provider = MockAgentProvider("messages")
    payload = {"model": "m", "messages": [{"role": "user", "content": "synthetic"}]}
    betas = ("claude-code-20250219", "effort-2025-11-24")
    await provider.complete(payload, betas=betas)
    await provider.count_tokens(payload)
    _ = [chunk async for chunk in provider.stream(payload, betas=betas)]
    assert provider.received == [payload, payload, payload]
    assert provider.received_betas == [betas, (), betas]


@pytest.mark.parametrize("protocol", ["responses", "messages"])
async def test_mock_native_protocols_are_deterministic_and_capture_inspected_payload(protocol):
    provider = MockAgentProvider(protocol)
    payload: dict[str, Any] = {"model": "m"}
    payload["input" if protocol == "responses" else "messages"] = [
        {"role": "user", "content": [{"type": "text", "text": "<EMAIL_1>"}]}
    ]
    first = await provider.complete(payload)
    second = await provider.complete(payload)
    assert first == second
    assert "<EMAIL_1>" in json.dumps(first)
    count = await provider.count_tokens(payload)
    assert count == {"input_tokens": 1}
    chunks = [chunk async for chunk in provider.stream(payload)]
    assert len(chunks) > 3
    assert b"<EMAIL_1>" in b"".join(chunks)
    assert (
        b"message_stop" in chunks[-1]
        if protocol == "messages"
        else b"response.completed" in (chunks[-1])
    )
    payload["model"] = "mutated"
    assert all(record["model"] == "m" for record in provider.received)
    await provider.aclose()


async def test_mock_supports_scripted_tool_output_for_full_agent_loop():
    seen: list[dict[str, Any]] = []

    def fixture(payload):
        seen.append(payload)
        return {
            "id": "resp_tools",
            "object": "response",
            "status": "completed",
            "output": [
                {
                    "id": "fc_safe",
                    "type": "function_call",
                    "call_id": "call_safe",
                    "name": "read_file",
                    "arguments": '{"path":"README.md"}',
                    "status": "completed",
                }
            ],
        }

    provider = MockAgentProvider(response=fixture)
    chunks = [chunk async for chunk in provider.stream({"input": "<EMAIL_1>"})]
    assert seen == [{"input": "<EMAIL_1>"}]
    assert b"response.function_call_arguments.delta" in b"".join(chunks)
    assert b"response.function_call_arguments.done" in b"".join(chunks)
    assert b"response.completed" in chunks[-1]
