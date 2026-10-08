"""Native Responses API transport, with the gateway's existing egress controls.

The adapter only transports already inspected payloads. It never translates
native agent requests through Chat Completions, and retries reuse one serialized
request body rather than running the privacy pipeline again.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import aclosing
from typing import Any, Literal

import httpx

from gateway.api.schema import RequestRejected
from gateway.protocols.base import _constant, _pairs, bounded_json
from gateway.routing.base import (
    _RETRYABLE_STATUS,
    MAX_RESPONSE_BYTES,
    MAX_RETRIES,
    OpenAICompatibleProvider,
    ProviderError,
    resolve_model,
)
from gateway.routing.egress import EgressPolicy


class ResponsesProvider(OpenAICompatibleProvider):
    """Direct HTTP adapter for ``POST /responses`` and native SSE.

    A pooled client shares the existing TLS verification and proxy opt-in
    policy. Only connection failures before response headers and explicitly
    retryable statuses may be retried. A timeout or body failure may follow
    processing upstream, so replaying either could duplicate a paid request.
    """

    endpoint = "responses"

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        model_override: str | None = None,
        timeout_seconds: float = 120.0,
        name: str = "openai_responses",
        trust_env: bool = False,
        trust_env_certs: bool | None = None,
        egress: EgressPolicy | None = None,
        max_retries: int = MAX_RETRIES,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        jitter: Callable[[float], float] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(
            base_url=base_url,
            api_key=api_key,
            model_override=model_override,
            timeout_seconds=timeout_seconds,
            name=name,
            trust_env=trust_env,
            trust_env_certs=trust_env_certs,
            egress=egress,
            max_retries=max_retries,
            max_response_bytes=min(max_response_bytes, MAX_RESPONSE_BYTES),
            sleep=sleep,
            jitter=jitter,
            transport=transport,
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _body(self, payload: dict[str, Any], *, stream: bool | None) -> bytes:
        body = dict(payload)
        if "model" in body or self._model_override:
            body["model"] = resolve_model(str(body.get("model", "")), self._model_override)
        if stream is not None:
            body["stream"] = stream
        # Serialize once. Every retry sends these exact bytes, including nested
        # tool arguments and tool results that have already been transformed.
        return json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _status_error(status: int) -> ProviderError:
        return ProviderError(
            f"upstream returned HTTP {status}",
            status if 400 <= status < 500 else 502,
        )

    async def _open(
        self, endpoint: str, body: bytes, *, request_headers: dict[str, str] | None = None
    ) -> httpx.Response:
        """Open one accepted response; release rejected attempts before retrying."""
        deadline = time.monotonic() + self._timeout
        last_error: ProviderError | None = None
        for attempt in range(self._max_retries + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProviderError("upstream request deadline elapsed", 504)
            # Recheck every attempt, including attempts using an existing pool.
            # Blocking DNS is kept off the server's event loop.
            await asyncio.to_thread(self._egress.validate, self._base_url)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProviderError("upstream request deadline elapsed", 504)
            client = self._pooled_client()
            request = client.build_request(
                "POST",
                f"{self._base_url}/{endpoint}",
                content=body,
                headers=self._headers() | (request_headers or {}),
                timeout=remaining,
            )
            try:
                response = await client.send(request, stream=True)
            except httpx.TimeoutException as exc:
                raise ProviderError("upstream request timed out", 504) from exc
            except httpx.ConnectError as exc:
                last_error = ProviderError("upstream request failed (ConnectError)", 502)
                if attempt >= self._max_retries:
                    raise last_error from exc
                await self._sleep(min(self._backoff(attempt, None), remaining))
                continue
            except httpx.HTTPError as exc:
                # WriteError and ReadError are ambiguous: the provider may have
                # processed the request. Never replay them or expose str(exc).
                raise ProviderError(f"upstream request failed ({type(exc).__name__})", 502) from exc

            status = response.status_code
            if 200 <= status < 300:
                return response
            retry_after = self._retry_after(response)
            # Error bodies can contain transformed prompts and credentials.
            # Do not read, log, decode, or relay them.
            await response.aclose()
            last_error = self._status_error(status)
            if status in _RETRYABLE_STATUS and attempt < self._max_retries:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProviderError("upstream request deadline elapsed", 504)
                await self._sleep(min(self._backoff(attempt, retry_after), remaining))
                continue
            raise last_error
        raise last_error or ProviderError("upstream request failed", 502)

    async def _complete_at(
        self,
        endpoint: str,
        payload: dict[str, Any],
        *,
        stream: bool | None = False,
        request_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        try:
            # One budget covers egress, retries, backoff, headers, and the whole
            # body. A slow body sending occasional bytes cannot renew it.
            async with asyncio.timeout(self._timeout):
                response = await self._open(
                    endpoint,
                    self._body(payload, stream=stream),
                    request_headers=request_headers,
                )
                try:
                    try:
                        raw = await self._read_bounded(response)
                    except httpx.TimeoutException as exc:
                        raise ProviderError("upstream response timed out", 504) from exc
                    except httpx.HTTPError as exc:
                        raise ProviderError(
                            f"upstream response failed ({type(exc).__name__})", 502
                        ) from exc
                finally:
                    await response.aclose()
        except TimeoutError as exc:
            raise ProviderError("upstream request deadline elapsed", 504) from exc
        try:
            # Decode explicitly: json.loads(bytes) also accepts UTF-16/32.
            # The shared schema checks reject ambiguous keys, nonfinite numbers,
            # invalid Unicode, and unbounded tree depth/collections. Keep the
            # transport's response byte cap rather than the request decoder's
            # separate, smaller byte cap.
            decoded = json.loads(
                raw.decode("utf-8", errors="strict"),
                object_pairs_hook=_pairs,
                parse_constant=_constant,
            )
            bounded_json(decoded)
        except (RequestRejected, UnicodeError, ValueError, RecursionError) as exc:
            raise ProviderError("upstream returned invalid UTF-8 JSON", 502) from exc
        if not isinstance(decoded, dict):
            raise ProviderError("upstream returned JSON that is not an object", 502)
        return decoded

    async def complete(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._complete_at(self.endpoint, payload)

    async def stream(self, payload: dict[str, Any]) -> AsyncIterator[bytes]:
        async with aclosing(self._stream_at(self.endpoint, payload)) as chunks:
            async for chunk in chunks:
                yield chunk

    async def _stream_at(
        self,
        endpoint: str,
        payload: dict[str, Any],
        *,
        request_headers: dict[str, str] | None = None,
    ) -> AsyncIterator[bytes]:
        """Yield bounded raw SSE bytes for inspection by the streaming pipeline.

        httpx bounds inactivity on each read. The request pipeline applies the
        configured idle and total stream deadlines around this iterator. Once
        headers are accepted there is no retry, even before the first byte.
        Closing or cancelling the iterator closes the upstream response.
        """
        response = await self._open(
            endpoint, self._body(payload, stream=True), request_headers=request_headers
        )
        try:
            media_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip()
            if media_type.lower() != "text/event-stream":
                raise ProviderError("upstream did not return an event stream", 502)
            total = 0
            try:
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > self._max_response_bytes:
                        raise ProviderError(
                            f"upstream response exceeded {self._max_response_bytes} bytes", 502
                        )
                    if chunk:
                        yield chunk
            except httpx.TimeoutException as exc:
                raise ProviderError("upstream event stream timed out", 504) from exc
            except httpx.HTTPError as exc:
                raise ProviderError(
                    f"upstream event stream failed ({type(exc).__name__})", 502
                ) from exc
        finally:
            await response.aclose()


def _sse(event: dict[str, Any]) -> bytes:
    encoded = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
    return f"event: {event['type']}\ndata: {encoded}\n\n".encode()


class MockAgentProvider:
    """Offline native protocol fixtures, including injectable tool-loop output."""

    name = "mock"

    def __init__(
        self,
        protocol: Literal["responses", "messages"] = "responses",
        response: dict[str, Any] | Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        events: list[bytes | dict[str, Any]] | None = None,
    ) -> None:
        if protocol not in {"responses", "messages"}:
            raise ValueError("unknown agent protocol")
        self.protocol = protocol
        self.received: list[dict[str, Any]] = []
        self.received_betas: list[tuple[str, ...]] = []
        self._response = response
        self._events = events

    def _record(self, payload: dict[str, Any], betas: tuple[str, ...] = ()) -> None:
        self.received.append(copy.deepcopy(payload))
        self.received_betas.append(tuple(betas))

    def _text(self, payload: dict[str, Any]) -> str:
        """Echo inspected human text and tool results, never structure metadata."""
        source = (
            payload.get("input", [])
            if self.protocol == "responses"
            else payload.get("messages", [])
        )
        if isinstance(source, str):
            return source
        text: list[str] = []

        def collect(value: Any) -> None:
            if isinstance(value, str):
                text.append(value)
            elif isinstance(value, list):
                for item in value:
                    collect(item)
            elif isinstance(value, dict):
                for field in ("text", "content", "output"):
                    if field in value:
                        collect(value[field])

        collect(source)
        return "\n".join(text)

    def _completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._response is not None:
            response = self._response(payload) if callable(self._response) else self._response
            return copy.deepcopy(response)
        text = self._text(payload)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
        output = f"[mock] received: {text}"
        if self.protocol == "messages":
            return {
                "id": f"msg_mock_{digest}",
                "type": "message",
                "role": "assistant",
                "model": payload.get("model", "mock-model"),
                "content": [{"type": "text", "text": output}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": len(text.split()), "output_tokens": len(output.split())},
            }
        return {
            "id": f"resp_mock_{digest}",
            "object": "response",
            "created_at": 0,
            "status": "completed",
            "model": payload.get("model", "mock-model"),
            "output": [
                {
                    "id": f"msg_mock_{digest}",
                    "type": "message",
                    "status": "completed",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": output, "annotations": []}],
                }
            ],
            "usage": {
                "input_tokens": len(text.split()),
                "output_tokens": len(output.split()),
                "total_tokens": len(text.split()) + len(output.split()),
            },
        }

    async def complete(
        self, payload: dict[str, Any], *, betas: tuple[str, ...] = ()
    ) -> dict[str, Any]:
        self._record(payload, betas)
        return self._completion(payload)

    async def count_tokens(
        self, payload: dict[str, Any], *, betas: tuple[str, ...] = ()
    ) -> dict[str, Any]:
        self._record(payload, betas)
        return {"input_tokens": len(self._text(payload).split())}

    async def stream(
        self, payload: dict[str, Any], *, betas: tuple[str, ...] = ()
    ) -> AsyncIterator[bytes]:
        self._record(payload, betas)
        if self._events is not None:
            for event in self._events:
                yield event if isinstance(event, bytes) else _sse(event)
            return
        response = self._completion(payload)
        if self.protocol == "messages":
            yield _sse(
                {
                    "type": "message_start",
                    "message": {
                        **response,
                        "content": [],
                        "stop_reason": None,
                        "stop_sequence": None,
                        "usage": {**response["usage"], "output_tokens": 0},
                    },
                }
            )
            for index, block in enumerate(response["content"]):
                block_type = block["type"]
                initial = {**block, "text": ""} if block_type == "text" else {**block, "input": {}}
                yield _sse(
                    {"type": "content_block_start", "index": index, "content_block": initial}
                )
                delta = (
                    {"type": "text_delta", "text": block["text"]}
                    if block_type == "text"
                    else {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}
                )
                yield _sse({"type": "content_block_delta", "index": index, "delta": delta})
                yield _sse({"type": "content_block_stop", "index": index})
            yield _sse(
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": response["stop_reason"], "stop_sequence": None},
                    "usage": {"output_tokens": response["usage"]["output_tokens"]},
                }
            )
            yield _sse({"type": "message_stop"})
            return
        sequence = 0

        def event(kind: str, **fields: Any) -> bytes:
            nonlocal sequence
            value = _sse({"type": kind, "sequence_number": sequence, **fields})
            sequence += 1
            return value

        initial_response = {**response, "status": "in_progress", "output": []}
        yield event("response.created", response=initial_response)
        for index, item in enumerate(response["output"]):
            initial_item = {**item, "status": "in_progress"}
            if item["type"] == "message":
                initial_item["content"] = []
            elif item["type"] == "function_call":
                initial_item["arguments"] = ""
            yield event("response.output_item.added", output_index=index, item=initial_item)
            if item["type"] == "message":
                for content_index, part in enumerate(item["content"]):
                    yield event(
                        "response.content_part.added",
                        item_id=item["id"],
                        output_index=index,
                        content_index=content_index,
                        part={**part, "text": ""},
                    )
                    yield event(
                        "response.output_text.delta",
                        item_id=item["id"],
                        output_index=index,
                        content_index=content_index,
                        delta=part["text"],
                    )
                    yield event(
                        "response.output_text.done",
                        item_id=item["id"],
                        output_index=index,
                        content_index=content_index,
                        text=part["text"],
                    )
                    yield event(
                        "response.content_part.done",
                        item_id=item["id"],
                        output_index=index,
                        content_index=content_index,
                        part=part,
                    )
            elif item["type"] == "function_call":
                yield event(
                    "response.function_call_arguments.delta",
                    item_id=item["id"],
                    output_index=index,
                    delta=item["arguments"],
                )
                yield event(
                    "response.function_call_arguments.done",
                    item_id=item["id"],
                    output_index=index,
                    arguments=item["arguments"],
                )
            yield event("response.output_item.done", output_index=index, item=item)
        yield event("response.completed", response=response)

    async def aclose(self) -> None:
        return None
