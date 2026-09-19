"""Provider adapter interface and built-in adapters.

The interface exists so that LiteLLM is *one implementation among several*
rather than a load-bearing dependency. LiteLLM is MIT at the core but ships a
proprietary ``enterprise/`` directory and moves very fast; we must always be
able to leave. See ADR-0002.

Three adapters ship in v1:

* ``MockProvider``   -- deterministic, offline, used by ``make demo`` and every
                        test. This is what makes the demo work with no paid
                        credentials.
* ``OpenAICompatibleProvider`` -- direct HTTP to any OpenAI-compatible endpoint
                        (OpenAI, Ollama, vLLM, OpenRouter, Bedrock via a
                        compatible shim). No LiteLLM dependency at all.
* ``LiteLLMProvider`` -- optional, multi-provider, imported lazily so the core
                        never requires it.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import random
import ssl
import time
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

import httpx

from gateway.routing.egress import EgressPolicy


@functools.lru_cache(maxsize=2)
def verification_context(trust_env: bool) -> ssl.SSLContext:
    """The TLS trust store, built once and shared.

    ``verify=True`` makes httpx build an ``SSLContext`` from scratch, which
    loads and parses the entire CA bundle. That is **~400 ms of CPU on
    Windows**, and the client below is constructed per request, so every
    upstream call was paying it.

    It stayed invisible for two reasons, both worth recording because each is
    the kind of thing that hides a defect rather than one:

    * ``scripts/benchmark.py`` deliberately excludes the provider call, on the
      sound argument that upstream latency says more about the upstream than
      about us. This cost is ours, and it sat just outside what that measures.
    * Every test injects a ``transport``, and the branch in ``_post`` sets
      ``verify`` only when there is no transport. So the whole suite takes the
      cheap path: the seam that makes the tests fast is the seam that hid this.

    Measured on loopback -- no network, no handshake -- a fresh client per
    request cost **+389 ms** against a reused one, and the figure was within
    60 ms of the same measurement over Tailscale and over TLS to a public API.
    A constant, not a latency.

    Sharing changes no verification behaviour. An ``SSLContext`` is designed to
    be shared across connections -- a long-lived client does exactly this with
    it internally -- and the object here is the one httpx would have built,
    from its own ``create_ssl_context``, so certificate and hostname checking
    are identical.

    Keyed on ``trust_env`` because httpx honours ``SSL_CERT_FILE`` and
    ``SSL_CERT_DIR`` only when it is set, so the two yield different stores.
    """
    return httpx.create_ssl_context(verify=True, trust_env=trust_env)


class ProviderError(Exception):
    """Upstream provider failure, already mapped to something safe to surface.

    Never carries provider credentials or raw prompt content -- both would end
    up in logs and error responses (security invariants SI-11 and SI-12).
    """

    def __init__(self, message: str, status_code: int = 502) -> None:
        super().__init__(message)
        self.status_code = status_code


class ProviderAdapter(Protocol):
    name: str

    async def chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]: ...


class MockProvider:
    """Deterministic offline provider.

    Echoes back a response derived from the (already transformed) prompt. Two
    jobs:

    1. ``make demo`` works with no API key and no network.
    2. Leakage tests can assert on exactly what the provider received -- which
       is the only way to prove "the original value never reached the
       provider".
    """

    name = "mock"

    def __init__(self) -> None:
        self.received: list[dict[str, Any]] = []

    async def chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.received.append(payload)
        messages = payload.get("messages", [])
        last = ""
        for message in reversed(messages):
            if message.get("role") == "user":
                last = str(message.get("content", ""))
                break

        digest = hashlib.sha256(last.encode("utf-8")).hexdigest()[:8]
        return {
            "id": f"chatcmpl-mock-{digest}",
            "object": "chat.completion",
            "created": 0,
            "model": payload.get("model", "mock-model"),
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"[mock] received: {last}",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": len(last.split()),
                "completion_tokens": 8,
                "total_tokens": len(last.split()) + 8,
            },
        }


#: Retry budget. Two retries, because the failures worth retrying are transient
#: and a third attempt mostly adds latency to a request the client has already
#: given up on.
MAX_RETRIES = 2

#: Exponential backoff with **full jitter**: sleep is uniform in [0, base*2^n].
#: Full rather than equal jitter because the failure mode we are avoiding is a
#: retry storm when an upstream recovers, and full jitter spreads best.
BACKOFF_BASE_SECONDS = 0.25
BACKOFF_CAP_SECONDS = 4.0

#: A response larger than this is refused rather than buffered. Output
#: inspection reads the whole body, so an unbounded response is an unbounded
#: allocation driven by a third party.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

#: Retried: the upstream never processed the request, or told us to come back.
#: 501 is excluded -- "not implemented" will still not be implemented.
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


class OpenAICompatibleProvider:
    """Direct HTTP adapter for any OpenAI-compatible endpoint.

    ## Retry policy

    Retries only failures where the upstream demonstrably did not process the
    request, or explicitly asked us to come back. **Timeouts are not retried**:
    a timed-out request may well have been processed, and the OpenAI API has no
    idempotency key, so retrying risks a duplicate billed completion.

    A retry re-sends the **already-transformed** payload. It does not re-run
    detection and does not create a new provenance set -- transform once, send
    many. Re-running the pipeline per attempt would look harmless because
    minting is deterministic, but it would double the vault writes, make the
    audit event's entity counts ambiguous, and multiply detection latency by the
    retry budget. See docs/adr/0014-retry-cancellation-and-provenance.md.

    The deadline is **total across attempts**, not per attempt. Otherwise a
    120 s timeout becomes a 360 s worst case and the client disconnected long
    ago.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        model_override: str | None = None,
        timeout_seconds: float = 120.0,
        name: str = "openai_compatible",
        trust_env: bool = False,
        egress: EgressPolicy | None = None,
        max_retries: int = MAX_RETRIES,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        jitter: Callable[[float], float] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.name = name
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._model_override = model_override
        self._timeout = timeout_seconds
        # `trust_env=False` by default: httpx would otherwise silently honour
        # HTTP_PROXY / HTTPS_PROXY / ALL_PROXY from the environment. In a
        # security gateway that is unacceptable -- an operator who does not
        # know a proxy variable is set would be routing every prompt through
        # an unreviewed third-party hop, defeating the egress controls the
        # product exists to provide. Operators who genuinely need an egress
        # proxy opt in explicitly via SAG_TRUST_ENV_PROXY.
        self._trust_env = trust_env
        self._egress = egress or EgressPolicy(name=name)
        self._max_retries = max_retries
        self._max_response_bytes = max_response_bytes
        self._sleep = sleep or asyncio.sleep
        # Injectable so backoff is deterministic under test. Production uses a
        # non-cryptographic PRNG deliberately: this schedules a sleep, it does
        # not protect anything.
        self._jitter = jitter or (lambda ceiling: random.uniform(0, ceiling))  # noqa: S311
        # Injecting a transport is httpx's own supported seam. Contract tests
        # drive the real retry loop, status handling, and bounded read through
        # a scripted transport rather than stubbing `chat_completion` -- a stub
        # at that level would test the stub.
        self._transport = transport
        # Built on first use, then reused for the life of the provider. See
        # `_pooled_client` for why not here.
        self._client: httpx.AsyncClient | None = None

        # Fail at startup rather than on the first request. An operator who has
        # misconfigured the destination should find out when they deploy.
        self._egress.validate(self._base_url)

    @property
    def egress(self) -> EgressPolicy:
        return self._egress

    def _backoff(self, attempt: int, retry_after: float | None) -> float:
        if retry_after is not None:
            return min(retry_after, BACKOFF_CAP_SECONDS)
        ceiling = min(BACKOFF_BASE_SECONDS * (2**attempt), BACKOFF_CAP_SECONDS)
        return self._jitter(ceiling)

    @staticmethod
    def _retry_after(response: httpx.Response) -> float | None:
        raw = response.headers.get("Retry-After")
        if not raw:
            return None
        try:
            return max(0.0, float(raw))
        except ValueError:
            # HTTP-date form. Not parsed -- fall back to our own backoff rather
            # than trusting a date we might read differently from the sender.
            return None

    def _pooled_client(self) -> httpx.AsyncClient:
        """The long-lived client for this provider, created on first use.

        Previously a client was constructed inside the retry loop and discarded
        after every attempt, so each request paid a fresh TCP handshake -- and,
        against an HTTPS provider, a fresh TLS handshake on top. Measured with
        the trust store already shared, that was **+53 ms against a public
        HTTPS API**, +11 ms over a LAN-like link, +2 ms on loopback.

        Created lazily rather than in ``__init__`` because httpx binds its
        connection pool to the running event loop on first use; building it
        during construction ties the pool to whichever loop happened to be
        current, which is not necessarily the one serving requests.

        ## What sharing a client does and does not change

        It does **not** widen what this provider may talk to. Egress is
        validated per request in ``chat_completion`` before any connection is
        used, and the pool is per provider instance, so a ``local`` provider's
        connections are never reachable from the ``external`` one -- they are
        different objects with different policies.

        It does mean a connection outlives the request that opened it. Two
        consequences worth naming:

        * A cancelled or timed-out request returns its connection to the pool
          rather than destroying the client. That is httpx's own behaviour and
          is what makes cancellation cheap, but it means a half-consumed
          response must be closed properly -- which the ``finally: aclose()``
          in the caller already guarantees.
        * DNS is re-resolved less often, because a live connection is reused.
          That narrows the rebinding window described in
          ``gateway/routing/egress.py`` rather than widening it, but it does not
          close it: a *new* connection still resolves again, after validation.

        See ADR-0014 for the retry and cancellation contract this preserves.
        """
        if self._client is None:
            kwargs: dict[str, Any] = {
                "trust_env": self._trust_env,
                "follow_redirects": False,
            }
            if self._transport is None:
                # Explicit, so a future refactor cannot disable verification by
                # omission. httpx rejects `verify` alongside `transport`.
                #
                # A cached context rather than `verify=True`: the latter rebuilds
                # the CA bundle every time a client is constructed. Same object
                # httpx would have built -- see `verification_context`.
                kwargs["verify"] = verification_context(self._trust_env)
            else:
                kwargs["transport"] = self._transport
            self._client = httpx.AsyncClient(**kwargs)
        return self._client

    async def aclose(self) -> None:
        """Release pooled connections. Idempotent.

        Called from the application lifespan on shutdown. Without it the pool is
        closed by garbage collection at interpreter exit, which is late enough to
        emit warnings and to hold sockets open past the graceful-shutdown window.
        """
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()

    async def _read_bounded(self, response: httpx.Response) -> bytes:
        """Read the body, refusing anything over the cap.

        Checked while reading rather than from Content-Length, because
        Content-Length is a claim by the same party sending the body.
        """
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > self._max_response_bytes:
                raise ProviderError(
                    f"upstream response exceeded {self._max_response_bytes} bytes", 502
                )
            chunks.append(chunk)
        return b"".join(chunks)

    async def chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = dict(payload)
        if self._model_override:
            body["model"] = self._model_override

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        # Re-validated per request, not only at startup: a name that resolved to
        # a public address when we booted can resolve elsewhere later. See the
        # TOCTOU note in gateway/routing/egress.py.
        await asyncio.to_thread(self._egress.validate, self._base_url)

        url = f"{self._base_url}/chat/completions"
        deadline = time.monotonic() + self._timeout
        last_error: ProviderError | None = None

        for attempt in range(self._max_retries + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise last_error or ProviderError(
                    f"upstream deadline of {self._timeout}s elapsed", 504
                )

            try:
                client = self._pooled_client()
                # Per request, not per client: the deadline shrinks with every
                # retry, and the client now outlives all of them.
                request = client.build_request(
                    "POST", url, json=body, headers=headers, timeout=remaining
                )
                response = await client.send(request, stream=True)
                try:
                    status = response.status_code
                    if status < 400:
                        raw = await self._read_bounded(response)
                    else:
                        # The error body is not read. A provider error body
                        # can echo the prompt back, and reading it only to
                        # discard it is an opportunity to log it by accident.
                        retry_after = self._retry_after(response)
                        raw = b""
                finally:
                    await response.aclose()
            except httpx.TimeoutException as exc:
                # Not retried: the upstream may have processed this, and there
                # is no idempotency key to make a second attempt safe.
                raise ProviderError(f"upstream timed out after {self._timeout}s", 504) from exc
            except httpx.TransportError as exc:
                # Connection-level: the request was never processed, so a retry
                # cannot duplicate anything.
                last_error = ProviderError(f"upstream request failed ({type(exc).__name__})", 502)
                if attempt >= self._max_retries:
                    raise last_error from exc
                await self._sleep(self._backoff(attempt, None))
                continue
            except httpx.HTTPError as exc:
                # Deliberately does NOT include str(exc): httpx error strings can
                # contain the full request URL, which may carry credentials.
                raise ProviderError(f"upstream request failed ({type(exc).__name__})", 502) from exc

            if status >= 400:
                # Surface the status but not the body -- see above.
                last_error = ProviderError(
                    f"upstream returned HTTP {status}",
                    502 if status >= 500 else status,
                )
                if status in _RETRYABLE_STATUS and attempt < self._max_retries:
                    await self._sleep(self._backoff(attempt, retry_after))
                    continue
                raise last_error

            try:
                decoded = json.loads(raw)
            except ValueError as exc:
                raise ProviderError("upstream returned a body that is not JSON", 502) from exc
            if not isinstance(decoded, dict):
                raise ProviderError("upstream returned JSON that is not an object", 502)
            return decoded

        raise last_error or ProviderError("upstream request failed", 502)
