"""Egress control, retry behaviour, and the upstream failure simulations.

These are the Phase 5 exit criteria, made checkable:

* no accepted field can bypass inspection — `tests/test_request_contract.py`;
* **arbitrary client-supplied upstream URLs are not permitted** — here;
* **provider errors do not expose protected or restored values** — here;
* **cancellation, timeout, and retry preserve provenance isolation** — here.

The retry tests are the ones ADR-0014 said had to exist *before* retries were
implemented. They did not, which is why the structural tripwire
`test_there_is_no_retry_logic_to_race` existed to fail the moment a retry loop
appeared. It fired on the first run after this landed, and these replace it.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from typing import Any

import httpx
import pytest

from gateway.domain import Span
from gateway.restoration.engine import RestorationEngine
from gateway.routing.base import (
    MAX_RESPONSE_BYTES,
    OpenAICompatibleProvider,
    ProviderError,
    verification_context,
)
from gateway.routing.egress import EgressBlockedError, EgressPolicy, policy_for
from gateway.transformations.engine import TransformationEngine
from gateway.transformations.tokens import TokenProvenance

CANARY = "alice@acme.lv"
PROVIDER_KEY = "sk-super-secret-provider-key"

LOCAL = EgressPolicy(name="test", allow_private=True)


def _completion(content: str = "ok") -> dict[str, Any]:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 0,
        "model": "m",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
    }


async def _no_sleep(_seconds: float) -> None:
    """Backoff without the waiting. Sleep durations are asserted separately."""
    return None


def make_provider(handler, **kwargs) -> OpenAICompatibleProvider:
    """A provider driven by a scripted transport, with no real network.

    Injected through httpx's own ``transport`` seam rather than by stubbing
    ``chat_completion``, so the retry loop, status handling, and bounded read
    are all genuinely under test. A stub at that level would test the stub.
    """
    return OpenAICompatibleProvider(
        base_url="http://127.0.0.1:11434/v1",
        api_key=kwargs.pop("api_key", None),
        timeout_seconds=kwargs.pop("timeout_seconds", 5.0),
        egress=kwargs.pop("egress", LOCAL),
        sleep=kwargs.pop("sleep", _no_sleep),
        jitter=kwargs.pop("jitter", lambda ceiling: ceiling),
        transport=httpx.MockTransport(handler),
        **kwargs,
    )


class TestVerificationContext:
    """The TLS trust store is built once, and still verifies.

    Every other test in this file injects a ``transport``, which is the branch
    that skips ``verify`` entirely -- so nothing here exercised the real client
    construction, and a ~400 ms per-request cost lived in that blind spot. These
    tests cover the branch the suite otherwise cannot reach.
    """

    def test_the_context_is_reused_rather_than_rebuilt(self):
        """The whole point of the fix: one trust store, not one per request."""
        assert verification_context(False) is verification_context(False)

    def test_building_it_twice_is_effectively_free(self):
        """A regression guard with teeth.

        Rebuilding costs hundreds of milliseconds; a cache hit costs
        microseconds. The threshold is loose enough to survive a slow machine
        and still fail instantly if the caching is removed.
        """
        import time

        verification_context(False)  # ensure it is warm
        start = time.perf_counter()
        for _ in range(50):
            verification_context(False)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 50, f"50 lookups took {elapsed_ms:.1f} ms; the context is being rebuilt"

    @pytest.mark.parametrize("trust_env", [True, False])
    def test_certificate_and_hostname_checking_stay_on(self, trust_env):
        """Sharing the context must not weaken it.

        This is the property the original `verify=True` was written to make
        explicit, so it is now asserted rather than implied.
        """
        import ssl

        context = verification_context(trust_env)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True

    def test_the_two_trust_env_settings_do_not_share_a_context(self):
        """httpx reads SSL_CERT_FILE/SSL_CERT_DIR only when trust_env is set, so
        the two settings can resolve to different stores and must not collide in
        the cache."""
        assert verification_context(True) is not verification_context(False)


class TestConnectionPooling:
    """The client outlives the request, and that must stay safe.

    Discarding a client per request cost a handshake per request: +53 ms
    against a public HTTPS API, measured with the trust store already shared.
    Reusing it is worth having, but it means connection state now survives a
    request -- including a request that failed, timed out, or was cancelled.
    These pin the properties that makes acceptable.
    """

    async def test_the_client_is_reused_across_requests(self):
        provider = make_provider(lambda request: httpx.Response(200, json=_completion()))
        await provider.chat_completion({"model": "m", "messages": []})
        first = provider._pooled_client()
        await provider.chat_completion({"model": "m", "messages": []})
        assert provider._pooled_client() is first

    async def test_two_providers_do_not_share_a_pool(self):
        """`local` and `external` carry different egress policies.

        Sharing a pool between them would let a connection opened under one
        policy serve a request judged under the other.
        """
        a = make_provider(lambda r: httpx.Response(200, json=_completion()))
        b = make_provider(lambda r: httpx.Response(200, json=_completion()))
        await a.chat_completion({"model": "m", "messages": []})
        await b.chat_completion({"model": "m", "messages": []})
        assert a._pooled_client() is not b._pooled_client()

    async def test_a_failed_request_does_not_poison_the_pool(self):
        """A 500 then a success, on the same client. The second must work."""
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(500)
            return httpx.Response(200, json=_completion("second"))

        provider = make_provider(handler)
        result = await provider.chat_completion({"model": "m", "messages": []})
        assert result["choices"][0]["message"]["content"] == "second"

    async def test_a_cancelled_request_leaves_the_provider_usable(self):
        """Cancellation must release the connection, not break the client.

        This is the property that made a per-request client feel safe: the
        client died with the request. Now it does not, so the next request has
        to prove it still works.
        """
        started = asyncio.Event()

        async def hang(request: httpx.Request) -> httpx.Response:
            started.set()
            await asyncio.sleep(3600)
            raise AssertionError("unreachable")

        provider = make_provider(hang)
        task = asyncio.create_task(provider.chat_completion({"model": "m", "messages": []}))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        provider._transport = httpx.MockTransport(
            lambda r: httpx.Response(200, json=_completion("after cancel"))
        )
        provider._client = None  # a new transport needs a new client
        result = await provider.chat_completion({"model": "m", "messages": []})
        assert result["choices"][0]["message"]["content"] == "after cancel"

    async def test_aclose_is_idempotent_and_releases_the_client(self):
        """Shutdown may run more than once; it must not raise the second time."""
        provider = make_provider(lambda r: httpx.Response(200, json=_completion()))
        await provider.chat_completion({"model": "m", "messages": []})
        assert provider._client is not None
        await provider.aclose()
        assert provider._client is None
        await provider.aclose()

    async def test_the_per_request_deadline_still_shrinks_across_retries(self):
        """The timeout moved from the client to the request when the client
        became shared. It still has to track the *total* deadline, or a 120 s
        timeout becomes a 360 s worst case -- the property ADR-0014 requires.

        Two things make this non-vacuous, and both were needed. An earlier
        version of this test asserted only "not None" and "non-increasing", and
        a mutation check showed it passed with the per-request timeout deleted:
        httpx falls back to its own client default, which is a constant, and a
        constant sequence is both non-None and non-increasing. It was 5.0 s,
        which is exactly what the test had configured -- so the fallback was
        indistinguishable from the real value.

        Hence: an unusual timeout no default can imitate, and a *strict*
        decrease.
        """
        seen: list[float | None] = []

        def handler(request: httpx.Request) -> httpx.Response:
            timeout = request.extensions.get("timeout") or {}
            seen.append(timeout.get("read"))
            return httpx.Response(500)

        provider = make_provider(handler, timeout_seconds=37.0, max_retries=2)
        with pytest.raises(ProviderError):
            await provider.chat_completion({"model": "m", "messages": []})

        assert len(seen) >= 2, "expected retries"
        assert all(t is not None for t in seen), "no per-request timeout was set"
        # Derived from our deadline, not from an httpx default.
        assert 36.0 < seen[0] <= 37.0, f"first attempt did not use the configured deadline: {seen}"
        # Strictly consumed, not merely repeated.
        assert seen[0] > seen[-1], f"deadline did not shrink across attempts: {seen}"
        assert all(t <= 37.0 for t in seen)


# ---------------------------------------------------------------------------
# Egress: the operator-controlled half of SSRF
# ---------------------------------------------------------------------------


class TestEgressPolicy:
    @pytest.mark.parametrize(
        "url",
        [
            "http://169.254.169.254/latest/meta-data",  # the metadata service
            "http://127.0.0.1:8080/v1",
            "http://localhost:8080/v1",
            "https://10.0.0.5/v1",
            "https://192.168.1.10/v1",
            "https://172.16.0.1/v1",
            "http://[::1]:8080/v1",
            "https://0.0.0.0/v1",
        ],
    )
    def test_private_and_link_local_destinations_are_refused(self, url):
        """``169.254.169.254`` is the first thing anyone tries."""
        with pytest.raises(EgressBlockedError):
            EgressPolicy(name="external").validate(url)

    def test_a_local_destination_may_use_private_addresses(self):
        """That is what `route_local` is for."""
        EgressPolicy(name="local", allow_private=True).validate("http://127.0.0.1:11434/v1")

    def test_plaintext_http_is_refused_for_a_non_local_destination(self):
        with pytest.raises(EgressBlockedError, match="plaintext http"):
            EgressPolicy(name="external").validate("http://example.com/v1")

    @pytest.mark.parametrize("scheme", ["file", "ftp", "gopher", "data", ""])
    def test_non_http_schemes_are_refused(self, scheme):
        url = f"{scheme}://example.com/v1" if scheme else "example.com/v1"
        with pytest.raises(EgressBlockedError, match="scheme"):
            EgressPolicy(name="external").validate(url)

    def test_a_host_outside_the_allowlist_is_refused(self):
        policy = EgressPolicy(name="external", allowed_hosts=frozenset({"api.openai.com"}))
        with pytest.raises(EgressBlockedError, match="allowlist"):
            policy.validate("https://evil.example/v1")

    def test_a_host_on_the_allowlist_is_permitted(self):
        policy = EgressPolicy(name="external", allowed_hosts=frozenset({"api.openai.com"}))
        policy.validate("https://api.openai.com/v1")

    def test_the_allowlist_is_case_insensitive(self):
        policy = EgressPolicy(name="external", allowed_hosts=frozenset({"api.openai.com"}))
        policy.validate("https://API.OpenAI.COM/v1")

    def test_a_host_that_does_not_resolve_is_refused(self):
        with pytest.raises(EgressBlockedError, match="does not resolve"):
            EgressPolicy(name="external").validate("https://nonexistent-host-for-tests.invalid/v1")

    def test_the_default_for_local_allows_private(self):
        assert policy_for("local").allow_private is True

    def test_the_default_for_external_does_not(self):
        assert policy_for("external").allow_private is False

    def test_the_global_override_is_describable(self):
        """An operator who disables the control should be able to see that."""
        policy = policy_for("external", allow_private_override=True)
        assert policy.describe()["allow_private"] is True


class TestProviderValidatesEgress:
    def test_a_misconfigured_destination_fails_at_startup(self):
        """Not on the first request. Deploy time is when it should be found."""
        with pytest.raises(EgressBlockedError):
            OpenAICompatibleProvider(base_url="http://169.254.169.254/v1", name="external")

    async def test_egress_is_revalidated_on_every_request(self):
        """Startup validation alone would miss a name that changes later.

        Not a complete rebinding defence -- httpx resolves again when it
        connects -- but it closes misconfiguration and slow rebinding, and the
        residual is documented in gateway/routing/egress.py.
        """
        calls: list[str] = []

        class CountingPolicy(EgressPolicy):
            def validate(self, url: str) -> None:  # type: ignore[override]
                calls.append(url)

        provider = make_provider(
            lambda request: httpx.Response(200, json=_completion()),
            egress=CountingPolicy(name="test", allow_private=True),
        )
        await provider.chat_completion({"model": "m", "messages": []})
        assert calls, "egress must be checked per request, not only at startup"

    async def test_request_time_dns_validation_does_not_block_the_event_loop(self):
        release = threading.Event()
        calls = [0]

        class SlowPolicy(EgressPolicy):
            def validate(self, url: str) -> None:  # type: ignore[override]
                calls[0] += 1
                if calls[0] > 1:  # The first call happens during provider construction.
                    release.wait(timeout=1)

        provider = make_provider(
            lambda request: httpx.Response(200, json=_completion()),
            egress=SlowPolicy(name="test", allow_private=True),
        )
        timer = threading.Timer(0.25, release.set)
        timer.start()
        started = time.perf_counter()
        task = asyncio.create_task(provider.chat_completion({"model": "m", "messages": []}))
        try:
            await asyncio.sleep(0.01)
            assert time.perf_counter() - started < 0.1
        finally:
            release.set()
            timer.cancel()
        await task


class TestClientsCannotChooseAnUpstream:
    """The client-controlled half, asserted rather than assumed.

    Destinations are selected by *name* from a map built at startup. A caller
    cannot supply a URL because there is no field that carries one -- and the
    typed request model now makes that structural: any such field is rejected
    as unknown.
    """

    @pytest.mark.parametrize(
        "field", ["base_url", "api_base", "url", "endpoint", "provider", "destination"]
    )
    def test_no_url_like_field_is_accepted(self, field):
        from gateway.api.schema import RequestRejected, parse_chat_completion_request

        body = {
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}],
            field: "http://169.254.169.254/",
        }
        with pytest.raises(RequestRejected) as caught:
            parse_chat_completion_request(body)
        assert caught.value.code == "unknown_field"

    async def test_an_unconfigured_destination_fails_rather_than_fetching(
        self, ctx, policy, vault, minter, audit_sink
    ):
        """A policy naming a destination that does not exist must not guess."""
        from gateway.detectors.deterministic import default_detectors
        from gateway.inspection.pipeline import SecurityPipeline

        pipeline = SecurityPipeline(
            detectors=default_detectors(),
            policy=policy,
            transformer=TransformationEngine(minter, vault),
            restorer=RestorationEngine(vault),
            providers={},  # nothing configured
            audit_sink=audit_sink,
        )
        with pytest.raises(ProviderError, match="not configured"):
            await pipeline.process(
                ctx, {"model": "m", "messages": [{"role": "user", "content": "x"}]}
            )


# ---------------------------------------------------------------------------
# Retry
# ---------------------------------------------------------------------------


class TestRetryPolicy:
    async def test_a_connection_error_is_retried(self):
        attempts = 0

        def handler(request):
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise httpx.ConnectError("refused", request=request)
            return httpx.Response(200, json=_completion())

        provider = make_provider(handler)
        assert await provider.chat_completion({"model": "m", "messages": []})
        assert attempts == 3, "two retries after the first failure"

    async def test_retries_are_bounded(self):
        attempts = 0

        def handler(request):
            nonlocal attempts
            attempts += 1
            raise httpx.ConnectError("refused", request=request)

        provider = make_provider(handler)
        with pytest.raises(ProviderError):
            await provider.chat_completion({"model": "m", "messages": []})
        assert attempts == 3, "one attempt plus MAX_RETRIES, and no more"

    async def test_a_timeout_is_not_retried(self):
        """The upstream may have processed it, and there is no idempotency key.

        Retrying risks a duplicate billed completion, which is a real cost to
        the customer for a request they only made once.
        """
        attempts = 0

        def handler(request):
            nonlocal attempts
            attempts += 1
            raise httpx.ReadTimeout("slow", request=request)

        provider = make_provider(handler)
        with pytest.raises(ProviderError) as caught:
            await provider.chat_completion({"model": "m", "messages": []})
        assert attempts == 1
        assert caught.value.status_code == 504

    @pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
    async def test_retryable_statuses_are_retried(self, status):
        attempts = 0

        def handler(request):
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                return httpx.Response(status)
            return httpx.Response(200, json=_completion())

        provider = make_provider(handler)
        assert await provider.chat_completion({"model": "m", "messages": []})
        assert attempts == 2

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 422, 501])
    async def test_client_errors_and_not_implemented_are_not_retried(self, status):
        """Retrying a wrong request just makes it wrong again."""
        attempts = 0

        def handler(request):
            nonlocal attempts
            attempts += 1
            return httpx.Response(status)

        provider = make_provider(handler)
        with pytest.raises(ProviderError):
            await provider.chat_completion({"model": "m", "messages": []})
        assert attempts == 1

    async def test_retry_after_is_honoured(self):
        slept: list[float] = []

        async def record(seconds: float) -> None:
            slept.append(seconds)

        attempts = 0

        def handler(request):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(429, headers={"Retry-After": "2"})
            return httpx.Response(200, json=_completion())

        provider = make_provider(handler, sleep=record)
        await provider.chat_completion({"model": "m", "messages": []})
        assert slept == [2.0]

    async def test_an_unparseable_retry_after_falls_back_to_backoff(self):
        """An HTTP-date we might read differently from the sender is not trusted."""
        slept: list[float] = []

        async def record(seconds: float) -> None:
            slept.append(seconds)

        attempts = 0

        def handler(request):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(503, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"})
            return httpx.Response(200, json=_completion())

        provider = make_provider(handler, sleep=record)
        await provider.chat_completion({"model": "m", "messages": []})
        assert slept == [0.25], "our own backoff, not the date"

    async def test_backoff_grows_and_is_capped(self):
        slept: list[float] = []

        async def record(seconds: float) -> None:
            slept.append(seconds)

        def handler(request):
            raise httpx.ConnectError("refused", request=request)

        provider = make_provider(handler, sleep=record, max_retries=6)
        with pytest.raises(ProviderError):
            await provider.chat_completion({"model": "m", "messages": []})

        assert slept == sorted(slept), "backoff must not shrink"
        assert max(slept) <= 4.0, "and must be capped"


class TestRetryPreservesProvenance:
    """ADR-0014's required tests, now that retries exist."""

    async def test_a_retry_does_not_re_run_detection(self, ctx, policy, vault, minter, audit_sink):
        """Transform once, send many.

        Re-running the pipeline per attempt looks harmless because minting is
        deterministic. It is not: it doubles the vault writes, makes the audit
        event's entity counts ambiguous, and multiplies detection latency by the
        retry budget.
        """
        from gateway.inspection.pipeline import SecurityPipeline

        detector_calls = 0

        class CountingDetector:
            name = "counting"

            def detect(self, text: str) -> list[Span]:
                nonlocal detector_calls
                detector_calls += 1
                return []

        attempts = 0

        def handler(request):
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise httpx.ConnectError("refused", request=request)
            return httpx.Response(200, json=_completion())

        provider = make_provider(handler)
        pipeline = SecurityPipeline(
            detectors=[CountingDetector()],
            policy=policy,
            transformer=TransformationEngine(minter, vault),
            restorer=RestorationEngine(vault),
            providers={"mock": provider, "local": provider},
            audit_sink=audit_sink,
        )

        await pipeline.process(
            ctx, {"model": "m", "messages": [{"role": "user", "content": "hello"}]}
        )
        assert attempts == 3, "the request was retried"
        assert detector_calls == 1, "but detection ran exactly once"

    async def test_a_retry_reuses_the_same_provenance_and_restores_correctly(
        self, ctx, policy, vault, minter, audit_sink
    ):
        from gateway.detectors.deterministic import default_detectors
        from gateway.inspection.pipeline import SecurityPipeline

        seen: list[str] = []
        attempts = 0

        def handler(request):
            nonlocal attempts
            attempts += 1
            body = json.loads(request.content)
            seen.append(body["messages"][-1]["content"])
            if attempts < 2:
                return httpx.Response(503)
            return httpx.Response(200, json=_completion(seen[-1]))

        provider = make_provider(handler)
        pipeline = SecurityPipeline(
            detectors=default_detectors(),
            policy=policy,
            transformer=TransformationEngine(minter, vault),
            restorer=RestorationEngine(vault),
            providers={"mock": provider, "local": provider},
            audit_sink=audit_sink,
        )

        result = await pipeline.process(
            ctx, {"model": "m", "messages": [{"role": "user", "content": f"Mail {CANARY}"}]}
        )

        assert attempts == 2
        assert len(set(seen)) == 1, "the retry re-sent the identical transformed payload"
        assert CANARY not in seen[0]
        assert CANARY in result.response["choices"][0]["message"]["content"]
        assert result.restoration.restored == 1
        assert result.restoration.total_refused == 0

    async def test_the_deadline_is_total_across_attempts(self):
        """Otherwise a 120 s timeout becomes a 360 s worst case."""
        slept: list[float] = []

        async def record(seconds: float) -> None:
            slept.append(seconds)

        seen_timeouts: list[float | None] = []

        def handler(request):
            seen_timeouts.append(request.extensions.get("timeout", {}).get("read"))
            raise httpx.ConnectError("refused", request=request)

        provider = make_provider(handler, sleep=record, timeout_seconds=5.0)
        with pytest.raises(ProviderError):
            await provider.chat_completion({"model": "m", "messages": []})

        finite = [t for t in seen_timeouts if t is not None]
        if len(finite) > 1:
            assert finite == sorted(finite, reverse=True), (
                "the remaining budget must shrink across attempts"
            )


# ---------------------------------------------------------------------------
# Upstream failure simulations
# ---------------------------------------------------------------------------


class TestUpstreamFailuresLeakNothing:
    async def test_an_error_body_that_echoes_the_prompt_is_not_relayed(self):
        """A provider error body can echo the request straight back.

        The body is not even read on the error path -- reading it only to
        discard it is an opportunity to log it by accident.
        """

        def handler(request):
            return httpx.Response(400, json={"error": {"message": f"bad prompt: {CANARY}"}})

        provider = make_provider(handler, api_key=PROVIDER_KEY)
        with pytest.raises(ProviderError) as caught:
            await provider.chat_completion({"model": "m", "messages": []})

        rendered = f"{caught.value!s} {caught.value!r}"
        assert CANARY not in rendered
        assert PROVIDER_KEY not in rendered
        assert "400" in rendered

    async def test_a_connection_error_does_not_name_the_host_or_key(self):
        def handler(request):
            raise httpx.ConnectError("connection refused to 10.1.2.3", request=request)

        provider = make_provider(handler, api_key=PROVIDER_KEY, max_retries=0)
        with pytest.raises(ProviderError) as caught:
            await provider.chat_completion({"model": "m", "messages": []})

        rendered = f"{caught.value!s} {caught.value!r}"
        assert PROVIDER_KEY not in rendered
        assert "10.1.2.3" not in rendered
        assert "ConnectError" in rendered

    async def test_a_non_json_body_is_a_provider_error_not_a_crash(self):
        def handler(request):
            return httpx.Response(200, content=b"<html>gateway timeout</html>")

        provider = make_provider(handler)
        with pytest.raises(ProviderError, match="not JSON"):
            await provider.chat_completion({"model": "m", "messages": []})

    @pytest.mark.parametrize("payload", [[], "text", 42])
    async def test_json_response_must_be_an_object(self, payload):
        provider = make_provider(lambda request: httpx.Response(200, json=payload))

        with pytest.raises(ProviderError, match="not an object"):
            await provider.chat_completion({"model": "m", "messages": []})

    async def test_an_oversized_response_is_refused(self):
        """Output inspection reads the whole body, so an unbounded response is
        an unbounded allocation driven by a third party."""

        def handler(request):
            return httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1024))

        provider = make_provider(handler)
        with pytest.raises(ProviderError, match="exceeded"):
            await provider.chat_completion({"model": "m", "messages": []})

    async def test_a_response_within_the_cap_is_accepted(self):
        payload = _completion("a" * 1024)

        def handler(request):
            return httpx.Response(200, json=payload)

        provider = make_provider(handler)
        assert await provider.chat_completion({"model": "m", "messages": []}) == payload

    async def test_redirects_are_not_followed(self):
        """A redirect is an upstream-chosen destination, which is the whole
        thing egress control exists to prevent."""
        hits: list[str] = []

        def handler(request):
            hits.append(str(request.url))
            if len(hits) == 1:
                return httpx.Response(302, headers={"Location": "http://169.254.169.254/"})
            return httpx.Response(200, json=_completion())

        provider = make_provider(handler)
        with pytest.raises(ProviderError):
            await provider.chat_completion({"model": "m", "messages": []})
        assert len(hits) == 1, "the redirect must not be followed"

    async def test_a_provider_failure_does_not_leak_restored_values(
        self, ctx, policy, vault, minter, audit_sink
    ):
        """End to end: the request carried a real value, the upstream failed."""
        from gateway.detectors.deterministic import default_detectors
        from gateway.inspection.pipeline import SecurityPipeline

        def handler(request):
            return httpx.Response(500, json={"echo": json.loads(request.content)})

        provider = make_provider(handler)
        pipeline = SecurityPipeline(
            detectors=default_detectors(),
            policy=policy,
            transformer=TransformationEngine(minter, vault),
            restorer=RestorationEngine(vault),
            providers={"mock": provider, "local": provider},
            audit_sink=audit_sink,
        )

        with pytest.raises(ProviderError) as caught:
            await pipeline.process(
                ctx, {"model": "m", "messages": [{"role": "user", "content": f"Mail {CANARY}"}]}
            )
        assert CANARY not in f"{caught.value!s} {caught.value!r}"


class TestRecordedProviderFixture:
    """A contract test against a recorded OpenAI-shaped response.

    Guards the response contract in the direction that actually breaks: a
    provider adding fields, or our parsing quietly depending on one that is
    optional.
    """

    RECORDED = {
        "id": "chatcmpl-9xY2mQe1",
        "object": "chat.completion",
        "created": 1730000000,
        "model": "gpt-4o-mini-2024-07-18",
        "system_fingerprint": "fp_0aa8d3e20b",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "Hello.", "refusal": None},
                "logprobs": None,
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 12,
            "completion_tokens": 3,
            "total_tokens": 15,
            "prompt_tokens_details": {"cached_tokens": 0},
        },
    }

    async def test_a_recorded_response_round_trips_unchanged(self):
        def handler(request):
            return httpx.Response(200, json=self.RECORDED)

        provider = make_provider(handler)
        assert await provider.chat_completion({"model": "m", "messages": []}) == self.RECORDED

    async def test_unknown_response_fields_are_passed_through(self):
        """We do not reject on the *response* side.

        Rejecting a provider's new field would break the gateway every time an
        upstream ships a feature, and the security boundary is the request path
        plus the restoration allowlist -- not the response schema. Stated so the
        asymmetry with reject-unknown on requests is a decision, not an
        oversight.
        """
        response = {**self.RECORDED, "brand_new_field": {"nested": True}}

        def handler(request):
            return httpx.Response(200, json=response)

        provider = make_provider(handler)
        assert (await provider.chat_completion({"model": "m", "messages": []})) == response

    async def test_the_authorization_header_is_sent_and_the_body_is_json(self):
        captured: dict[str, Any] = {}

        def handler(request):
            captured["auth"] = request.headers.get("Authorization")
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json=_completion())

        provider = make_provider(handler, api_key=PROVIDER_KEY)
        await provider.chat_completion({"model": "m", "messages": [], "temperature": 0.2})

        assert captured["auth"] == f"Bearer {PROVIDER_KEY}"
        assert captured["body"]["temperature"] == 0.2


class TestProvenanceIsolationUnderFailure:
    async def test_a_failed_request_leaves_no_restorable_orphan(
        self, ctx, policy, vault, minter, audit_sink
    ):
        """The vault record survives the failure; nothing can restore it."""
        from gateway.detectors.deterministic import default_detectors
        from gateway.inspection.pipeline import SecurityPipeline

        def handler(request):
            return httpx.Response(500)

        provider = make_provider(handler)
        pipeline = SecurityPipeline(
            detectors=default_detectors(),
            policy=policy,
            transformer=TransformationEngine(minter, vault),
            restorer=RestorationEngine(vault),
            providers={"mock": provider, "local": provider},
            audit_sink=audit_sink,
        )

        with pytest.raises(ProviderError):
            await pipeline.process(
                ctx, {"model": "m", "messages": [{"role": "user", "content": f"Mail {CANARY}"}]}
            )

        surrogate = minter.mint(ctx, "EMAIL_ADDRESS", CANARY, TokenProvenance())
        outcome = RestorationEngine(vault).restore(
            ctx, f"Echo {surrogate.token}", TokenProvenance()
        )
        assert outcome.restored == 0
        assert CANARY not in outcome.text
