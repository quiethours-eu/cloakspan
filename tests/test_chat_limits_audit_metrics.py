"""Chat Completions admission limits, detector deadline, error-path audit, metrics.

Covers ROADMAP v0.1.0-alpha.1 items 3 and 4 on the default Chat Completions
path:

* a per-key rate limit (429 + Retry-After) with an injected monotonic clock;
* a concurrency cap that refuses immediately (503 + Retry-After);
* a detector deadline that forwards nothing and keeps a still-running detector
  counted against capacity;
* exactly one audit event for every terminal outcome, none of which carries a
  synthetic prompt value, a presented credential, or an unvalidated header;
* a ``/metrics`` endpoint that exists only with its own token.

No test sleeps for longer than a few milliseconds: time is injected, and a
blocked detector or provider is released by an event rather than a timer.
"""

from __future__ import annotations

import asyncio
import json
import re
import threading
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gateway.api.app import create_app
from gateway.api.limits import ConcurrencyLimiter, RateLimiter
from gateway.audit.events import MemorySink
from gateway.audit.reasons import ReasonCode
from gateway.auth.keys import ApiKey, ApiKeyStore, hash_key
from gateway.config import ConfigurationError, Settings
from gateway.config_validation import inspect_environment
from gateway.detectors.deterministic import default_detectors
from gateway.domain import RequestContext
from gateway.inspection.pipeline import DetectionBudget, SecurityPipeline
from gateway.restoration.engine import RestorationEngine
from gateway.routing.base import MockProvider, ProviderError
from gateway.routing.egress import EgressBlockedError
from gateway.telemetry.metrics import Metrics
from gateway.transformations.engine import TransformationEngine

from .fixtures import TEST_API_KEY, TEST_API_KEY_B

#: Synthetic values that must never reach an audit event or a metric. The email
#: is detected and tokenised; the plain word is not detected at all, so it would
#: survive into any field that copied prompt text.
CANARY_WORD = "zebracanary7741"
CANARY_EMAIL = "zebra.canary7741@acme.lv"
CANARY_PROMPT = f"Write to {CANARY_EMAIL} about {CANARY_WORD}"
CANARIES = (CANARY_WORD, "canary7741")

METRICS_TOKEN = "m3tr1cs-" + "0123456789abcdef" * 2
AUTH = {"Authorization": f"Bearer {TEST_API_KEY}"}
AUTH_B = {"Authorization": f"Bearer {TEST_API_KEY_B}"}


def body(content: str = "Hello", **extra: Any) -> dict[str, Any]:
    return {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": content}], **extra}


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class BlockingDetector:
    """A detector that holds its worker thread until released.

    Waiting on a ``threading.Event`` releases the GIL, which is the case a
    wall-clock deadline can bound; see docs/limitations.md for the case it
    cannot.
    """

    name = "blocking_test_detector"

    def __init__(self) -> None:
        self.release = threading.Event()
        self.entered = threading.Event()

    def detect(self, text: str) -> list[Any]:
        self.entered.set()
        self.release.wait(timeout=10)
        return []


class FailingDetector:
    name = "failing_test_detector"

    def detect(self, text: str) -> list[Any]:
        raise RuntimeError(f"broken on {text}")


class GatedProvider(MockProvider):
    """Holds each request until released, to keep requests in flight."""

    def __init__(self) -> None:
        super().__init__()
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.entered.set()
        await self.release.wait()
        return await super().chat_completion(payload)


class RaisingProvider(MockProvider):
    def __init__(self, exc: BaseException) -> None:
        super().__init__()
        self.exc = exc

    async def chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.received.append(payload)
        raise self.exc


def make_pipeline(
    policy,
    vault,
    minter,
    sink: MemorySink,
    provider: MockProvider | None = None,
    detectors: list[Any] | None = None,
    restorer: RestorationEngine | None = None,
) -> SecurityPipeline:
    provider = provider or MockProvider()
    return SecurityPipeline(
        detectors=detectors if detectors is not None else default_detectors(),
        policy=policy,
        transformer=TransformationEngine(minter, vault),
        restorer=restorer or RestorationEngine(vault),
        providers={"mock": provider, "local": provider},
        audit_sink=sink,
    )


def make_app(pipeline: SecurityPipeline, key_store: ApiKeyStore, **overrides: Any):
    return create_app(pipeline=pipeline, key_store=key_store, settings=Settings(**overrides))


def async_client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gateway")


def assert_no_canary(sink: MemorySink, *extra: str) -> None:
    for event in sink.events:
        serialised = event.to_json()
        for canary in (*CANARIES, *extra):
            assert canary not in serialised, f"{canary!r} reached an audit event"


async def wait_until(predicate, *, attempts: int = 400) -> None:
    for _ in range(attempts):
        if predicate():
            return
        await asyncio.sleep(0.005)
    raise AssertionError("condition was not reached")


# ---------------------------------------------------------------------------
# 1. Rate limit
# ---------------------------------------------------------------------------


class TestRateLimit:
    def test_refuses_with_429_and_retry_after_then_recovers(
        self, pipeline, key_store, mock_provider, audit_sink
    ):
        app = make_app(pipeline, key_store, rate_limit_per_minute=2)
        clock = FakeClock()
        app.state.rate_limiter.clock = clock
        client = TestClient(app)

        assert client.post("/v1/chat/completions", json=body(), headers=AUTH).status_code == 200
        assert client.post("/v1/chat/completions", json=body(), headers=AUTH).status_code == 200
        refused = client.post("/v1/chat/completions", json=body(), headers=AUTH)

        assert refused.status_code == 429
        assert refused.headers["Retry-After"] == "30"
        assert refused.headers["X-Request-Id"].startswith("req_")
        assert refused.json()["error"] == {
            "message": "Rate limit exceeded for this API key. "
            "Retry after the interval in Retry-After.",
            "type": "rate_limit_error",
            "param": None,
            "code": "rate_limit_exceeded",
        }
        assert len(mock_provider.received) == 2, "a refused request is never forwarded"
        assert audit_sink.events[-1].error == "rate_limit_exceeded"
        assert audit_sink.events[-1].provider == "none"

        clock.now += 29
        assert client.post("/v1/chat/completions", json=body(), headers=AUTH).status_code == 429
        clock.now += 1
        assert client.post("/v1/chat/completions", json=body(), headers=AUTH).status_code == 200

    def test_limit_is_per_key(self, pipeline, key_store):
        app = make_app(pipeline, key_store, rate_limit_per_minute=1)
        app.state.rate_limiter.clock = FakeClock()
        client = TestClient(app)

        assert client.post("/v1/chat/completions", json=body(), headers=AUTH).status_code == 200
        assert client.post("/v1/chat/completions", json=body(), headers=AUTH).status_code == 429
        assert client.post("/v1/chat/completions", json=body(), headers=AUTH_B).status_code == 200

    def test_zero_disables_the_limit(self, pipeline, key_store):
        app = make_app(pipeline, key_store, rate_limit_per_minute=0)
        client = TestClient(app)
        for _ in range(25):
            assert client.post("/v1/chat/completions", json=body(), headers=AUTH).status_code == 200
        assert len(app.state.rate_limiter) == 0

    def test_unauthenticated_requests_create_no_buckets(self, pipeline, key_store):
        app = make_app(pipeline, key_store, rate_limit_per_minute=5)
        client = TestClient(app)
        for index in range(40):
            headers = {"Authorization": f"Bearer sgw_live_attacker_{index}"}
            assert client.post("/v1/chat/completions", json=body(), headers=headers).status_code
        assert len(app.state.rate_limiter) == 0

    def test_buckets_are_bounded_by_configured_keys(self, pipeline, key_store):
        app = make_app(pipeline, key_store, rate_limit_per_minute=1000)
        client = TestClient(app)
        for headers in (AUTH, AUTH_B) * 5:
            client.post("/v1/chat/completions", json=body(), headers=headers)
        assert len(app.state.rate_limiter) == 2

    def test_a_clock_that_steps_backwards_mints_nothing(self):
        clock = FakeClock()
        limiter = RateLimiter(1, clock=clock)
        assert limiter.acquire("key") is None
        clock.now -= 3600
        assert limiter.acquire("key") is not None
        clock.now += 3600
        assert limiter.acquire("key") is not None, "time already counted is not counted twice"

    def test_health_and_readiness_are_not_rate_limited(self, pipeline, key_store):
        app = make_app(pipeline, key_store, rate_limit_per_minute=1)
        app.state.rate_limiter.clock = FakeClock()
        client = TestClient(app)
        client.post("/v1/chat/completions", json=body(), headers=AUTH)
        assert client.post("/v1/chat/completions", json=body(), headers=AUTH).status_code == 429
        for _ in range(5):
            assert client.get("/healthz", headers=AUTH).status_code == 200
            assert client.get("/readyz", headers=AUTH).status_code == 200


# ---------------------------------------------------------------------------
# 2. Concurrency cap
# ---------------------------------------------------------------------------


class TestConcurrencyCap:
    async def test_refuses_immediately_while_requests_are_in_flight(
        self, policy, vault, minter, key_store
    ):
        sink = MemorySink()
        provider = GatedProvider()
        app = make_app(
            make_pipeline(policy, vault, minter, sink, provider),
            key_store,
            max_concurrent_requests=1,
        )
        async with async_client(app) as client:
            first = asyncio.create_task(
                client.post("/v1/chat/completions", json=body(), headers=AUTH)
            )
            await asyncio.wait_for(provider.entered.wait(), timeout=5)
            assert app.state.capacity.active == 1

            refused = await client.post("/v1/chat/completions", json=body(), headers=AUTH_B)
            assert refused.status_code == 503
            assert refused.headers["Retry-After"] == "1"
            assert refused.json()["error"]["code"] == "capacity_exceeded"
            # Liveness and readiness are not admitted through the cap.
            assert (await client.get("/healthz")).status_code == 200
            assert (await client.get("/readyz")).status_code == 200

            provider.release.set()
            assert (await first).status_code == 200
            assert app.state.capacity.active == 0
            again = await client.post("/v1/chat/completions", json=body(), headers=AUTH_B)
            assert again.status_code == 200

        assert len(provider.received) == 2
        errors = [event.error for event in sink.events]
        assert errors.count("capacity_exceeded") == 1
        assert len(sink.events) == 3

    async def test_a_capacity_refusal_does_not_spend_the_rate_limit(
        self, policy, vault, minter, key_store
    ):
        sink = MemorySink()
        provider = GatedProvider()
        app = make_app(
            make_pipeline(policy, vault, minter, sink, provider),
            key_store,
            max_concurrent_requests=1,
            rate_limit_per_minute=1,
        )
        app.state.rate_limiter.clock = FakeClock()  # time does not move
        async with async_client(app) as client:
            holder = asyncio.create_task(
                client.post("/v1/chat/completions", json=body(), headers=AUTH_B)
            )
            await asyncio.wait_for(provider.entered.wait(), timeout=5)
            for _ in range(3):
                refused = await client.post("/v1/chat/completions", json=body(), headers=AUTH)
                assert refused.json()["error"]["code"] == "capacity_exceeded"
            provider.release.set()
            assert (await holder).status_code == 200
            # Key A's single request per minute is still unspent.
            assert (
                await client.post("/v1/chat/completions", json=body(), headers=AUTH)
            ).status_code == 200
            assert (
                await client.post("/v1/chat/completions", json=body(), headers=AUTH)
            ).status_code == 429

    def test_refund_never_creates_a_bucket(self):
        limiter = RateLimiter(5)
        limiter.refund("unknown-key")
        assert len(limiter) == 0

    def test_every_exit_returns_its_slot(self, pipeline, key_store):
        app = make_app(pipeline, key_store, max_concurrent_requests=1)
        client = TestClient(app)
        client.post("/v1/chat/completions", json=body(), headers={})  # 401
        client.post("/v1/chat/completions", content=b"{nope", headers=AUTH)  # 400
        client.post("/v1/chat/completions", json=body("key AKIAIOSFODNN7EXAMPLE"), headers=AUTH)
        client.post("/v1/chat/completions", json=body(stream=True), headers=AUTH)
        assert app.state.capacity.active == 0
        assert client.post("/v1/chat/completions", json=body(), headers=AUTH).status_code == 200

    def test_limiter_never_goes_below_zero(self):
        limiter = ConcurrencyLimiter(1)
        slot = limiter.try_acquire()
        assert slot is not None
        assert limiter.try_acquire() is None
        slot.release()
        slot.release()
        assert limiter.active == 0


# ---------------------------------------------------------------------------
# 3. Detector deadline
# ---------------------------------------------------------------------------


class TestDetectorTimeout:
    async def test_timeout_forwards_nothing_audits_and_holds_capacity(
        self, policy, vault, minter, key_store
    ):
        sink = MemorySink()
        provider = MockProvider()
        detector = BlockingDetector()
        app = make_app(
            make_pipeline(policy, vault, minter, sink, provider, [*default_detectors(), detector]),
            key_store,
            detector_timeout_seconds=0.05,
            max_concurrent_requests=1,
        )
        try:
            async with async_client(app) as client:
                timed_out = await client.post(
                    "/v1/chat/completions", json=body(CANARY_PROMPT), headers=AUTH
                )
                assert timed_out.status_code == 503
                assert timed_out.json()["error"]["code"] == "detector_timeout"
                # No Retry-After: the same input would usually time out again.
                assert "Retry-After" not in timed_out.headers
                assert provider.received == [], "nothing reaches the provider on a timeout"

                [event] = sink.events
                assert event.error == "detector_timeout"
                assert event.provider == "none"
                assert event.decision == "block"

                # The detector thread is still running, so it still counts.
                assert app.state.capacity.active == 1
                assert app.state.capacity.overruns == 1
                held = await client.post("/v1/chat/completions", json=body(), headers=AUTH_B)
                assert held.status_code == 503
                assert held.json()["error"]["code"] == "capacity_exceeded"

                detector.release.set()
                await wait_until(lambda: app.state.capacity.active == 0)
                # The deadline has done its job; a slow runner must not make
                # the recovery request below time out as well.
                app.state.settings.detector_timeout_seconds = 30
                assert app.state.capacity.overruns == 0
                ok = await client.post("/v1/chat/completions", json=body(), headers=AUTH_B)
                assert ok.status_code == 200
        finally:
            detector.release.set()

        assert len(provider.received) == 1
        assert_no_canary(sink, CANARY_EMAIL)

    async def test_cancelled_inspection_hands_its_work_to_the_caller(
        self, policy, vault, minter, ctx
    ):
        sink = MemorySink()
        provider = MockProvider()
        detector = BlockingDetector()
        pipeline = make_pipeline(policy, vault, minter, sink, provider, [detector])
        overruns: list[asyncio.Future[Any]] = []
        try:
            task = asyncio.create_task(
                pipeline.process(
                    ctx,
                    body(CANARY_PROMPT),
                    detection=DetectionBudget(timeout_seconds=30, on_overrun=overruns.append),
                )
            )
            await asyncio.to_thread(detector.entered.wait, 5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert len(overruns) == 1 and not overruns[0].done()
        finally:
            detector.release.set()
        await asyncio.wait_for(overruns[0], timeout=5)
        assert provider.received == []
        [event] = sink.events
        assert event.error == "cancelled"
        assert_no_canary(sink, CANARY_EMAIL)

    @pytest.mark.parametrize("timed_out", [True, False])
    async def test_an_abandoned_preparation_stores_nothing_in_the_vault(
        self, policy, vault, minter, key_store, timed_out
    ):
        """After a timeout the detector thread finishes later; it must not then
        write surrogates the client can never delete before their TTL.

        The ``timed_out=False`` case is the control: the same request, not
        abandoned, does write its mapping, so the test can see a write.
        """
        sink = MemorySink()
        detector = BlockingDetector()
        if not timed_out:
            detector.release.set()
        app = make_app(
            make_pipeline(
                policy, vault, minter, sink, MockProvider(), [*default_detectors(), detector]
            ),
            key_store,
            detector_timeout_seconds=0.05 if timed_out else 30,
        )
        conversation = "conv-abandoned"
        try:
            async with async_client(app) as client:
                response = await client.post(
                    "/v1/chat/completions",
                    json=body(CANARY_PROMPT),
                    headers={**AUTH, "X-Conversation-Id": conversation},
                )
                assert response.status_code == (503 if timed_out else 200)
                detector.release.set()
                await wait_until(lambda: app.state.capacity.active == 0)
        finally:
            detector.release.set()
        scope = RequestContext("tenant-a", conversation, "req-check", "key-a", "test-app")
        stored = vault.delete_conversation(scope)
        assert stored == (0 if timed_out else 1)

    def test_detector_error_fails_closed_with_one_event(self, policy, vault, minter, key_store):
        sink = MemorySink()
        provider = MockProvider()
        app = make_app(
            make_pipeline(policy, vault, minter, sink, provider, [FailingDetector()]), key_store
        )
        response = TestClient(app).post(
            "/v1/chat/completions", json=body(CANARY_PROMPT), headers=AUTH
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "inspection_failed"
        assert provider.received == []
        [event] = sink.events
        assert event.error == "inspection_failed"
        assert_no_canary(sink, CANARY_EMAIL)


# ---------------------------------------------------------------------------
# 4. One audit event per terminal outcome
# ---------------------------------------------------------------------------


def _provider_case(exc: BaseException):
    return lambda: RaisingProvider(exc)


PROVIDER_FAILURES = [
    (
        ProviderError("upstream timed out after 1s", 504, "provider_timeout"),
        504,
        "provider_timeout",
    ),
    (
        ProviderError("upstream request failed (ConnectError)", 502, "provider_unavailable"),
        502,
        "provider_unavailable",
    ),
    (ProviderError("upstream returned HTTP 500", 502), 502, "provider_error"),
    (
        ProviderError("upstream returned a body that is not JSON", 502, "provider_bad_response"),
        502,
        "provider_bad_response",
    ),
    (EgressBlockedError("destination 'external': resolves to 10.0.0.1"), 502, "egress_blocked"),
    (RuntimeError(f"surprise {CANARY_WORD}"), 500, "internal_error"),
]


class TestOneAuditEventPerOutcome:
    @pytest.mark.parametrize(("exc", "status", "reason"), PROVIDER_FAILURES)
    def test_provider_failures(self, policy, vault, minter, key_store, exc, status, reason):
        sink = MemorySink()
        provider = RaisingProvider(exc)
        app = make_app(make_pipeline(policy, vault, minter, sink, provider), key_store)
        response = TestClient(app).post(
            "/v1/chat/completions", json=body(CANARY_PROMPT), headers=AUTH
        )

        assert response.status_code == status
        assert response.headers["X-Request-Id"].startswith("req_")
        [event] = sink.events
        assert event.error == reason
        assert event.request_id == response.headers["X-Request-Id"]
        # The request was handed to the provider's client, and the event says
        # so -- except an egress refusal, which happens before anything is sent.
        assert event.provider == ("none" if reason == "egress_blocked" else "mock")
        assert event.decision == "transform"
        assert event.entity_counts == {"EMAIL_ADDRESS": 1}
        assert_no_canary(sink, CANARY_EMAIL, "10.0.0.1")
        assert CANARY_WORD not in response.text
        # What the provider saw was tokenised.
        assert CANARY_EMAIL not in json.dumps(provider.received)

    @pytest.mark.parametrize(
        "poison",
        [{"id": "chatcmpl-\ud800"}, {"x": float("inf")}, {"x": float("nan")}, {"x": 1e999}],
        ids=["lone-surrogate", "infinity", "nan", "overflow"],
    )
    def test_an_unserialisable_response_is_not_audited_as_a_success(
        self, policy, vault, minter, key_store, poison
    ):
        """Any adapter, not only the HTTP one, can hand back a value the
        response cannot be serialised with. It must fail as a bad upstream
        response before the success event, not as a 500 after it."""

        class PoisonProvider(MockProvider):
            async def chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
                return {**(await super().chat_completion(payload)), **poison}

        sink = MemorySink()
        app = make_app(make_pipeline(policy, vault, minter, sink, PoisonProvider()), key_store)
        response = TestClient(app).post(
            "/v1/chat/completions", json=body(CANARY_PROMPT), headers=AUTH
        )
        assert response.status_code == 502
        assert response.json()["error"]["code"] == "upstream_error"
        [event] = sink.events
        assert event.error == "provider_bad_response"
        assert event.provider == "mock"
        assert_no_canary(sink, CANARY_EMAIL)

    def test_restoration_refusal(self, policy, vault, minter, key_store):
        sink = MemorySink()
        provider = MockProvider()
        restorer = RestorationEngine(vault, max_output_bytes=16)
        app = make_app(
            make_pipeline(policy, vault, minter, sink, provider, restorer=restorer), key_store
        )
        response = TestClient(app).post(
            "/v1/chat/completions", json=body(CANARY_PROMPT), headers=AUTH
        )
        assert response.status_code == 502
        [event] = sink.events
        assert event.error == "restoration_refused"
        assert_no_canary(sink, CANARY_EMAIL)
        assert CANARY_EMAIL not in response.text

    def test_success_writes_exactly_one_event(self, pipeline, key_store, audit_sink):
        response = TestClient(make_app(pipeline, key_store)).post(
            "/v1/chat/completions", json=body(CANARY_PROMPT), headers=AUTH
        )
        assert response.status_code == 200
        [event] = audit_sink.events
        assert event.error is None
        assert event.tokens_restored == 1
        assert_no_canary(audit_sink, CANARY_EMAIL)

    @pytest.mark.parametrize(
        ("request_kwargs", "status", "reason"),
        [
            ({"json": body(CANARY_PROMPT)}, 401, "invalid_api_key"),
            (
                {
                    "json": body(CANARY_PROMPT),
                    "headers": {"Authorization": f"Bearer sgw_live_{CANARY_WORD}"},
                },
                401,
                "invalid_api_key",
            ),
            (
                {"json": body(CANARY_PROMPT), "headers": {"X-Conversation-Id": "agent_x"}},
                403,
                "reserved_conversation_scope",
            ),
            (
                {"content": f'{{"model": "{CANARY_WORD}", nope'.encode()},
                400,
                "invalid_json",
            ),
            (
                {"content": b"x" * 64, "headers": {"Content-Type": "application/json"}},
                413,
                "request_too_large",
            ),
            ({"json": body(CANARY_PROMPT, stream=True)}, 400, "streaming_unsupported"),
            ({"json": body(CANARY_PROMPT, **{CANARY_WORD: 1})}, 422, "unknown_field"),
            ({"json": body(CANARY_PROMPT, tools=[])}, 422, "uninspectable_field"),
            (
                {
                    "json": {
                        "model": "m",
                        "messages": [{"role": CANARY_WORD, "content": CANARY_PROMPT}],
                    }
                },
                422,
                "unsupported_role",
            ),
            ({"json": {"model": "m", "messages": []}}, 422, "invalid_message"),
            ({"json": [CANARY_WORD]}, 400, "invalid_request"),
            (
                {"json": body(f"{CANARY_PROMPT} key AKIAIOSFODNN7EXAMPLE")},
                403,
                "blocked_by_policy",
            ),
            (
                {"json": body(f"{CANARY_WORD}‮evil")},
                422,
                "suspicious_encoding_bidi",
            ),
        ],
    )
    def test_refusals(
        self, pipeline, key_store, mock_provider, audit_sink, request_kwargs, status, reason
    ):
        app = make_app(pipeline, key_store, max_request_bytes=48)
        if reason != "request_too_large":
            app.state.settings.max_request_bytes = 1_048_576
        headers = {**AUTH, **request_kwargs.pop("headers", {})}
        if reason == "invalid_api_key" and headers["Authorization"] == AUTH["Authorization"]:
            del headers["Authorization"]
        # Before validation the conversation header is attacker text and must
        # not reach the event. Once a request passes validation the pipeline
        # records the caller's conversation id, as it always has, for
        # correlation; those two cases use a plain one.
        entered_pipeline = reason in {"blocked_by_policy", "suspicious_encoding_bidi"}
        headers.setdefault(
            "X-Conversation-Id", "conv-1" if entered_pipeline else f"conv-{CANARY_WORD}"
        )

        response = TestClient(app).post("/v1/chat/completions", headers=headers, **request_kwargs)

        assert response.status_code == status
        assert response.headers["X-Request-Id"].startswith("req_")
        assert len(audit_sink.events) == 1, "exactly one audit event per terminal outcome"
        [event] = audit_sink.events
        assert event.request_id == response.headers["X-Request-Id"]
        assert event.provider == "none"
        assert event.decision == "block"
        assert mock_provider.received == []
        if reason == "blocked_by_policy":
            # The policy block keeps its established shape: a decision, no error.
            assert event.error is None
            assert event.rule_name == "block-secrets"
        elif entered_pipeline:
            assert event.error == reason
            assert event.conversation_id == "conv-1"
        else:
            assert event.error == reason
            assert event.rule_name == "request-refused"
            assert event.model_requested == "client-model"
            assert event.conversation_id == "anonymous"
        if reason == "invalid_api_key":
            assert event.tenant_id == "unauthenticated"
            assert event.api_key_id == "unknown"
        assert_no_canary(audit_sink, CANARY_EMAIL)

    def test_model_not_allowed(self, pipeline, audit_sink, mock_provider):
        restricted = ApiKeyStore(
            [
                ApiKey(
                    key_id="key-r",
                    key_hash=hash_key(TEST_API_KEY),
                    tenant_id="tenant-a",
                    application="test-app",
                    allowed_models=frozenset({"gpt-4o-mini"}),
                )
            ]
        )
        app = make_app(pipeline, restricted)
        response = TestClient(app).post(
            "/v1/chat/completions",
            json={"model": CANARY_WORD, "messages": [{"role": "user", "content": "hi"}]},
            headers=AUTH,
        )
        assert response.status_code == 403
        [event] = audit_sink.events
        assert event.error == "model_not_allowed"
        assert event.model_requested == "client-model"
        assert mock_provider.received == []
        assert_no_canary(audit_sink)

    async def test_body_deadline(self, pipeline, key_store, audit_sink):
        # The provider deadline stays long: the body has its own short one.
        app = make_app(
            pipeline, key_store, request_timeout_seconds=120, request_body_timeout_seconds=0.05
        )
        never = asyncio.Event()
        sent: list[dict[str, Any]] = []

        async def receive() -> dict[str, Any]:
            await never.wait()
            return {"type": "http.disconnect"}

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
                "headers": [
                    (b"host", b"testserver"),
                    (b"authorization", f"Bearer {TEST_API_KEY}".encode()),
                    (b"content-type", b"application/json"),
                ],
                "client": ("testclient", 50000),
                "server": ("testserver", 80),
            },
            receive,
            send,
        )
        assert sent[0]["status"] == 408
        assert app.state.capacity.active == 0
        [event] = audit_sink.events
        assert event.error == "request_timeout"

    async def test_a_disconnect_mid_body_is_a_cancellation(
        self, pipeline, key_store, mock_provider, audit_sink
    ):
        app = make_app(pipeline, key_store)
        messages = iter(
            [
                {"type": "http.request", "body": b'{"model": "m", "mess', "more_body": True},
                {"type": "http.disconnect"},
            ]
        )

        async def receive() -> dict[str, Any]:
            return next(messages)

        async def send(_message: dict[str, Any]) -> None:
            return None

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
                "headers": [
                    (b"host", b"testserver"),
                    (b"authorization", f"Bearer {TEST_API_KEY}".encode()),
                    (b"content-type", b"application/json"),
                ],
                "client": ("testclient", 50000),
                "server": ("testserver", 80),
            },
            receive,
            send,
        )
        [event] = audit_sink.events
        assert event.error == "cancelled"
        assert mock_provider.received == []
        assert app.state.capacity.active == 0
        assert (
            app.state.metrics.value(
                "cloakspan_requests_total",
                route="chat_completions",
                status_class="none",
                decision="none",
                destination="none",
            )
            == 1
        )

    def test_an_exception_in_the_limiter_fails_closed(
        self, pipeline, key_store, mock_provider, audit_sink
    ):
        app = make_app(pipeline, key_store)

        def broken(_key_id: str) -> float | None:
            raise RuntimeError("limiter bug")

        app.state.rate_limiter.acquire = broken
        response = TestClient(app).post("/v1/chat/completions", json=body(), headers=AUTH)
        assert response.status_code == 500
        assert mock_provider.received == []
        [event] = audit_sink.events
        assert event.error == "internal_error"

    def test_a_broken_audit_sink_does_not_turn_a_refusal_into_a_forward(
        self, pipeline, key_store, mock_provider, audit_sink, monkeypatch
    ):
        def broken(_event: Any) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(audit_sink, "write", broken)
        client = TestClient(make_app(pipeline, key_store))
        assert client.post("/v1/chat/completions", json=body()).status_code == 401
        response = client.post("/v1/chat/completions", json=body(stream=True), headers=AUTH)
        assert response.status_code == 400
        assert mock_provider.received == []

    @settings(
        max_examples=60,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    @given(
        payload=st.recursive(
            st.none() | st.booleans() | st.integers() | st.text(max_size=20),
            lambda children: (
                st.lists(children, max_size=4)
                | st.dictionaries(
                    st.sampled_from(["model", "messages", "role", "content", "stream", "x"]),
                    children,
                    max_size=4,
                )
            ),
            max_leaves=12,
        ),
        authenticated=st.booleans(),
    )
    def test_any_body_writes_exactly_one_event(self, pipeline, key_store, payload, authenticated):
        sink = MemorySink()
        pipeline._audit = sink  # noqa: SLF001 - one sink per example
        client = TestClient(make_app(pipeline, key_store))
        response = client.post(
            "/v1/chat/completions", json=payload, headers=AUTH if authenticated else {}
        )
        assert response.status_code in {200, 400, 401, 403, 413, 422}
        assert len(sink.events) == 1
        [event] = sink.events
        if response.status_code == 200:
            assert event.error is None
        elif event.error is None:
            # Only a policy block is a refusal without an error code.
            assert response.status_code == 403
            assert event.decision == "block"
            assert event.rule_name != "request-refused"
        else:
            assert event.error in {reason.value for reason in ReasonCode}


# ---------------------------------------------------------------------------
# 5. Metrics
# ---------------------------------------------------------------------------

_SAMPLE = re.compile(
    r'^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(\{(?P<labels>[a-z_]+="[^"\\\n]*"(,[a-z_]+="[^"\\\n]*")*)\})?'
    r" (?P<value>-?[0-9.e+]+)$"
)


def parse_exposition(text: str) -> dict[tuple[str, frozenset[tuple[str, str]]], float]:
    """A strict reader for what the gateway emits: every sample has a TYPE."""
    assert text.endswith("\n")
    types: dict[str, str] = {}
    samples: dict[tuple[str, frozenset[tuple[str, str]]], float] = {}
    for line in text.splitlines():
        if line.startswith("# HELP "):
            continue
        if line.startswith("# TYPE "):
            _, _, name, kind = line.split(" ")
            assert kind in {"counter", "gauge"}
            types[name] = kind
            continue
        match = _SAMPLE.match(line)
        assert match, f"not a valid exposition line: {line!r}"
        assert match["name"] in types, f"sample before its TYPE: {line!r}"
        labels = frozenset(
            tuple(pair.split("=", 1)) for pair in (match["labels"] or "").split(",") if pair
        )
        labels = frozenset((key, value.strip('"')) for key, value in labels)
        samples[(match["name"], labels)] = float(match["value"])
    return samples


def metric(samples, name: str, **labels: str) -> float:
    return samples.get((name, frozenset(labels.items())), 0.0)


class TestMetrics:
    def test_absent_unless_a_token_is_configured(self, pipeline, key_store):
        client = TestClient(make_app(pipeline, key_store))
        assert client.get("/metrics").status_code == 404
        assert client.get("/metrics", headers=AUTH).status_code == 404

    @pytest.mark.parametrize(
        "authorization",
        [None, "Bearer ", "Bearer wrong-token", f"Bearer {TEST_API_KEY}", METRICS_TOKEN],
    )
    def test_refuses_anything_but_its_own_token(self, pipeline, key_store, authorization):
        client = TestClient(make_app(pipeline, key_store, metrics_token=METRICS_TOKEN))
        headers = {"Authorization": authorization} if authorization else {}
        response = client.get("/metrics", headers=headers)
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"
        assert response.json()["error"]["code"] == "invalid_metrics_token"

    def test_serves_parseable_exposition_without_content(
        self, policy, vault, minter, key_store, audit_sink
    ):
        provider = MockProvider()
        app = make_app(
            make_pipeline(policy, vault, minter, audit_sink, provider),
            key_store,
            metrics_token=METRICS_TOKEN,
            rate_limit_per_minute=3,
        )
        app.state.rate_limiter.clock = FakeClock()
        client = TestClient(app)
        conversation = {"X-Conversation-Id": f"conv-{CANARY_WORD}"}
        client.post("/v1/chat/completions", json=body(CANARY_PROMPT), headers=AUTH)
        client.post(
            "/v1/chat/completions",
            json=body(f"{CANARY_PROMPT} <EMAIL_ADDRESS:v1:ffffffffffffffffffffffffffffffff>"),
            headers={**AUTH, **conversation},
        )
        client.post(
            "/v1/chat/completions",
            json=body("key AKIAIOSFODNN7EXAMPLE"),
            headers={**AUTH, **conversation},
        )
        client.post("/v1/chat/completions", json=body(CANARY_PROMPT), headers=AUTH)  # 429
        client.post(
            "/v1/chat/completions",
            json=body(CANARY_PROMPT),
            headers={"Authorization": f"Bearer sgw_live_{CANARY_WORD}"},
        )

        response = client.get("/metrics", headers={"Authorization": f"Bearer {METRICS_TOKEN}"})

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain; version=0.0.4")
        assert response.headers["Cache-Control"] == "no-store"
        for canary in (*CANARIES, CANARY_EMAIL, TEST_API_KEY, "key-a", "tenant-a", "gpt-4o"):
            assert canary not in response.text
        samples = parse_exposition(response.text)
        chat = {"route": "chat_completions"}
        assert (
            metric(
                samples,
                "cloakspan_requests_total",
                **chat,
                status_class="2xx",
                decision="transform",
                destination="mock",
            )
            == 2
        )
        assert (
            metric(
                samples, "cloakspan_request_refusals_total", **chat, reason="rate_limit_exceeded"
            )
            == 1
        )
        assert (
            metric(samples, "cloakspan_request_refusals_total", **chat, reason="invalid_api_key")
            == 1
        )
        assert (
            metric(samples, "cloakspan_request_refusals_total", **chat, reason="blocked_by_policy")
            == 1
        )
        assert (
            metric(samples, "cloakspan_request_refusals_total", **chat, reason="detector_timeout")
            == 0
        )
        assert metric(samples, "cloakspan_tokens_refused_total", reason="not_minted") == 1
        assert metric(samples, "cloakspan_tokens_restored_total") == 2
        assert metric(samples, "cloakspan_requests_in_flight", **chat) == 0
        assert metric(samples, "cloakspan_max_concurrent_requests", **chat) == 64
        assert metric(samples, "cloakspan_detector_overruns_in_flight", **chat) == 0
        # The metrics request itself is not a chat request and is not audited.
        assert len(audit_sink.events) == 5

    def test_label_values_outside_their_set_become_other(self):
        metrics = Metrics()
        metrics.inc("cloakspan_tokens_refused_total", reason=f"{CANARY_WORD}")
        metrics.inc(
            "cloakspan_requests_total",
            route="chat_completions",
            status_class="2xx",
            decision="allow",
            destination=f"https://{CANARY_WORD}.example",
        )
        rendered = metrics.render()
        assert CANARY_WORD not in rendered
        assert 'cloakspan_tokens_refused_total{reason="other"} 1' in rendered
        assert 'destination="other"' in rendered

    def test_every_reason_code_is_a_known_label(self):
        metrics = Metrics()
        for reason in ReasonCode:
            metrics.inc("cloakspan_request_refusals_total", route="chat_completions", reason=reason)
        assert 'reason="other"' not in metrics.render()

    def test_a_metrics_failure_does_not_fail_the_request(self, pipeline, key_store):
        app = make_app(pipeline, key_store)

        def broken(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("metrics bug")

        app.state.metrics.inc = broken
        response = TestClient(app).post("/v1/chat/completions", json=body(), headers=AUTH)
        assert response.status_code == 200

    def test_a_token_that_is_also_a_tenant_key_stops_startup(self, pipeline, key_store):
        twin = TEST_API_KEY + "x" * 32
        store = ApiKeyStore(
            [ApiKey(key_id="k", key_hash=hash_key(twin), tenant_id="t", application="a")]
        )
        with pytest.raises(ConfigurationError, match="tenant API key"):
            make_app(pipeline, store, metrics_token=twin)

    def test_the_offline_playground_serves_no_metrics(self):
        from gateway.playground.app import create_playground_app

        app = create_playground_app(
            Settings(metrics_token=METRICS_TOKEN), port=8765, access_code="test-session-code"
        )
        assert app.state.supervisor.settings.metrics_token == ""
        client = TestClient(app, base_url="http://127.0.0.1:8765")
        for headers in ({}, {"Authorization": f"Bearer {METRICS_TOKEN}"}):
            response = client.get("/metrics", headers=headers)
            assert response.status_code != 200
            assert "cloakspan_" not in response.text

    def test_a_short_token_stops_startup(self, pipeline, key_store):
        with pytest.raises(ConfigurationError, match="SAG_METRICS_TOKEN"):
            make_app(pipeline, key_store, metrics_token="short")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_PRODUCTION = {
    "SAG_ENVIRONMENT": "production",
    "SAG_API_KEYS": "sgw_live_" + "a" * 40 + ":tenant:app",
    "SAG_VAULT_KEY": "11" * 32,
    "SAG_TOKEN_KEY": "22" * 32,
}


class TestConfiguration:
    def test_defaults(self):
        parsed = Settings.from_mapping({})
        assert parsed.rate_limit_per_minute == 600
        assert parsed.max_concurrent_requests == 64
        assert parsed.detector_timeout_seconds == 15.0
        assert parsed.request_body_timeout_seconds == 15.0
        assert parsed.metrics_token == ""

    def test_values_are_read(self):
        parsed = Settings.from_mapping(
            {
                "SAG_RATE_LIMIT_PER_MINUTE": "0",
                "SAG_MAX_CONCURRENT_REQUESTS": "3",
                "SAG_DETECTOR_TIMEOUT_SECONDS": "2.5",
                "SAG_METRICS_TOKEN": METRICS_TOKEN,
            }
        )
        assert parsed.rate_limit_per_minute == 0
        assert parsed.max_concurrent_requests == 3
        assert parsed.detector_timeout_seconds == 2.5
        assert parsed.metrics_token == METRICS_TOKEN
        assert METRICS_TOKEN not in repr(parsed)

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("SAG_REQUEST_BODY_TIMEOUT_SECONDS", "0"),
            ("SAG_REQUEST_BODY_TIMEOUT_SECONDS", "301"),
            ("SAG_RATE_LIMIT_PER_MINUTE", "-1"),
            ("SAG_RATE_LIMIT_PER_MINUTE", "ten"),
            ("SAG_MAX_CONCURRENT_REQUESTS", "0"),
            ("SAG_MAX_CONCURRENT_REQUESTS", "5000"),
            ("SAG_DETECTOR_TIMEOUT_SECONDS", "0"),
            ("SAG_DETECTOR_TIMEOUT_SECONDS", "nan"),
            ("SAG_DETECTOR_TIMEOUT_SECONDS", "301"),
        ],
    )
    def test_out_of_range_values_stop_startup(self, name, value):
        with pytest.raises(ConfigurationError, match=name):
            Settings.from_mapping({name: value})

    @pytest.mark.parametrize(
        "token",
        ["short", "a" * 64, "ab" * 32, "has a space in it 0123456789abcdef"],
    )
    @pytest.mark.parametrize("environment", ["production", "development"])
    def test_weak_metrics_token_stops_startup(self, token, environment):
        env = {**_PRODUCTION, "SAG_ENVIRONMENT": environment, "SAG_METRICS_TOKEN": token}
        with pytest.raises(ConfigurationError, match="SAG_METRICS_TOKEN") as raised:
            Settings.from_mapping(env)
        assert token not in str(raised.value)

    def test_production_accepts_a_strong_metrics_token(self):
        assert Settings.from_mapping({**_PRODUCTION, "SAG_METRICS_TOKEN": METRICS_TOKEN})

    def test_reused_tenant_key_is_reported_without_its_value(self):
        key = "sgw_live_" + "b" * 40
        parsed = inspect_environment(
            {**_PRODUCTION, "SAG_API_KEYS": f"{key}:t:a", "SAG_METRICS_TOKEN": key}
        )
        [issue] = [issue for issue in parsed.issues if issue.id == "metrics.token.reused"]
        assert issue.startup_fatal
        assert key not in f"{issue.summary} {issue.remediation}"

    def test_new_settings_are_wired_into_compose_env_example_and_docs(self):
        from pathlib import Path

        import yaml

        root = Path(__file__).resolve().parent.parent
        compose = yaml.safe_load((root / "compose.yaml").read_text(encoding="utf-8"))
        environment = compose["services"]["gateway"]["environment"]
        example = (root / ".env.example").read_text(encoding="utf-8")
        docs = (root / "docs" / "configuration.md").read_text(encoding="utf-8")
        for name in (
            "SAG_REQUEST_BODY_TIMEOUT_SECONDS",
            "SAG_RATE_LIMIT_PER_MINUTE",
            "SAG_MAX_CONCURRENT_REQUESTS",
            "SAG_DETECTOR_TIMEOUT_SECONDS",
            "SAG_METRICS_TOKEN",
        ):
            assert name in environment, f"{name} is not passed by compose.yaml"
            assert re.search(rf"^{name}=", example, re.MULTILINE), f"{name} not in .env.example"
            assert f"`{name}`" in docs, f"{name} not in docs/configuration.md"
        assert environment["SAG_METRICS_TOKEN"] == "${SAG_METRICS_TOKEN:-}"

    def test_the_reason_codes_match_the_runbook(self):
        """docs/operations.md lists every audit reason code, and no other."""
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent
        operations = (root / "docs" / "operations.md").read_text(encoding="utf-8")
        section = operations.split("### Audit reason codes", 1)[1].split("\n## ", 1)[0]
        documented: set[str] = set()
        for row in re.findall(r"^\| (`[^|]+) \|", section, re.MULTILINE):
            documented.update(re.findall(r"`([a-z_*]+)`", row))
        if "suspicious_encoding_*" in documented:
            documented.remove("suspicious_encoding_*")
            documented.update(
                reason for reason in ReasonCode if reason.startswith("suspicious_encoding_")
            )
        # A policy block is a decision, not an error code; it is documented as such.
        produced = {reason.value for reason in ReasonCode} - {"blocked_by_policy"}
        assert documented == produced
