"""OpenAI-compatible HTTP surface.

Errors are mapped to OpenAI's error envelope so existing SDKs handle them
naturally. Error messages never include prompt content or provider
credentials -- an error path is still a log path.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
import uuid
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from starlette.requests import ClientDisconnect

from gateway.api.limits import ConcurrencyLimiter, RateLimiter, Slot, retry_after_header
from gateway.api.schema import RequestRejected, parse_chat_completion_request
from gateway.audit.events import build_event
from gateway.audit.reasons import ReasonCode, contract_reason, reason_for_exception
from gateway.auth.keys import ApiKeyStore
from gateway.config import ConfigurationError, Settings, build_key_store, build_pipeline
from gateway.config_validation import MIN_METRICS_TOKEN_BYTES
from gateway.domain import RequestContext
from gateway.inspection.pipeline import (
    DetectionBudget,
    DetectionError,
    PolicyBlockedError,
    SecurityPipeline,
)
from gateway.normalization import SuspiciousEncodingError
from gateway.routing.base import ProviderError
from gateway.routing.egress import EgressBlockedError
from gateway.telemetry.metrics import (
    REASONS,
    TOKEN_REFUSAL_REASONS,
    Metrics,
    status_class,
    token_matches,
)

logger = logging.getLogger("gateway.api")

try:
    APP_VERSION = version("secure-ai-gateway")
except PackageNotFoundError:  # Source checkout before an editable install.
    APP_VERSION = "0.1.0a1"

#: How often the expiry sweep runs. The sweep bounds memory; it is **not** the
#: expiry mechanism -- TTL is enforced on read, so a sweep that stops running
#: cannot silently extend the lifetime of personal data. See
#: docs/adr/0013-vault-lifetime-deletion-and-restart.md.
SWEEP_INTERVAL_SECONDS = 60.0


class RequestBodyTooLargeError(Exception):
    """Raised as soon as a streamed request crosses its configured byte cap."""


async def _read_json_body(request: Request, max_bytes: int) -> Any:
    """Read and decode JSON without ever accumulating more than ``max_bytes``."""
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > max_bytes:
            raise RequestBodyTooLargeError
        body.extend(chunk)
    return json.loads(body)


def _declared_body_too_large(request: Request, max_bytes: int) -> bool:
    """Use a valid Content-Length as an early rejection, never as the sole limit."""
    declared = request.headers.get("content-length")
    if declared is None:
        return False
    try:
        return int(declared) > max_bytes
    except ValueError:
        # The stream remains authoritative when the header is absent or invalid.
        return False


def error_response(
    status: int,
    message: str,
    error_type: str,
    code: str | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "error": {
                "message": message,
                "type": error_type,
                "param": None,
                "code": code,
            }
        },
        headers=headers,
    )


#: Fixed audit placeholders for values a client controls but the gateway has
#: not validated yet. An error-path audit event must not become a way to write
#: attacker-chosen strings into the audit log (SI-11).
UNAUTHENTICATED = "unauthenticated"
UNVALIDATED_CONVERSATION = "anonymous"
UNVALIDATED_MODEL = "client-model"
CHAT_ROUTE = "chat_completions"


@dataclass(slots=True)
class _ChatOutcome:
    """The terminal outcome of one chat request, for its audit event and metrics."""

    ctx: RequestContext
    status: int | None = None
    reason: ReasonCode | None = None
    #: Set once ``pipeline.process`` is entered: from then on the pipeline owns
    #: the request's single audit event, on every exit.
    pipeline_audits: bool = False
    decision: str = "none"
    destination: str = "none"
    tokens_restored: int = 0
    tokens_refused: dict[str, int] = field(default_factory=dict)
    slot: Slot | None = None


def _bearer(authorization: str | None) -> str:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def _exception_response(exc: Exception, request_id: str) -> tuple[int, ReasonCode, JSONResponse]:
    """Map an exception raised while serving a chat request to its response.

    Messages are fixed strings, or exception messages built to be safe to
    surface (SI-11, SI-12); the reason code never reads them.
    """
    reason = reason_for_exception(exc)
    if isinstance(exc, PolicyBlockedError):
        reason = ReasonCode.BLOCKED_BY_POLICY
        return 403, reason, error_response(403, str(exc), "policy_violation", reason)
    if isinstance(exc, SuspiciousEncodingError):
        # The encoding itself is the finding. The reason code tells the
        # operator which class was refused; neither the message nor the log
        # carries the content (SI-11).
        logger.warning("refused request %s: %s (%d characters)", request_id, reason, exc.count)
        return 422, reason, error_response(422, str(exc), "inspection_error", exc.reason)
    if reason is ReasonCode.DETECTOR_TIMEOUT:
        # 503 rather than 422: an inspection that did not finish is a capacity
        # condition as often as it is a property of the input. No Retry-After:
        # the failure is often deterministic for this input, and an immediate
        # retry would occupy another slot behind the first one's overrun.
        response = error_response(
            503,
            "Content inspection did not finish within its deadline; nothing was forwarded.",
            "inspection_error",
            reason,
        )
        return 503, reason, response
    if isinstance(exc, DetectionError):
        # Fail closed: we could not inspect, so we do not forward.
        return 422, reason, error_response(422, str(exc), "inspection_error", "inspection_failed")
    if isinstance(exc, ProviderError) and reason is not ReasonCode.INTERNAL_ERROR:
        status = exc.status_code if 400 <= exc.status_code < 600 else 502
        return status, reason, error_response(status, str(exc), "api_error", "upstream_error")
    if isinstance(exc, EgressBlockedError):
        # The message names the destination host; the client does not need it.
        logger.error("egress refused for request %s", request_id)
        response = error_response(
            502,
            f"The configured provider destination was refused. Request id: {request_id}",
            "api_error",
            "upstream_error",
        )
        return 502, reason, response
    # Never leak internals. The traceback goes to the log; the client gets a
    # request id to quote.
    logger.error("unhandled error processing request %s", request_id, exc_info=exc)
    return (
        500,
        reason,
        error_response(500, f"Internal error. Request id: {request_id}", "api_error"),
    )


def _build_metrics(app: FastAPI) -> Metrics:
    metrics = Metrics()
    # Every refusal series exists from the first scrape, at zero, so an alert
    # on a rate does not first need the event it is waiting for.
    for reason in sorted(REASONS):
        metrics.inc("cloakspan_request_refusals_total", 0, route=CHAT_ROUTE, reason=reason)
    for reason in sorted(TOKEN_REFUSAL_REASONS):
        metrics.inc("cloakspan_tokens_refused_total", 0, reason=reason)
    metrics.inc("cloakspan_tokens_restored_total", 0)
    metrics.gauge(
        "cloakspan_requests_in_flight", lambda: app.state.capacity.active, route=CHAT_ROUTE
    )
    metrics.gauge(
        "cloakspan_max_concurrent_requests", lambda: app.state.capacity.limit, route=CHAT_ROUTE
    )
    metrics.gauge(
        "cloakspan_detector_overruns_in_flight",
        lambda: app.state.capacity.overruns,
        route=CHAT_ROUTE,
    )
    return metrics


def _check_metrics_token(token: str, key_store: ApiKeyStore) -> None:
    """Refuse a metrics token that is short, or that a tenant already holds.

    ``Settings.from_env`` applies the same rules from the environment; this
    covers settings built directly and a key store the caller injected.
    """
    if len(token) < MIN_METRICS_TOKEN_BYTES:
        raise ConfigurationError(
            f"SAG_METRICS_TOKEN must be at least {MIN_METRICS_TOKEN_BYTES} characters."
        )
    if key_store.authenticate(token) is not None:
        raise ConfigurationError(
            "SAG_METRICS_TOKEN is also a tenant API key; use a separate secret."
        )


async def _serve_chat(
    app: FastAPI,
    request: Request,
    authorization: str | None,
    x_conversation_id: str | None,
    outcome: _ChatOutcome,
) -> JSONResponse:
    """Serve one chat request. Every return records its outcome first."""
    settings: Settings = app.state.settings
    request_id = outcome.ctx.request_id

    def refuse(
        status: int,
        reason: ReasonCode,
        message: str,
        error_type: str = "invalid_request_error",
        code: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> JSONResponse:
        outcome.status, outcome.reason = status, reason
        return error_response(status, message, error_type, code, headers)

    api_key = app.state.key_store.authenticate(_bearer(authorization))
    if api_key is None:
        return refuse(401, ReasonCode.INVALID_API_KEY, "Invalid API key.", code="invalid_api_key")
    outcome.ctx = RequestContext(
        api_key.tenant_id,
        UNVALIDATED_CONVERSATION,
        request_id,
        api_key.key_id,
        api_key.application,
    )

    # Admission, before the body is read: a refused request costs no parsing.
    wait = app.state.rate_limiter.acquire(api_key.key_id)
    if wait is not None:
        return refuse(
            429,
            ReasonCode.RATE_LIMIT_EXCEEDED,
            "Rate limit exceeded for this API key. Retry after the interval in Retry-After.",
            "rate_limit_error",
            ReasonCode.RATE_LIMIT_EXCEEDED,
            {"Retry-After": retry_after_header(wait)},
        )
    outcome.slot = app.state.capacity.try_acquire()
    if outcome.slot is None:
        # Not this key's fault: give back the request it was just charged.
        app.state.rate_limiter.refund(api_key.key_id)
        return refuse(
            503,
            ReasonCode.CAPACITY_EXCEEDED,
            "The gateway is at its concurrent request limit. Retry shortly.",
            "server_error",
            ReasonCode.CAPACITY_EXCEEDED,
            {"Retry-After": "1"},
        )

    if x_conversation_id and x_conversation_id.startswith("agent_"):
        return refuse(
            403,
            ReasonCode.RESERVED_CONVERSATION_SCOPE,
            "Use the agent endpoint for an agent session.",
            code="reserved_conversation_scope",
        )

    too_large = "Request body exceeds the maximum allowed size."
    if _declared_body_too_large(request, settings.max_request_bytes):
        return refuse(413, ReasonCode.REQUEST_TOO_LARGE, too_large, code="request_too_large")

    try:
        # A slot is held while the body arrives, so the body has its own short
        # deadline: otherwise a client trickling bytes could hold every slot
        # for the whole provider deadline.
        async with asyncio.timeout(settings.request_body_timeout_seconds):
            body = await _read_json_body(request, settings.max_request_bytes)
    except RequestBodyTooLargeError:
        return refuse(413, ReasonCode.REQUEST_TOO_LARGE, too_large, code="request_too_large")
    except ClientDisconnect:
        # Nobody is left to answer. Audited as a cancellation, not a bad body.
        outcome.status, outcome.reason = None, ReasonCode.CANCELLED
        return error_response(400, "Client disconnected.", "invalid_request_error")
    except TimeoutError:
        return refuse(
            408,
            ReasonCode.REQUEST_TIMEOUT,
            "Request body was not received within the deadline.",
            code="request_timeout",
        )
    except Exception:  # noqa: BLE001 - malformed body, nothing useful to surface
        return refuse(400, ReasonCode.INVALID_JSON, "Request body is not valid JSON.")

    model = str(body.get("model", "")) if isinstance(body, dict) else ""
    if not api_key.permits_model(model):
        return refuse(
            403,
            ReasonCode.MODEL_NOT_ALLOWED,
            f"This API key is not permitted to use model '{model}'.",
        )

    # Reject-unknown. Every field is understood and inspected, or refused
    # with a documented code -- there is no pass-through. The payload handed
    # to the pipeline is rebuilt from validated fields, so a key that is not
    # on the model cannot reach the provider (SI-01, SI-02).
    try:
        validated = parse_chat_completion_request(body)
    except RequestRejected as exc:
        error_type = "invalid_request_error" if exc.status < 422 else "inspection_error"
        return refuse(exc.status, contract_reason(exc.code), exc.detail, error_type, exc.code)

    payload = validated.to_payload()

    ctx = RequestContext(
        tenant_id=api_key.tenant_id,
        conversation_id=x_conversation_id or f"conv_{uuid.uuid4().hex}",
        request_id=request_id,
        api_key_id=api_key.key_id,
        application=api_key.application,
    )
    outcome.ctx = ctx
    outcome.pipeline_audits = True
    result = await app.state.pipeline.process(
        ctx,
        payload,
        detection=DetectionBudget(
            timeout_seconds=settings.detector_timeout_seconds,
            executor=app.state.detector_executor,
            on_overrun=outcome.slot.hold_until,
        ),
    )

    outcome.status = 200
    outcome.decision = result.decision_action
    outcome.destination = result.provider
    outcome.tokens_restored = result.restoration.restored
    outcome.tokens_refused = result.restoration.reasons()

    response = JSONResponse(content=result.response)
    response.headers["X-Conversation-Id"] = ctx.conversation_id
    response.headers["X-Policy-Decision"] = result.decision_action
    response.headers["X-Policy-Rule"] = result.rule_name
    response.headers["X-Policy-Version"] = result.policy_version
    response.headers["X-Entities-Detected"] = str(sum(result.entity_counts.values()))
    response.headers["X-Tokens-Restored"] = str(result.restoration.restored)
    response.headers["X-Tokens-Refused"] = str(result.restoration.total_refused)
    return response


def _finish_chat(app: FastAPI, outcome: _ChatOutcome, started: float) -> None:
    """Write the request's audit event, unless the pipeline did, then metrics.

    Neither may raise: the response is already decided, and an exception here
    would only replace one refusal with another.
    """
    if not outcome.pipeline_audits:
        pipeline: SecurityPipeline = app.state.pipeline
        try:
            pipeline.audit.write(
                build_event(
                    outcome.ctx,
                    model_requested=UNVALIDATED_MODEL,
                    decision=pipeline.refusal_decision(),
                    provider="none",
                    entity_counts={},
                    latency_ms=(time.perf_counter() - started) * 1000,
                    error=(outcome.reason or ReasonCode.INTERNAL_ERROR).value,
                )
            )
        except Exception:
            logger.exception("audit write failed for request %s", outcome.ctx.request_id)
    try:
        metrics: Metrics = app.state.metrics
        metrics.inc(
            "cloakspan_requests_total",
            route=CHAT_ROUTE,
            status_class=status_class(outcome.status),
            decision=outcome.decision,
            destination=outcome.destination,
        )
        if outcome.reason is not None:
            metrics.inc("cloakspan_request_refusals_total", route=CHAT_ROUTE, reason=outcome.reason)
        if outcome.tokens_restored:
            metrics.inc("cloakspan_tokens_restored_total", outcome.tokens_restored)
        for reason, count in outcome.tokens_refused.items():
            metrics.inc("cloakspan_tokens_refused_total", count, reason=reason)
    except Exception:
        logger.exception("metrics update failed for request %s", outcome.ctx.request_id)


async def _sweep_forever(app: FastAPI) -> None:
    """Purge expired vault records on a fixed interval.

    A failure here logs and continues. It must never fail requests: read-time
    expiry still holds the privacy line, and taking the gateway down because a
    memory-management task stopped would be a self-inflicted outage.
    """
    while True:
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
        try:
            purged = app.state.pipeline.vault.purge_expired()
        except Exception:
            logger.exception("vault sweep failed; read-time expiry still applies")
            continue
        if purged:
            logger.info("vault sweep purged %d expired records", purged)


def create_app(
    pipeline: SecurityPipeline | None = None,
    key_store: ApiKeyStore | None = None,
    settings: Settings | None = None,
    agent_providers: dict[str, dict[str, Any]] | None = None,
) -> FastAPI:
    resolved_settings = settings or Settings.from_env()

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        sweeper = asyncio.create_task(_sweep_forever(app))
        try:
            yield
        finally:
            sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sweeper
            # Providers keep pooled connections open so a request does not pay
            # a handshake it does not need. Hand the sockets back here, inside
            # the graceful-shutdown window, rather than at interpreter exit.
            await app.state.pipeline.aclose_providers()
            if hasattr(app.state, "agent_runtime"):
                await app.state.agent_runtime.aclose()
            # Does not wait here, and drops detector work not yet started. A
            # detector still running past its deadline is a different matter:
            # the interpreter joins pool threads at exit, so it delays process
            # exit until it returns or the container runtime kills the process.
            app.state.detector_executor.shutdown(wait=False, cancel_futures=True)

    app = FastAPI(
        title="Cloakspan",
        version=APP_VERSION,
        docs_url=None,  # No interactive docs by default: it is an
        redoc_url=None,  # unnecessary surface on a security appliance.
        openapi_url=None,
        lifespan=lifespan,
    )

    app.state.pipeline = pipeline or build_pipeline(resolved_settings)
    app.state.key_store = key_store or build_key_store()
    app.state.settings = resolved_settings
    app.state.ready = True

    # Admission limits and metrics live on app.state, never at module level,
    # so two apps in one process (tests, the benchmark) never share them.
    if resolved_settings.metrics_token:
        _check_metrics_token(resolved_settings.metrics_token, app.state.key_store)
    app.state.rate_limiter = RateLimiter(resolved_settings.rate_limit_per_minute)
    app.state.capacity = ConcurrencyLimiter(resolved_settings.max_concurrent_requests)
    # At most one detector thread per admitted request, so this pool never
    # queues work, and a detector stuck past its deadline cannot starve the
    # default executor that egress validation and restoration use.
    app.state.detector_executor = ThreadPoolExecutor(
        max_workers=resolved_settings.max_concurrent_requests,
        thread_name_prefix="cloakspan-detect",
    )
    app.state.metrics = _build_metrics(app)

    if resolved_settings.enable_responses or resolved_settings.enable_messages:
        from gateway.api.agent import register_session_deletion
        from gateway.api.agent_runtime import AgentRuntime

        app.state.agent_runtime = AgentRuntime(
            app.state.pipeline, resolved_settings, agent_providers
        )
        register_session_deletion(app)
        if resolved_settings.enable_responses:
            from gateway.api.responses import register_responses

            register_responses(app)
        if resolved_settings.enable_messages:
            from gateway.api.messages import register_messages

            register_messages(app)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness: the process is up. Never touches downstream dependencies."""
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        """Readiness: we can actually serve.

        Deliberately does NOT check the external provider. The Community
        Edition must keep serving locally-routed and blocked requests when the
        Internet is down -- and control-plane or provider availability must
        never gate the self-hosted request path (security invariant SI-15).
        """
        ready = bool(app.state.ready and len(app.state.key_store))
        return JSONResponse(
            status_code=200 if ready else 503,
            content={"status": "ready" if ready else "not_ready"},
        )

    if resolved_settings.metrics_token:

        @app.get("/metrics", include_in_schema=False)
        async def metrics(authorization: str | None = Header(default=None)) -> Response:
            """Prometheus text exposition, behind its own bearer token.

            Not registered at all unless SAG_METRICS_TOKEN is set. The key
            store is never consulted, so a tenant API key cannot satisfy it and
            this route cannot be used to test whether a key is valid.
            """
            if not token_matches(_bearer(authorization), resolved_settings.metrics_token):
                return error_response(
                    401,
                    "Invalid metrics token.",
                    "invalid_request_error",
                    "invalid_metrics_token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return PlainTextResponse(
                app.state.metrics.render(),
                media_type="text/plain; version=0.0.4; charset=utf-8",
                headers={"Cache-Control": "no-store"},
            )

    @app.post("/v1/chat/completions")
    async def chat_completions(
        request: Request,
        authorization: str | None = Header(default=None),
        x_conversation_id: str | None = Header(default=None),
    ) -> JSONResponse:
        started = time.perf_counter()
        request_id = f"req_{uuid.uuid4().hex}"
        outcome = _ChatOutcome(
            ctx=RequestContext(
                UNAUTHENTICATED, UNVALIDATED_CONVERSATION, request_id, "unknown", "unknown"
            )
        )
        try:
            response = await _serve_chat(app, request, authorization, x_conversation_id, outcome)
        except asyncio.CancelledError:
            outcome.status, outcome.reason = None, ReasonCode.CANCELLED
            raise
        except Exception as exc:  # noqa: BLE001 - every failure gets a fixed, audited response
            outcome.status, outcome.reason, response = _exception_response(exc, request_id)
            if outcome.reason is ReasonCode.BLOCKED_BY_POLICY:
                outcome.decision = "block"
        finally:
            if outcome.slot is not None:
                outcome.slot.release()
            _finish_chat(app, outcome, started)
        response.headers["X-Request-Id"] = request_id
        return response

    @app.delete("/v1/conversations/{conversation_id}")
    async def delete_conversation(
        conversation_id: str,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        """Erase every surrogate mapping for a conversation.

        Required for an erasure request to be answerable with something other
        than "wait for the TTL". Scoped to the caller's tenant by construction:
        the storage key is built from the authenticated tenant, so one tenant
        cannot delete another's records even by guessing a conversation id.
        """
        presented = (
            authorization[7:].strip()
            if authorization and authorization.lower().startswith("bearer ")
            else ""
        )
        api_key = app.state.key_store.authenticate(presented)
        if api_key is None:
            return error_response(
                401, "Invalid API key.", "invalid_request_error", "invalid_api_key"
            )
        if not conversation_id:
            return error_response(400, "A conversation id is required.", "invalid_request_error")
        if conversation_id.startswith("agent_"):
            return error_response(
                403,
                "Use /v1/agent/sessions with the original client session ID.",
                "invalid_request_error",
                "reserved_conversation_scope",
            )

        ctx = RequestContext(
            tenant_id=api_key.tenant_id,
            conversation_id=conversation_id,
            request_id=f"req_{uuid.uuid4().hex}",
            api_key_id=api_key.key_id,
            application=api_key.application,
        )
        deleted = app.state.pipeline.vault.delete_conversation(ctx)
        logger.info("deleted %d vault records for conversation %s", deleted, ctx.request_id)
        return JSONResponse(
            content={
                "object": "conversation.deleted",
                "id": conversation_id,
                "deleted": True,
                "records_removed": deleted,
            }
        )

    @app.get("/v1/models")
    async def models(
        request: Request, authorization: str | None = Header(default=None)
    ) -> JSONResponse:
        presented = (
            authorization[7:].strip()
            if authorization and authorization.lower().startswith("bearer ")
            else ""
        )
        if hasattr(app.state, "agent_runtime"):
            from gateway.api.agent import authenticate

            api_key = authenticate(
                request, "messages" if resolved_settings.enable_messages else "responses"
            )
        else:
            api_key = app.state.key_store.authenticate(presented)
        if hasattr(app.state, "agent_runtime"):
            if any(
                len(request.headers.getlist(name)) > 1 for name in ("authorization", "x-api-key")
            ):
                api_key = None
            audit_ctx = RequestContext(
                api_key.tenant_id if api_key else "unauthenticated",
                "agent-model-discovery",
                "req_" + uuid.uuid4().hex,
                api_key.key_id if api_key else "unknown",
                api_key.application if api_key else "agent",
            )
            app.state.agent_runtime.audit(
                audit_ctx,
                error=None if api_key else "invalid_api_key",
                operation="agent-model-discovery",
            )
        if api_key is None:
            return error_response(
                401, "Invalid API key.", "invalid_request_error", "invalid_api_key"
            )
        if hasattr(app.state, "agent_runtime"):
            names = {
                name
                for name in (
                    resolved_settings.external_model if resolved_settings.enable_responses else "",
                    resolved_settings.messages_model if resolved_settings.enable_messages else "",
                    resolved_settings.local_model,
                )
                if name
            } or {"mock-model"}
            destinations = sorted(name for name in names if api_key.permits_model(name))
        else:
            destinations = sorted(app.state.pipeline._providers)  # noqa: SLF001
        return JSONResponse(
            content={
                "object": "list",
                "data": [
                    {"id": name, "object": "model", "created": 0, "owned_by": "secure-ai-gateway"}
                    for name in destinations
                ],
            }
        )

    return app
