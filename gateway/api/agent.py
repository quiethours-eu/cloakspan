"""Authenticated HTTP boundaries shared by the two opt-in protocol adapters."""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from gateway.api.agent_runtime import AgentRuntime, StreamLifecycle
from gateway.api.schema import RequestRejected
from gateway.domain import RequestContext
from gateway.inspection.agent import AgentInputLimitExceeded
from gateway.inspection.pipeline import PolicyBlockedError
from gateway.inspection.preparation import DetectionError
from gateway.protocols.base import ValidatedRequest, loads_json
from gateway.routing.base import ProviderError
from gateway.sessions.scope import SessionScopeError, session_scope


class AgentStreamingResponse(StreamingResponse):
    def __init__(self, iterator: Any, lifecycle: StreamLifecycle, **kwargs: Any) -> None:
        super().__init__(iterator, **kwargs)
        self.lifecycle = lifecycle

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            try:
                await self.body_iterator.aclose()
            finally:
                self.lifecycle.finish()


def protocol_error(
    protocol: str, status: int, code: str, message: str, request_id: str
) -> JSONResponse:
    if protocol == "messages":
        body = {
            "type": "error",
            "error": {
                "type": {
                    401: "authentication_error",
                    403: "permission_error",
                    404: "not_found_error",
                    413: "request_too_large",
                    429: "rate_limit_error",
                    529: "overloaded_error",
                }.get(status, "invalid_request_error" if status < 500 else "api_error"),
                "message": message,
                "code": code,
            },
            "request_id": request_id,
        }
    else:
        body = {
            "error": {
                "message": message,
                "type": {
                    401: "authentication_error",
                    403: "permission_error",
                    429: "rate_limit_error",
                }.get(status, "invalid_request_error" if status < 500 else "api_error"),
                "param": None,
                "code": code,
            },
            "request_id": request_id,
        }
    return JSONResponse(body, status_code=status, headers={"X-Request-Id": request_id})


def authenticate(request: Request, protocol: str) -> Any:
    auth = request.headers.get("authorization", "")
    bearer = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    native = request.headers.get("x-api-key", "") if protocol == "messages" else ""
    if bearer and native and bearer != native:
        return None
    return request.app.state.key_store.authenticate(bearer or native)


async def read_body(request: Request, limit: int) -> Any:
    declared = request.headers.get("content-length")
    try:
        if declared and int(declared) > limit:
            raise RequestRejected(
                413, "request_too_large", "Request exceeds the byte limit; shorten history."
            )
    except ValueError:
        pass
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > limit:
            raise RequestRejected(
                413, "request_too_large", "Request exceeds the byte limit; shorten history."
            )
        raw.extend(chunk)
    return loads_json(bytes(raw))


def response_headers(ctx: RequestContext, identity: str, prepared: Any) -> dict[str, str]:
    return {
        "X-Request-Id": ctx.request_id,
        "X-Session-Id": identity,
        "X-Conversation-Id": identity,
        "X-Policy-Decision": prepared.decision.action.value,
        "X-Policy-Rule": prepared.decision.rule_name,
        "X-Policy-Version": prepared.decision.policy_version,
        "X-Entities-Detected": str(sum(prepared.entity_counts.values())),
    }


async def handle_request(
    request: Request,
    protocol: str,
    parser: Callable[..., ValidatedRequest],
    *,
    count_tokens: bool = False,
    unsupported: bool = False,
) -> Any:
    runtime: AgentRuntime = request.app.state.agent_runtime
    request_id = "req_" + uuid.uuid4().hex
    ctx = RequestContext("unauthenticated", "anonymous", request_id, "unknown", "agent")
    started = time.perf_counter()
    prepared = None
    admitted = False
    handed_stream = False
    runtime_audits = False
    try:
        key = authenticate(request, protocol)
        if key is None:
            raise RequestRejected(401, "invalid_api_key", "Authenticate with a gateway API key.")
        identity, scope = session_scope(
            key,
            [
                request.headers.get(name)
                for name in (
                    "x-session-id",
                    "session_id",
                    "session-id",
                    "thread-id",
                    "x-conversation-id",
                    "x-claude-code-session-id",
                )
            ],
            agent_id=request.headers.get("x-claude-code-agent-id"),
        )
        ctx = RequestContext(key.tenant_id, scope, request_id, key.key_id, key.application)
        for header in (
            "authorization",
            "x-api-key",
            "x-session-id",
            "session_id",
            "session-id",
            "thread-id",
            "x-conversation-id",
            "x-claude-code-session-id",
            "x-claude-code-agent-id",
            "anthropic-version",
            "anthropic-beta",
        ):
            if len(request.headers.getlist(header)) > 1:
                raise RequestRejected(
                    400, "invalid_headers", "Send one value per authentication or session header."
                )
        native_betas: tuple[str, ...] = ()
        if protocol == "messages":
            if request.headers.get("anthropic-version", "2023-06-01") != "2023-06-01":
                raise RequestRejected(
                    422, "unsupported_version", "Use the tested Anthropic version 2023-06-01."
                )
            if "anthropic-beta" in request.headers:
                from gateway.protocols.messages import SUPPORTED_MESSAGES_BETAS

                raw_betas = request.headers["anthropic-beta"]
                values = raw_betas.split(",")
                if (
                    len(raw_betas) > 512
                    or not 1 <= len(values) <= len(SUPPORTED_MESSAGES_BETAS)
                    or any(value.strip() not in SUPPORTED_MESSAGES_BETAS for value in values)
                ):
                    raise RequestRejected(
                        422,
                        "unsupported_beta",
                        "Use only the documented inspectable Messages capabilities.",
                    )
                native_betas = tuple(sorted({value.strip() for value in values}))
        if unsupported:
            raise RequestRejected(
                422,
                "unsupported_continuation",
                "Opaque compaction and stored continuation are disabled; "
                "replay inspectable history.",
            )
        content_type = (
            request.headers.get("content-type", "application/json").lower().replace(" ", "")
        )
        if content_type not in {"application/json", "application/json;charset=utf-8"}:
            raise RequestRejected(
                415, "invalid_encoding", "Send application/json encoded as UTF-8."
            )
        if not runtime.admit():
            raise RequestRejected(
                429,
                "capacity_exceeded",
                "Agent capacity is full; retry after active requests finish.",
            )
        admitted = True
        try:
            async with asyncio.timeout(runtime.settings.request_timeout_seconds):
                body = await read_body(request, runtime.settings.max_request_bytes)
        except TimeoutError as exc:
            raise RequestRejected(
                408,
                "request_timeout",
                "Request body deadline exceeded; retry with a complete body.",
            ) from exc
        if count_tokens and isinstance(body, dict):
            body = dict(body)
            body.setdefault("max_tokens", 1)
            if body.get("stream"):
                raise RequestRejected(
                    422, "invalid_request", "Token counting is not a streaming operation."
                )
        validated = parser(body)
        if not key.permits_model(validated.model):
            raise RequestRejected(
                403, "model_not_allowed", "Choose a model authorized for this gateway credential."
            )
        prepared = await runtime.prepare(ctx, validated)
        prepared.native_betas = native_betas
        headers = response_headers(ctx, identity, prepared)
        if validated.stream:
            lifecycle = StreamLifecycle(runtime, ctx, prepared)
            response = AgentStreamingResponse(
                runtime.stream(ctx, prepared, lifecycle=lifecycle),
                lifecycle,
                media_type="text/event-stream",
                headers={**headers, "Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
            )
            handed_stream = True
            return response
        runtime_audits = True
        result = await runtime.complete(ctx, prepared, count_tokens=count_tokens)
        headers["X-Tokens-Restored"] = str(result.restoration.restored)
        headers["X-Tokens-Refused"] = str(result.restoration.total_refused)
        return JSONResponse(result.response, headers=headers)
    except asyncio.CancelledError:
        if not runtime_audits:
            runtime.audit(ctx, prepared=prepared, error="cancelled", started=started)
        raise
    except Exception as exc:
        prepared = getattr(exc, "prepared", prepared)
        if isinstance(exc, RequestRejected):
            status, code, message = exc.status, exc.code, exc.detail
        elif isinstance(exc, SessionScopeError):
            status, code, message = 400, "invalid_session", str(exc)
        elif isinstance(exc, PolicyBlockedError):
            status, code, message = (
                403,
                "blocked_by_policy",
                "Request blocked by privacy policy; remove prohibited content.",
            )
        elif isinstance(exc, AgentInputLimitExceeded):
            status, code, message = (
                400,
                "context_length_exceeded",
                "prompt is too long: gateway inspection limit exceeded; "
                "compact inspectable history.",
            )
        elif isinstance(exc, DetectionError):
            status, code, message = (
                422,
                "inspection_failed",
                "Inspection failed; reduce input or check detector configuration.",
            )
        elif isinstance(exc, ProviderError):
            status, code, message = (
                exc.status_code,
                "upstream_error",
                "Native provider request failed; check the configured protocol and provider.",
            )
        else:
            status = 502 if prepared else 500
            code = getattr(
                exc, "code", "response_validation_failed" if prepared else "internal_error"
            )
            message = (
                "Response validation failed; replay original history "
                "and check protocol capability settings."
            )
        if not runtime_audits:
            runtime.audit(
                ctx,
                prepared=prepared,
                error=code,
                outcome=getattr(exc, "outcome", None),
                started=started,
            )
        return protocol_error(protocol, status, code, message, request_id)
    finally:
        if admitted and not handed_stream:
            runtime.release()


def register_session_deletion(app: FastAPI) -> None:
    @app.delete("/v1/agent/sessions/{identity}")
    async def delete_session(identity: str, request: Request) -> JSONResponse:
        request_id = "req_" + uuid.uuid4().hex
        runtime = app.state.agent_runtime
        ctx = RequestContext("unauthenticated", "anonymous", request_id, "unknown", "agent")
        try:
            key = authenticate(request, "messages")
            if key is None:
                raise RequestRejected(
                    401, "invalid_api_key", "Authenticate with a gateway API key."
                )
            identity, scope = session_scope(
                key, [identity], agent_id=request.headers.get("x-claude-code-agent-id")
            )
            ctx = RequestContext(key.tenant_id, scope, request_id, key.key_id, key.application)
            if any(
                len(request.headers.getlist(header)) > 1
                for header in ("authorization", "x-api-key", "x-claude-code-agent-id")
            ):
                raise RequestRejected(
                    400, "invalid_headers", "Send one authentication header value."
                )
            deleted = app.state.pipeline.vault.delete_conversation(ctx)
            runtime.audit(ctx, operation="agent-session-deleted")
            return JSONResponse(
                {"id": identity, "deleted": True, "records_removed": deleted},
                headers={"X-Request-Id": request_id},
            )
        except (RequestRejected, SessionScopeError) as exc:
            status = exc.status if isinstance(exc, RequestRejected) else 400
            code = exc.code if isinstance(exc, RequestRejected) else "invalid_session"
            message = exc.detail if isinstance(exc, RequestRejected) else str(exc)
            runtime.audit(ctx, error=code)
            return protocol_error("responses", status, code, message, request_id)
