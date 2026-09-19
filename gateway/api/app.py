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
import uuid
from collections.abc import AsyncIterator
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from gateway.api.schema import RequestRejected, parse_chat_completion_request
from gateway.auth.keys import ApiKeyStore
from gateway.config import Settings, build_key_store, build_pipeline
from gateway.domain import RequestContext
from gateway.inspection.pipeline import (
    DetectionError,
    PolicyBlockedError,
    SecurityPipeline,
)
from gateway.normalization import SuspiciousEncodingError
from gateway.routing.base import ProviderError

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
    status: int, message: str, error_type: str, code: str | None = None
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
    )


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

    app = FastAPI(
        title="Secure AI Gateway",
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

    @app.post("/v1/chat/completions")
    async def chat_completions(
        request: Request,
        authorization: str | None = Header(default=None),
        x_conversation_id: str | None = Header(default=None),
    ) -> JSONResponse:
        presented = ""
        if authorization and authorization.lower().startswith("bearer "):
            presented = authorization[7:].strip()

        api_key = app.state.key_store.authenticate(presented)
        if api_key is None:
            return error_response(
                401, "Invalid API key.", "invalid_request_error", "invalid_api_key"
            )

        if _declared_body_too_large(request, app.state.settings.max_request_bytes):
            return error_response(
                413,
                "Request body exceeds the maximum allowed size.",
                "invalid_request_error",
                "request_too_large",
            )

        try:
            body = await _read_json_body(request, app.state.settings.max_request_bytes)
        except RequestBodyTooLargeError:
            return error_response(
                413,
                "Request body exceeds the maximum allowed size.",
                "invalid_request_error",
                "request_too_large",
            )
        except Exception:  # noqa: BLE001 - malformed body, nothing useful to surface
            return error_response(400, "Request body is not valid JSON.", "invalid_request_error")

        model = str(body.get("model", "")) if isinstance(body, dict) else ""
        if not api_key.permits_model(model):
            return error_response(
                403,
                f"This API key is not permitted to use model '{model}'.",
                "invalid_request_error",
            )

        # Reject-unknown. Every field is understood and inspected, or refused
        # with a documented code -- there is no pass-through. The payload handed
        # to the pipeline is rebuilt from validated fields, so a key that is not
        # on the model cannot reach the provider (SI-01, SI-02).
        try:
            validated = parse_chat_completion_request(body)
        except RequestRejected as exc:
            error_type = "invalid_request_error" if exc.status < 422 else "inspection_error"
            return error_response(exc.status, exc.detail, error_type, exc.code)

        payload = validated.to_payload()

        ctx = RequestContext(
            tenant_id=api_key.tenant_id,
            conversation_id=x_conversation_id or f"conv_{uuid.uuid4().hex}",
            request_id=f"req_{uuid.uuid4().hex}",
            api_key_id=api_key.key_id,
            application=api_key.application,
        )

        try:
            result = await app.state.pipeline.process(ctx, payload)
        except PolicyBlockedError as exc:
            return error_response(403, str(exc), "policy_violation", "blocked_by_policy")
        except SuspiciousEncodingError as exc:
            # The encoding itself is the finding. The reason code tells the
            # operator which class was refused; neither the message nor the log
            # carries the content (SI-11).
            logger.warning(
                "refused request %s: %s (%d characters)",
                ctx.request_id,
                exc.reason,
                exc.count,
            )
            return error_response(422, str(exc), "inspection_error", exc.reason)
        except DetectionError as exc:
            # Fail closed: we could not inspect, so we do not forward.
            return error_response(422, str(exc), "inspection_error", "inspection_failed")
        except ProviderError as exc:
            return error_response(exc.status_code, str(exc), "api_error", "upstream_error")
        except Exception:
            # Never leak internals. The traceback goes to the log; the client
            # gets a request id to quote.
            logger.exception("unhandled error processing request %s", ctx.request_id)
            return error_response(500, f"Internal error. Request id: {ctx.request_id}", "api_error")

        response = JSONResponse(content=result.response)
        response.headers["X-Request-Id"] = ctx.request_id
        response.headers["X-Conversation-Id"] = ctx.conversation_id
        response.headers["X-Policy-Decision"] = result.decision_action
        response.headers["X-Policy-Rule"] = result.rule_name
        response.headers["X-Policy-Version"] = result.policy_version
        response.headers["X-Entities-Detected"] = str(sum(result.entity_counts.values()))
        response.headers["X-Tokens-Restored"] = str(result.restoration.restored)
        response.headers["X-Tokens-Refused"] = str(result.restoration.total_refused)
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
    async def models(authorization: str | None = Header(default=None)) -> JSONResponse:
        presented = (
            authorization[7:].strip()
            if authorization and authorization.lower().startswith("bearer ")
            else ""
        )
        if app.state.key_store.authenticate(presented) is None:
            return error_response(
                401, "Invalid API key.", "invalid_request_error", "invalid_api_key"
            )
        destinations = sorted(app.state.pipeline._providers)  # noqa: SLF001 - internal read for listing
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
