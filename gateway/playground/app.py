"""Authenticated loopback HTTP surface for transient local previews."""

from __future__ import annotations

import contextlib
import hmac
import json
from collections.abc import AsyncIterator
from dataclasses import replace
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from gateway.api.schema import ACCEPTED_ROLES
from gateway.config import Settings
from gateway.playground.preview import PreviewConfiguration, describe_preview
from gateway.playground.worker import WorkerBusy, WorkerSupervisor, WorkerUnavailable

STATIC_DIR = Path(__file__).resolve().parent / "static"


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message}})


def _authorized(request: Request, access_code: str) -> bool:
    raw = request.headers.get("authorization", "")
    presented = raw[7:] if raw.lower().startswith("bearer ") else ""
    return hmac.compare_digest(presented, access_code)


async def _bounded_json(request: Request, limit: int) -> Any:
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > limit:
                raise OverflowError
        except ValueError:
            pass
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > limit:
            raise OverflowError
        body.extend(chunk)
    return json.loads(body)


def create_playground_app(settings: Settings, *, port: int, access_code: str) -> FastAPI:
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    # Provider credentials are irrelevant to preview and never enter the worker.
    settings = replace(settings, external_api_key="")
    config: PreviewConfiguration = describe_preview(settings)
    supervisor = WorkerSupervisor(settings)
    expected_host = f"127.0.0.1:{port}"
    expected_origin = f"http://{expected_host}"

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await supervisor.start()
        try:
            yield
        finally:
            await supervisor.close()

    app = FastAPI(
        title="Cloakspan local privacy playground",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.supervisor = supervisor
    app.state.configuration = config

    @app.middleware("http")
    async def guard(request: Request, call_next):  # noqa: ANN001, ANN202
        if request.headers.get("host") != expected_host:
            response = _error(403, "invalid_host", "Use the loopback URL printed by cloakspan.")
        elif request.url.path.startswith("/api/") and not _authorized(request, access_code):
            response = _error(401, "unauthorized", "Enter the current session access code.")
        # Same-origin browser GET fetches commonly omit Origin. Status carries
        # no input and still requires the session bearer; POST requires Origin.
        elif (
            request.url.path.startswith("/api/")
            and request.method == "POST"
            and (request.headers.get("origin") != expected_origin)
        ):
            response = _error(403, "invalid_origin", "The request origin is not allowed.")
        else:
            response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'none'; font-src 'none'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        )
        return response

    @app.get("/")
    async def index() -> HTMLResponse:
        return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))

    @app.get("/style.css")
    async def style() -> Response:
        return Response((STATIC_DIR / "style.css").read_bytes(), media_type="text/css")

    @app.get("/app.js")
    async def script() -> Response:
        return Response((STATIC_DIR / "app.js").read_bytes(), media_type="text/javascript")

    @app.get("/api/status")
    async def status() -> dict[str, Any]:
        return {
            "schema_version": 1,
            "config_fingerprint": config.fingerprint,
            "policy_version": config.policy_version,
            "routing_mode": config.routing_mode,
            "coverage": config.coverage,
            "warnings": config.warnings,
            "limits": config.limits,
            "applications": config.applications,
            "roles": ACCEPTED_ROLES,
            "worker": "ready" if supervisor.ready else "recovering",
        }

    @app.post("/api/inspect")
    async def inspect(request: Request) -> Response:
        if not supervisor.ready:
            return _error(503, "worker_unavailable", "The local inspection worker is recovering.")
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > config.limits["request_bytes"]:
                    return _error(
                        413, "request_too_large", "Preview request exceeds the byte limit."
                    )
            except ValueError:
                pass
        if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
            return _error(422, "invalid_request", "Send a JSON request.")
        try:
            body = await _bounded_json(request, config.limits["request_bytes"])
        except OverflowError:
            return _error(413, "request_too_large", "Preview request exceeds the byte limit.")
        except (ValueError, UnicodeError):
            return _error(422, "invalid_json", "Preview request is not valid JSON.")
        if not isinstance(body, dict) or body.keys() != {"text", "role", "application"}:
            return _error(422, "invalid_request", "Expected text, role, and application only.")
        text, role, application = body["text"], body["role"], body["application"]
        if (
            not isinstance(text, str)
            or not isinstance(role, str)
            or not isinstance(application, str)
        ):
            return _error(422, "invalid_request", "Text, role, and application must be strings.")
        if len(text) > config.limits["text_chars"]:
            return _error(413, "text_too_large", "Preview text exceeds the character limit.")
        if role not in ACCEPTED_ROLES or application not in config.applications:
            return _error(422, "invalid_context", "Choose a listed role and application.")
        try:
            result = await supervisor.inspect(
                {"text": text, "role": role, "application": application}
            )
        except WorkerBusy:
            return _error(
                429, "worker_busy", "An inspection is already running. Try again shortly."
            )
        except WorkerUnavailable as exc:
            return _error(503, "worker_unavailable", str(exc))
        if "error" in result:
            code = result["error"]["code"]
            status_code = (
                422 if code == "inspection_failed" else 413 if code == "result_too_large" else 503
            )
            return _error(
                status_code,
                code,
                result["error"]["message"],
            )
        result["config_fingerprint"] = config.fingerprint
        result["coverage"] = config.coverage
        result["warnings"] = config.warnings
        encoded = json.dumps(result, ensure_ascii=False).encode("utf-8")
        if len(encoded) > config.limits["result_bytes"]:
            return _error(413, "result_too_large", "Preview result exceeds the 1 MiB limit.")
        return Response(encoded, media_type="application/json")

    return app
