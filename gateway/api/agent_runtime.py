"""Shared policy, lifecycle, and audit boundary for experimental agent protocols."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gateway.api.schema import RequestRejected
from gateway.audit.events import build_event
from gateway.config import ConfigurationError, Settings
from gateway.domain import Action, PolicyDecision, RequestContext
from gateway.inspection.agent import AgentPreparation, PreparedAgentRequest
from gateway.inspection.pipeline import PolicyBlockedError, SecurityPipeline
from gateway.policy.local_routing import LocalRouting
from gateway.protocols.base import ValidatedRequest
from gateway.restoration.engine import RestorationOutcome
from gateway.routing.base import ProviderError
from gateway.routing.egress import policy_for
from gateway.sessions.scope import scoped_cache_key
from gateway.streaming.protocols import restore_response, restore_stream
from gateway.tools.bound import BoundToolRegistry
from gateway.tools.registry import ToolRegistry, ToolRestorationError


@dataclass(slots=True)
class AgentResult:
    response: dict[str, Any]
    prepared: PreparedAgentRequest
    restoration: RestorationOutcome


class StreamLifecycle:
    """Response-level ownership also covers disconnects before iteration starts."""

    def __init__(
        self, runtime: AgentRuntime, ctx: RequestContext, prepared: PreparedAgentRequest
    ) -> None:
        self.runtime = runtime
        self.ctx = ctx
        self.prepared = prepared
        self.finished = False
        self.started = time.perf_counter()

    def finish(
        self,
        *,
        error: str | None = "cancelled",
        outcome: RestorationOutcome | None = None,
        provider: str = "none",
    ) -> None:
        if self.finished:
            return
        self.finished = True
        try:
            self.runtime.audit(
                self.ctx,
                prepared=self.prepared,
                error=error,
                outcome=outcome,
                provider=provider,
                started=self.started,
            )
        finally:
            self.runtime.release()


def build_agent_providers(settings: Settings) -> dict[str, dict[str, Any]]:
    from gateway.routing.messages import MessagesProvider
    from gateway.routing.responses import MockAgentProvider, ResponsesProvider

    result: dict[str, dict[str, Any]] = {}
    hosts = frozenset(host.lower() for host in settings.egress_allowlist)
    for protocol, enabled, adapter, base, key, model in (
        (
            "responses",
            settings.enable_responses,
            ResponsesProvider,
            settings.external_base_url,
            settings.external_api_key,
            settings.external_model,
        ),
        (
            "messages",
            settings.enable_messages,
            MessagesProvider,
            settings.messages_base_url,
            settings.messages_api_key,
            settings.messages_model,
        ),
    ):
        if not enabled:
            continue
        mock = MockAgentProvider(protocol=protocol)
        providers: dict[str, Any] = {"mock": mock}
        if settings.local_routing is not LocalRouting.ALL:
            if base:
                providers["external"] = adapter(
                    base_url=base,
                    api_key=key or None,
                    model_override=model or None,
                    timeout_seconds=settings.agent_stream_idle_seconds,
                    name="external",
                    trust_env=settings.trust_env_proxy,
                    egress=policy_for(
                        "external",
                        allowed_hosts=hosts,
                        allow_private_override=settings.egress_allow_private or None,
                    ),
                )
            else:
                providers["external"] = mock
        if settings.local_base_url:
            providers["local"] = adapter(
                base_url=settings.local_base_url,
                model_override=settings.local_model or None,
                timeout_seconds=settings.agent_stream_idle_seconds,
                name="local",
                trust_env=settings.trust_env_proxy and settings.local_routing is LocalRouting.OFF,
                trust_env_certs=settings.trust_env_proxy,
                egress=policy_for(
                    "local",
                    allowed_hosts=hosts,
                    require_private_network=settings.local_routing is not LocalRouting.OFF,
                ),
            )
        else:
            providers["local"] = mock
        result[protocol] = providers
    return result


class AgentRuntime:
    def __init__(
        self,
        pipeline: SecurityPipeline,
        settings: Settings,
        providers: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        root = Path(settings.agent_workspace_root)
        if not settings.agent_workspace_root or not root.is_absolute() or not root.is_dir():
            raise ConfigurationError(
                "Set SAG_AGENT_WORKSPACE_ROOT to an existing absolute workspace directory."
            )
        for value in (
            settings.agent_max_concurrent,
            settings.agent_detector_timeout_seconds,
            settings.agent_stream_idle_seconds,
            settings.agent_stream_total_seconds,
            settings.agent_max_event_bytes,
            settings.agent_max_output_bytes,
        ):
            if value <= 0:
                raise ConfigurationError("Agent resource limits must be positive.")
        self.pipeline = pipeline
        self.settings = settings
        self.providers = providers if providers is not None else build_agent_providers(settings)
        self.tools = ToolRegistry(root)
        self.preparation = AgentPreparation(
            pipeline.preparation,
            max_input_chars=settings.max_input_chars,
            detector_timeout=settings.agent_detector_timeout_seconds,
            mixed_script=settings.block_mixed_script,
        )
        self.active = 0
        required = pipeline.preparation._policy.required_destinations
        for protocol, enabled in (
            ("responses", settings.enable_responses),
            ("messages", settings.enable_messages),
        ):
            if not enabled:
                continue
            available = self.providers.get(protocol, {})
            if required - available.keys():
                raise ConfigurationError(
                    "An enabled agent protocol lacks a required provider destination."
                )
            if providers is None:
                from gateway.config import _is_production

                if _is_production() and any(
                    destination != "mock" and available[destination] is available.get("mock")
                    for destination in required
                ):
                    raise ConfigurationError(
                        "Configure native upstreams for every selected agent destination."
                    )

    def admit(self) -> bool:
        if self.active >= self.settings.agent_max_concurrent:
            return False
        self.active += 1
        return True

    def release(self) -> None:
        self.active -= 1

    async def aclose(self) -> None:
        closed: set[int] = set()
        for providers in self.providers.values():
            for provider in providers.values():
                if id(provider) not in closed:
                    closed.add(id(provider))
                    close = getattr(provider, "aclose", None)
                    if close is not None:
                        await close()

    def audit(
        self,
        ctx: RequestContext,
        *,
        prepared: PreparedAgentRequest | None = None,
        error: str | None = None,
        outcome: RestorationOutcome | None = None,
        provider: str = "none",
        started: float | None = None,
        operation: str = "agent-validation",
    ) -> None:
        decision = (
            prepared.decision
            if prepared
            else PolicyDecision(
                Action.BLOCK if error else Action.ALLOW, "none", operation, "agent-contract-v1"
            )
        )
        self.pipeline.audit.write(
            build_event(
                ctx,
                model_requested="client-model",
                decision=decision,
                provider=provider,
                entity_counts=prepared.entity_counts if prepared else {},
                encoding_signals=prepared.encoding_signals if prepared else {},
                entities_transformed=prepared.transformed_count if prepared else 0,
                restoration_performed=bool(outcome and outcome.restored),
                tokens_restored=outcome.restored if outcome else 0,
                tokens_refused=outcome.total_refused if outcome else 0,
                tokens_refused_by_reason=outcome.reasons() if outcome else {},
                latency_ms=(time.perf_counter() - started) * 1000 if started else 0,
                error=error,
            )
        )

    async def prepare(self, ctx: RequestContext, request: ValidatedRequest) -> PreparedAgentRequest:
        prepared = await self.preparation.prepare(ctx, request)
        if prepared.decision.action is Action.BLOCK:
            error = PolicyBlockedError(
                "Request blocked by privacy policy.", prepared.decision.rule_name
            )
            error.prepared = prepared
            raise error
        if prepared.outbound is None:
            raise ProviderError("No inspected outbound request is available.", 500)
        # Public clients send local attribution in these explicit fields. The
        # parser and inspection have validated them; authenticated gateway
        # identity remains authoritative and raw device/turn IDs stay local.
        prepared.outbound.pop("client_metadata", None)
        prepared.outbound.pop("metadata", None)
        if "prompt_cache_key" in prepared.outbound:
            prepared.outbound["prompt_cache_key"] = scoped_cache_key(
                ctx,
                request.protocol,
                request.model,
                prepared.decision.destination,
                prepared.decision.policy_version,
                prepared.outbound["prompt_cache_key"],
            )
        try:
            prepared.tool_registry = BoundToolRegistry(
                self.tools, prepared.outbound, request.protocol
            )
        except ToolRestorationError as exc:
            error = RequestRejected(
                422, exc.code, "Use declared registered tools with supported argument schemas."
            )
            error.prepared = prepared
            raise error from exc
        return prepared

    def provider(self, prepared: PreparedAgentRequest) -> Any:
        providers = self.providers.get(prepared.request.protocol, {})
        provider = providers.get(prepared.decision.destination)
        if provider is None:
            raise ProviderError("Selected provider does not implement this protocol.", 502)
        mode = self.settings.local_routing
        if (
            mode is LocalRouting.ALL or mode is LocalRouting.DETECTED and prepared.entity_counts
        ) and (provider is not providers.get("local")):
            raise ProviderError("Local routing requires a native local protocol provider.", 502)
        return provider

    async def complete(
        self, ctx: RequestContext, prepared: PreparedAgentRequest, *, count_tokens: bool = False
    ) -> AgentResult:
        provider = None
        started = time.perf_counter()
        outcome = RestorationOutcome(text="")
        try:
            provider = self.provider(prepared)
            native_options = {"betas": prepared.native_betas} if prepared.native_betas else {}
            async with asyncio.timeout(self.settings.agent_stream_total_seconds):
                if count_tokens:
                    # Native token counting must receive precisely the sanitized content.
                    payload = dict(prepared.outbound or {})
                    for field in ("stream", "max_tokens", "temperature", "top_p", "top_k"):
                        payload.pop(field, None)
                    response = await provider.count_tokens(payload, **native_options)
                    if (
                        not isinstance(response, dict)
                        or set(response) != {"input_tokens"}
                        or type(response["input_tokens"]) is not int
                        or response["input_tokens"] < 0
                    ):
                        raise ProviderError("Provider returned an invalid token count.", 502)
                else:
                    response = await provider.complete(prepared.outbound, **native_options)
                    response, outcome = restore_response(
                        prepared.request.protocol,
                        response,
                        ctx,
                        prepared.provenance,
                        self.pipeline.restorer,
                        prepared.tool_registry,
                        expected_request=prepared.outbound,
                        max_output_bytes=self.settings.agent_max_output_bytes,
                    )
                    if len(json.dumps(response).encode()) > self.settings.agent_max_output_bytes:
                        raise ProviderError("Restored response exceeds its output limit.", 502)
        except BaseException as exc:
            self.audit(
                ctx,
                prepared=prepared,
                error=(
                    "cancelled" if isinstance(exc, asyncio.CancelledError) else "response_failed"
                ),
                outcome=getattr(exc, "outcome", outcome),
                provider=provider.name if provider else "none",
                started=started,
            )
            raise
        self.audit(ctx, prepared=prepared, outcome=outcome, provider=provider.name, started=started)
        return AgentResult(response, prepared, outcome)

    async def _bounded_chunks(self, chunks: Any) -> AsyncIterator[bytes]:
        iterator = chunks.__aiter__()
        try:
            while True:
                try:
                    async with asyncio.timeout(self.settings.agent_stream_idle_seconds):
                        chunk = await anext(iterator)
                except StopAsyncIteration:
                    break
                yield chunk
        finally:
            close = getattr(iterator, "aclose", None)
            if close is not None:
                await close()

    async def stream(
        self,
        ctx: RequestContext,
        prepared: PreparedAgentRequest,
        *,
        lifecycle: StreamLifecycle | None = None,
    ) -> AsyncIterator[bytes]:
        lifecycle = lifecycle or StreamLifecycle(self, ctx, prepared)
        outcome = RestorationOutcome(text="")
        provider = None
        error = None
        try:
            provider = self.provider(prepared)
            native_options = {"betas": prepared.native_betas} if prepared.native_betas else {}
            async with asyncio.timeout(self.settings.agent_stream_total_seconds):
                chunks = self._bounded_chunks(provider.stream(prepared.outbound, **native_options))
                try:
                    async for event in restore_stream(
                        prepared.request.protocol,
                        chunks,
                        ctx,
                        prepared.provenance,
                        self.pipeline.restorer,
                        prepared.tool_registry,
                        max_event_bytes=self.settings.agent_max_event_bytes,
                        max_output_bytes=self.settings.agent_max_output_bytes,
                        outcome=outcome,
                        expected_request=prepared.outbound,
                    ):
                        yield event
                finally:
                    await chunks.aclose()
        except (asyncio.CancelledError, GeneratorExit):
            error = "cancelled"
            raise
        except Exception as exc:
            error = "stream_failed"
            refused = getattr(exc, "outcome", None)
            if refused is not None and refused is not outcome:
                outcome.merge(refused)
            if prepared.request.protocol == "messages":
                body = {
                    "type": "error",
                    "error": {
                        "type": "api_error",
                        "message": (
                            "Stream failed validation; replay original history before retrying."
                        ),
                    },
                }
            else:
                body = {
                    "type": "error",
                    "code": "stream_failed",
                    "message": (
                        "Stream failed validation; replay original history before retrying."
                    ),
                }
            body["request_id"] = ctx.request_id
            yield ("event: error\ndata: " + json.dumps(body) + "\n\n").encode()
        finally:
            lifecycle.finish(
                error=error, outcome=outcome, provider=provider.name if provider else "none"
            )
