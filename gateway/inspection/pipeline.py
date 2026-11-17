"""Inspect, apply policy, transform, route, and safely restore LLM traffic.

Detection fails closed. Spans remain scoped to their source message, and spans
found in a normalized view are mapped back before the original text is edited.
Provider responses are buffered because a sensitive value can cross streaming
chunk boundaries.
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import Executor
from dataclasses import dataclass
from typing import Any

from gateway.audit.events import AuditSink, build_event
from gateway.domain import Action, InspectionResult, PolicyDecision, RequestContext
from gateway.inspection.preparation import (
    INSPECTED_INPUT_ROLES,  # noqa: F401 - public compatibility import
    INSPECTED_MESSAGE_FIELDS,  # noqa: F401 - public compatibility import
    DetectionError,  # noqa: F401 - public compatibility import
    DetectorTimeoutError,
    InspectedMessage,
    PreparationService,
    PreparedRequest,
)
from gateway.policy.engine import PolicyEngine
from gateway.policy.local_routing import LOCAL_DESTINATION, LocalRouting, LocalRoutingViolation
from gateway.restoration.engine import (
    RestorationEngine,
    RestorationOutcome,
    RestorationOutputTooLargeError,
)
from gateway.routing.base import ProviderAdapter, ProviderError
from gateway.routing.egress import EgressBlockedError
from gateway.transformations.engine import TransformationEngine
from gateway.transformations.tokens import TokenProvenance

# The ONLY response fields restoration may write into (security invariant
# SI-03). Restoring into a tool-call name or an id would let a model rewrite
# control data, not just prose.
RESTORABLE_RESPONSE_FIELDS = ("content",)

logger = logging.getLogger("gateway.pipeline")

#: Rule name on an audit event for a request that ended before policy decided
#: anything. Not a policy rule: nothing was forwarded.
REFUSED_BEFORE_DECISION = "request-refused"


class PolicyBlockedError(Exception):
    def __init__(self, message: str, rule_name: str) -> None:
        super().__init__(message)
        self.rule_name = rule_name


@dataclass(frozen=True, slots=True)
class DetectionBudget:
    """Bounds on the synchronous inspection stage of one request.

    Detection runs in a worker thread, and a thread cannot be interrupted. On
    timeout the request fails closed -- nothing is forwarded -- but the thread
    keeps running until the detector returns. ``on_overrun`` receives the
    future of that still-running work, so the caller can keep counting it
    against capacity rather than letting a pathological input start work
    without bound.

    The deadline is checked by the event loop. A detector that holds the GIL
    for its entire run -- one catastrophic regular-expression match is the
    textbook case -- also stops the loop, so the deadline cannot fire until
    that call returns. See docs/limitations.md.
    """

    timeout_seconds: float | None = None
    executor: Executor | None = None
    on_overrun: Callable[[asyncio.Future[Any]], None] | None = None


@dataclass(slots=True)
class _AuditState:
    """What the audit event for this request can truthfully say so far."""

    decision: PolicyDecision | None = None
    provider: str = "none"
    entity_counts: dict[str, int] | None = None
    encoding_signals: dict[str, int] | None = None
    transformed: int = 0
    written: bool = False


def _require_serialisable(response: dict[str, Any]) -> None:
    """Serialise exactly as the HTTP response will, or raise ProviderError."""
    try:
        json.dumps(response, allow_nan=False, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        # UnicodeEncodeError is a ValueError. The message names the class only.
        raise ProviderError(
            f"upstream response cannot be serialised ({type(exc).__name__})",
            502,
            "provider_bad_response",
        ) from None


def _consume_result(future: asyncio.Future[Any]) -> None:
    """Retrieve an abandoned future's outcome so asyncio does not log it."""
    if not future.cancelled():
        future.exception()


@dataclass(slots=True)
class PipelineResult:
    response: dict[str, Any]
    entity_counts: dict[str, int]
    decision_action: str
    rule_name: str
    policy_version: str
    provider: str
    restoration: RestorationOutcome
    latency_ms: float


class SecurityPipeline:
    def __init__(
        self,
        detectors: list[Any],
        policy: PolicyEngine,
        transformer: TransformationEngine,
        restorer: RestorationEngine,
        providers: dict[str, ProviderAdapter],
        audit_sink: AuditSink,
        max_input_chars: int = 256_000,
        block_mixed_script: bool = False,
        local_routing: LocalRouting = LocalRouting.OFF,
    ) -> None:
        self._detectors = detectors
        self._policy = policy
        self._transformer = transformer
        self._restorer = restorer
        self._providers = providers
        self._audit = audit_sink
        self._max_input_chars = max_input_chars
        self._block_mixed_script = block_mixed_script
        self._preparation = PreparationService(
            detectors, policy, transformer, max_input_chars, block_mixed_script
        )
        #: Checked again here, by provider identity, after the policy engine
        #: has applied it. See the tripwire in ``process``.
        self._local_routing = local_routing

    @property
    def vault(self):  # noqa: ANN201 - avoids importing the vault module here
        """The surrogate vault, for the expiry sweep and deletion requests."""
        return self._restorer.vault

    @property
    def audit(self) -> AuditSink:
        return self._audit

    @property
    def preparation(self) -> PreparationService:
        return self._preparation

    @property
    def restorer(self) -> RestorationEngine:
        return self._restorer

    async def aclose_providers(self) -> None:
        """Release provider connection pools on shutdown.

        Providers hold long-lived HTTP clients so that a request does not pay a
        handshake it does not need. Those sockets have to be handed back inside
        the graceful-shutdown window rather than left to garbage collection at
        interpreter exit.

        Adapters that hold nothing -- ``MockProvider`` -- have no ``aclose`` and
        are skipped, so this does not force every adapter to grow a lifecycle it
        does not need.
        """
        for provider in self._providers.values():
            close = getattr(provider, "aclose", None)
            if close is not None:
                await close()

    def inspect_payload(
        self, payload: dict[str, Any]
    ) -> tuple[InspectionResult, list[InspectedMessage]]:
        """Compatibility entrypoint for direct callers of the gateway pipeline."""
        return self._preparation.inspect_payload(payload)

    @property
    def policy_version(self) -> str:
        return self._policy.version

    def refusal_decision(self) -> PolicyDecision:
        """The decision recorded for a request that ended before policy ran."""
        return PolicyDecision(Action.BLOCK, "none", REFUSED_BEFORE_DECISION, self._policy.version)

    async def _prepare(
        self, ctx: RequestContext, payload: dict[str, Any], budget: DetectionBudget | None
    ) -> PreparedRequest:
        """Run preparation off the event loop, within the detection budget."""
        budget = budget or DetectionBudget()
        loop = asyncio.get_running_loop()
        abandoned = threading.Event()
        work = loop.run_in_executor(
            budget.executor,
            functools.partial(self._preparation.prepare, ctx, payload, abandoned=abandoned),
        )
        try:
            # Shielded so that a timeout or a cancellation abandons the *wait*,
            # not the future: the future then completes when the thread really
            # finishes, which is what the overrun accounting needs to observe.
            return await asyncio.wait_for(asyncio.shield(work), budget.timeout_seconds)
        except TimeoutError as exc:
            raise DetectorTimeoutError(
                "content inspection exceeded its deadline; nothing was forwarded"
            ) from exc
        finally:
            if not work.done():
                # Before anything else: the worker checks this immediately
                # before each vault write, so a refused request stores nothing.
                abandoned.set()
                work.add_done_callback(_consume_result)
                if budget.on_overrun is not None:
                    budget.on_overrun(work)

    async def process(
        self,
        ctx: RequestContext,
        payload: dict[str, Any],
        *,
        detection: DetectionBudget | None = None,
    ) -> PipelineResult:
        """Inspect, route, and restore one request.

        CPU-bound stages run in worker threads so health checks and provider I/O
        stay responsive. Cancellation cannot stop a running thread, so input
        limits and ``detection`` bound the remaining work. See ADR-0014.

        **Writes exactly one audit event on every exit** -- success, policy
        block, every error, and cancellation -- before returning or raising. A
        caller must therefore not write a second one for the same request.
        """
        started = time.perf_counter()
        model_requested = str(payload.get("model", ""))
        state = _AuditState()
        try:
            return await self._process(ctx, payload, model_requested, started, state, detection)
        except BaseException as exc:
            if not state.written:
                self._write_error_event(ctx, model_requested, started, state, exc)
            raise

    def _write_error_event(
        self,
        ctx: RequestContext,
        model_requested: str,
        started: float,
        state: _AuditState,
        exc: BaseException,
    ) -> None:
        from gateway.audit.reasons import reason_for_exception

        state.written = True
        try:
            self._audit.write(
                build_event(
                    ctx,
                    model_requested=model_requested,
                    decision=state.decision or self.refusal_decision(),
                    # The egress check runs inside the provider adapter, before
                    # anything is sent: a refused destination received nothing.
                    provider="none" if isinstance(exc, EgressBlockedError) else state.provider,
                    entity_counts=state.entity_counts or {},
                    encoding_signals=state.encoding_signals,
                    entities_transformed=state.transformed,
                    latency_ms=(time.perf_counter() - started) * 1000,
                    error=reason_for_exception(exc).value,
                )
            )
        except Exception:
            # The request is already failing closed; a broken sink must not
            # replace that error with its own. Logged without the event.
            logger.exception("audit write failed for request %s", ctx.request_id)

    async def _process(
        self,
        ctx: RequestContext,
        payload: dict[str, Any],
        model_requested: str,
        started: float,
        state: _AuditState,
        detection: DetectionBudget | None,
    ) -> PipelineResult:
        prepared = await self._prepare(ctx, payload, detection)
        decision = prepared.decision
        entity_counts = prepared.entity_counts
        encoding_signals = prepared.encoding_signals
        state.decision = decision
        state.entity_counts = entity_counts
        state.encoding_signals = encoding_signals
        state.transformed = prepared.transformed_count

        if decision.action is Action.BLOCK:
            state.written = True
            self._audit.write(
                build_event(
                    ctx,
                    model_requested=model_requested,
                    decision=decision,
                    provider="none",
                    entity_counts=entity_counts,
                    encoding_signals=encoding_signals,
                    latency_ms=(time.perf_counter() - started) * 1000,
                )
            )
            raise PolicyBlockedError(
                f"request blocked by policy rule '{decision.rule_name}'",
                decision.rule_name,
            )

        outbound = prepared.outbound
        if outbound is None:
            raise ProviderError("preparation returned no outbound payload", 500, "internal_error")

        provider = self._providers.get(decision.destination)
        if provider is None:
            raise ProviderError(
                f"policy selected destination '{decision.destination}', which is not configured",
                500,
                "destination_unavailable",
            )

        # Tripwire for SAG_LOCAL_ROUTING. The engine already moved this request
        # to `local`; this checks the object about to receive it. It decides
        # whether the mode requires `local` on its own, from the entity counts
        # the audit event records, rather than asking the engine's
        # `requires_local`. A regression in the rewrite or in that predicate
        # therefore fails closed here instead of reaching another provider.
        mode = self._local_routing
        must_be_local = mode is LocalRouting.ALL or (
            mode is LocalRouting.DETECTED and bool(entity_counts)
        )
        if must_be_local and provider is not self._providers.get(LOCAL_DESTINATION):
            raise LocalRoutingViolation(
                f"local routing {mode} requires the local destination; "
                f"rule {decision.rule_name!r} selected {decision.destination!r}"
            )

        # From here the request is handed to this destination's client, so an
        # error event names it rather than "none" -- except an egress refusal,
        # which happens inside the client before anything is sent.
        state.provider = provider.name
        response = await provider.chat_completion(outbound)

        # ---- Buffered output inspection and restoration ----
        try:
            response, restoration = await asyncio.to_thread(
                self._restore_response, ctx, response, prepared.provenance
            )
        except RestorationOutputTooLargeError as exc:
            raise ProviderError(str(exc), 502, "restoration_refused") from exc
        # The response must be deliverable before it is audited as a success.
        # Any adapter can hand back a lone surrogate or a non-finite number,
        # which the HTTP layer could then not serialise: refuse it here, so the
        # event says what happened instead of a success followed by a 500.
        await asyncio.to_thread(_require_serialisable, response)
        latency_ms = (time.perf_counter() - started) * 1000

        state.written = True
        self._audit.write(
            build_event(
                ctx,
                model_requested=model_requested,
                decision=decision,
                provider=provider.name,
                entity_counts=entity_counts,
                encoding_signals=encoding_signals,
                entities_transformed=prepared.transformed_count,
                restoration_performed=restoration.restored > 0,
                tokens_restored=restoration.restored,
                tokens_refused=restoration.total_refused,
                tokens_refused_by_reason=restoration.reasons(),
                latency_ms=latency_ms,
            )
        )

        return PipelineResult(
            response=response,
            entity_counts=entity_counts,
            decision_action=decision.action.value,
            rule_name=decision.rule_name,
            policy_version=decision.policy_version,
            provider=provider.name,
            restoration=restoration,
            latency_ms=latency_ms,
        )

    def _restore_response(
        self,
        ctx: RequestContext,
        response: dict[str, Any],
        provenance: TokenProvenance,
    ) -> tuple[dict[str, Any], RestorationOutcome]:
        """Restore approved response fields only, and report what was refused."""
        result = dict(response)
        choices = [dict(c) for c in result.get("choices", [])]
        aggregate = RestorationOutcome(text="")
        remaining_bytes = self._restorer.max_output_bytes

        for choice in choices:
            message = dict(choice.get("message") or {})
            for field_name in RESTORABLE_RESPONSE_FIELDS:
                value = message.get(field_name)
                if not isinstance(value, str):
                    continue
                outcome = self._restorer.restore(
                    ctx,
                    value,
                    provenance,
                    max_output_bytes=remaining_bytes,
                )
                message[field_name] = outcome.text
                aggregate.merge(outcome)
                remaining_bytes -= len(outcome.text.encode("utf-8"))
            choice["message"] = message

        result["choices"] = choices
        return result, aggregate
