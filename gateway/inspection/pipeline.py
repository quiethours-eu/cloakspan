"""Inspect, apply policy, transform, route, and safely restore LLM traffic.

Detection fails closed. Spans remain scoped to their source message, and spans
found in a normalized view are mapped back before the original text is edited.
Provider responses are buffered because a sensitive value can cross streaming
chunk boundaries.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from gateway.audit.events import AuditSink, build_event
from gateway.detectors.base import resolve_conflicts
from gateway.domain import Action, InspectionResult, RequestContext, Span
from gateway.normalization import (
    DetectionView,
    ScreeningResult,
    build_detection_view,
    screen_text,
)
from gateway.policy.engine import PolicyEngine
from gateway.restoration.engine import (
    RestorationEngine,
    RestorationOutcome,
    RestorationOutputTooLargeError,
)
from gateway.routing.base import ProviderAdapter, ProviderError
from gateway.transformations.engine import TransformationEngine
from gateway.transformations.tokens import TokenProvenance

# Message roles accepted by the request schema and inspected on the way in.
INSPECTED_INPUT_ROLES = ("system", "user", "assistant", "tool")

# The ONLY response fields restoration may write into (security invariant
# SI-03). Restoring into a tool-call name or an id would let a model rewrite
# control data, not just prose.
RESTORABLE_RESPONSE_FIELDS = ("content",)


class DetectionError(Exception):
    """A detector failed, or content could not be inspected. Fails closed."""


class PolicyBlockedError(Exception):
    def __init__(self, message: str, rule_name: str) -> None:
        super().__init__(message)
        self.rule_name = rule_name


@dataclass(slots=True)
class InspectedMessage:
    """One message with its span list in **original** coordinates.

    ``text`` is the client's bytes, unchanged. Spans index into it directly, so
    transformation and forwarding both operate on what the customer actually
    sent.
    """

    index: int
    text: str
    spans: list[Span] = field(default_factory=list)
    #: Encoding signals for the audit event. Codes and counts, never content.
    signals: dict[str, int] = field(default_factory=dict)


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
    ) -> None:
        self._detectors = detectors
        self._policy = policy
        self._transformer = transformer
        self._restorer = restorer
        self._providers = providers
        self._audit = audit_sink
        self._max_input_chars = max_input_chars
        self._block_mixed_script = block_mixed_script

    @property
    def vault(self):  # noqa: ANN201 - avoids importing the vault module here
        """The surrogate vault, for the expiry sweep and deletion requests."""
        return self._restorer.vault

    @property
    def audit(self) -> AuditSink:
        return self._audit

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

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def _detect(self, view: DetectionView) -> list[Span]:
        """Run every detector over the view, in **view** coordinates.

        Structured detectors -- the ones with a checksum or a rigid shape -- see
        the confusable-folded view, so a Cyrillic ``З`` inside a personal code is
        found. Dictionary and NER detectors see the unfolded view, because
        folding a Cyrillic word into Latin letters could make it collide with a
        customer term that has nothing to do with it. Both views share indices,
        so the same offset map serves both.
        """
        spans: list[Span] = []
        for detector in self._detectors:
            text = view.folded if getattr(detector, "uses_folded_view", False) else view.text
            try:
                spans.extend(detector.detect(text))
            except Exception as exc:  # noqa: BLE001 - broad by design, then re-raised
                # Any detector failure must fail closed. We name the detector
                # and the exception type, but never the text being scanned.
                raise DetectionError(
                    f"detector {getattr(detector, 'name', type(detector).__name__)!r} "
                    f"failed: {type(exc).__name__}"
                ) from exc
        return spans

    def _map_to_original(self, view: DetectionView, view_spans: list[Span]) -> list[Span]:
        """Translate view spans into original coordinates, validating each one.

        A span that cannot be mapped, or whose mapped text does not re-derive
        the matched view text, **fails the request**. Dropping it silently would
        forward an entity we detected; clamping it would replace bytes we did
        not choose.

        The mapped span carries the *original* bytes, so the token is derived
        from what the customer actually wrote and restoration returns it
        exactly. One consequence worth naming: a homoglyph variant and its clean
        equivalent are different byte sequences and therefore get different
        tokens. Both are detected and replaced, which is what matters; token
        consistency across an attacker's obfuscation is not something we owe.
        """
        mapped: list[Span] = []
        for span in view_spans:
            try:
                origin_start, origin_end = view.map_span(span.start, span.end)
            except Exception as exc:  # noqa: BLE001 - re-raised as fail-closed
                raise DetectionError(
                    f"detector {span.detector!r} produced a span that could not be "
                    f"mapped to the source text: {type(exc).__name__}"
                ) from exc

            if not view.verify_round_trip(span.start, span.end):
                raise DetectionError(
                    f"detector {span.detector!r} produced a span whose source text "
                    "does not re-derive the matched text; refusing to replace it"
                )

            mapped.append(
                Span(
                    start=origin_start,
                    end=origin_end,
                    entity_type=span.entity_type,
                    text=view.original[origin_start:origin_end],
                    score=span.score,
                    detector=span.detector,
                )
            )

        # Re-resolve in original coordinates: two spans that did not overlap in
        # the view can overlap once dropped characters are absorbed into their
        # ranges. Replacing overlapping spans would corrupt the text.
        return resolve_conflicts(mapped)

    def inspect_payload(
        self, payload: dict[str, Any]
    ) -> tuple[InspectionResult, list[InspectedMessage]]:
        """Detect across every inspected message, keeping spans message-scoped.

        Each message is screened for deceptive encoding, viewed, detected on the
        view, and then mapped back so its spans index the **original** text.
        Transformation and forwarding both work on the original from here on.
        """
        messages = payload.get("messages") or []
        if not isinstance(messages, list) or not messages:
            raise DetectionError("request contains no messages to inspect")

        total = 0
        inspected: list[InspectedMessage] = []
        aggregate: list[Span] = []

        for index, message in enumerate(messages):
            if not isinstance(message, dict):
                raise DetectionError(f"message {index} is not an object")
            if message.get("role") not in INSPECTED_INPUT_ROLES:
                continue

            content = message.get("content")
            if not isinstance(content, str):
                # Multimodal / structured content is not inspectable in v1.
                # Explicit policy per security invariant SI-02: refuse rather
                # than forward something we did not inspect.
                raise DetectionError(
                    f"message {index} has non-text content, which this version "
                    "cannot inspect; refusing to forward uninspected content"
                )

            total += len(content)
            if total > self._max_input_chars:
                raise DetectionError(
                    f"request exceeds the {self._max_input_chars} character inspection limit"
                )

            # Screening first: an encoding designed to deceive is refused before
            # we spend detection effort on it, and refusing it is a decision
            # about the encoding, not about what was found.
            screening: ScreeningResult = screen_text(
                content, block_mixed_script=self._block_mixed_script
            )
            screening.raise_if_blocking()

            view = build_detection_view(content)
            # Conflict resolution is per message -- see the module docstring --
            # and runs once in view coordinates and again after mapping.
            view_spans = resolve_conflicts(self._detect(view))
            spans = self._map_to_original(view, view_spans)

            inspected.append(
                InspectedMessage(
                    index=index,
                    text=content,
                    spans=spans,
                    signals=dict(screening.signals),
                )
            )
            aggregate.extend(spans)

        # The aggregate is used only for policy matching and audit counts, both
        # of which care about entity *types and counts*, not offsets.
        return InspectionResult(spans=aggregate), inspected

    # ------------------------------------------------------------------
    # Main path
    # ------------------------------------------------------------------

    def _build_outbound(
        self,
        ctx: RequestContext,
        payload: dict[str, Any],
        inspected: list[InspectedMessage],
        should_transform: bool,
        provenance: TokenProvenance,
    ) -> tuple[dict[str, Any], int]:
        """Assemble the payload actually sent upstream. Synchronous, CPU-bound.

        Extracted from ``process`` so it can be handed to a worker thread as one
        unit -- see the threading note there.
        """
        outbound = dict(payload)
        outbound["messages"] = [dict(m) for m in payload["messages"]]
        transformed_count = 0

        for message in inspected:
            if should_transform:
                result = self._transformer.transform(ctx, message.text, message.spans, provenance)
                outbound["messages"][message.index]["content"] = result.text
                transformed_count += result.replaced
            else:
                # ALLOW: forward the client's bytes unchanged (SI-17). This is
                # safe because the *whole* original was inspected -- every index
                # of it is covered by the offset map -- so "unchanged" does not
                # mean "unscanned".
                outbound["messages"][message.index]["content"] = message.text
        return outbound, transformed_count

    async def process(self, ctx: RequestContext, payload: dict[str, Any]) -> PipelineResult:
        """Inspect, route, and restore one request.

        CPU-bound stages run in worker threads so health checks and provider I/O
        stay responsive. Cancellation cannot stop a running thread, so input
        limits bound the remaining work. See ADR-0014.
        """
        started = time.perf_counter()
        model_requested = str(payload.get("model", ""))
        provenance = TokenProvenance()

        inspection, inspected = await asyncio.to_thread(self.inspect_payload, payload)
        decision = self._policy.evaluate(ctx, inspection)
        entity_counts = inspection.entity_counts()
        encoding_signals: dict[str, int] = {}
        for message in inspected:
            for reason, count in message.signals.items():
                encoding_signals[reason] = encoding_signals.get(reason, 0) + count

        if decision.action is Action.BLOCK:
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

        should_transform = decision.action in (Action.TRANSFORM, Action.ROUTE_LOCAL)
        outbound, transformed_count = await asyncio.to_thread(
            self._build_outbound, ctx, payload, inspected, should_transform, provenance
        )

        provider = self._providers.get(decision.destination)
        if provider is None:
            raise ProviderError(
                f"policy selected destination '{decision.destination}', which is not configured",
                500,
            )

        response = await provider.chat_completion(outbound)

        # ---- Buffered output inspection and restoration ----
        try:
            response, restoration = await asyncio.to_thread(
                self._restore_response, ctx, response, provenance
            )
        except RestorationOutputTooLargeError as exc:
            raise ProviderError(str(exc), 502) from exc
        latency_ms = (time.perf_counter() - started) * 1000

        self._audit.write(
            build_event(
                ctx,
                model_requested=model_requested,
                decision=decision,
                provider=provider.name,
                entity_counts=entity_counts,
                encoding_signals=encoding_signals,
                entities_transformed=transformed_count,
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
