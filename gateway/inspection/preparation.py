"""Provider-free request inspection and preparation shared by every entrypoint."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from gateway.api.schema import accepts_request_fields
from gateway.detectors.base import resolve_conflicts
from gateway.domain import Action, InspectionResult, PolicyDecision, RequestContext, Span
from gateway.normalization import DetectionView, ScreeningResult, build_detection_view, screen_text
from gateway.policy.engine import PolicyEngine
from gateway.transformations.engine import TransformationEngine
from gateway.transformations.tokens import TokenProvenance

INSPECTED_INPUT_ROLES = ("system", "user", "assistant", "tool")
INSPECTED_MESSAGE_FIELDS = frozenset({"role", "content"})


class DetectionError(Exception):
    """A detector failed or content could not be inspected. Fails closed."""


@dataclass(slots=True)
class InspectedMessage:
    index: int
    text: str
    spans: list[Span] = field(default_factory=list)
    signals: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class PreparedRequest:
    inspected: list[InspectedMessage]
    entity_counts: dict[str, int]
    encoding_signals: dict[str, int]
    base_decision: PolicyDecision
    decision: PolicyDecision
    outbound: dict[str, Any] | None
    provenance: TokenProvenance
    transformed_count: int


class PreparationService:
    def __init__(
        self,
        detectors: list[Any],
        policy: PolicyEngine,
        transformer: TransformationEngine,
        max_input_chars: int = 256_000,
        block_mixed_script: bool = False,
    ) -> None:
        self._detectors = detectors
        self._policy = policy
        self._transformer = transformer
        self._max_input_chars = max_input_chars
        self._block_mixed_script = block_mixed_script

    def _detect(self, view: DetectionView) -> list[Span]:
        spans: list[Span] = []
        for detector in self._detectors:
            text = view.folded if getattr(detector, "uses_folded_view", False) else view.text
            try:
                spans.extend(detector.detect(text))
            except Exception as exc:
                raise DetectionError(
                    f"detector {getattr(detector, 'name', type(detector).__name__)!r} "
                    f"failed: {type(exc).__name__}"
                ) from exc
        return spans

    @staticmethod
    def _map_to_original(view: DetectionView, view_spans: list[Span]) -> list[Span]:
        mapped: list[Span] = []
        for span in view_spans:
            try:
                origin_start, origin_end = view.map_span(span.start, span.end)
            except Exception as exc:
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
        return resolve_conflicts(mapped)

    def inspect_payload(
        self, payload: dict[str, Any]
    ) -> tuple[InspectionResult, list[InspectedMessage]]:
        if not accepts_request_fields(payload):
            raise DetectionError(
                "request has a field this version does not accept; refusing to forward it"
            )
        messages = payload.get("messages") or []
        if not isinstance(messages, list) or not messages:
            raise DetectionError("request contains no messages to inspect")

        total = 0
        inspected: list[InspectedMessage] = []
        aggregate: list[Span] = []
        for index, message in enumerate(messages):
            if not isinstance(message, dict):
                raise DetectionError(f"message {index} is not an object")
            if not message.keys() <= INSPECTED_MESSAGE_FIELDS:
                raise DetectionError(
                    f"message {index} has a field this version does not inspect; "
                    "refusing to forward it"
                )
            if message.get("role") not in INSPECTED_INPUT_ROLES:
                raise DetectionError(
                    f"message {index} has a role this version does not inspect; "
                    "refusing to forward it"
                )
            content = message.get("content")
            if not isinstance(content, str):
                raise DetectionError(
                    f"message {index} has non-text content, which this version "
                    "cannot inspect; refusing to forward uninspected content"
                )
            total += len(content)
            if total > self._max_input_chars:
                raise DetectionError(
                    f"request exceeds the {self._max_input_chars} character inspection limit"
                )
            screening: ScreeningResult = screen_text(
                content, block_mixed_script=self._block_mixed_script
            )
            screening.raise_if_blocking()
            view = build_detection_view(content)
            view_spans = resolve_conflicts(self._detect(view))
            spans = self._map_to_original(view, view_spans)
            inspected.append(
                InspectedMessage(
                    index=index, text=content, spans=spans, signals=dict(screening.signals)
                )
            )
            aggregate.extend(spans)
        return InspectionResult(spans=aggregate), inspected

    def _build_outbound(
        self,
        ctx: RequestContext,
        payload: dict[str, Any],
        inspected: list[InspectedMessage],
        should_transform: bool,
        provenance: TokenProvenance,
    ) -> tuple[dict[str, Any], int]:
        outbound = dict(payload)
        outbound["messages"] = [dict(m) for m in payload["messages"]]
        transformed_count = 0
        for message in inspected:
            if should_transform:
                result = self._transformer.transform(ctx, message.text, message.spans, provenance)
                outbound["messages"][message.index]["content"] = result.text
                transformed_count += result.replaced
            else:
                outbound["messages"][message.index]["content"] = message.text
        return outbound, transformed_count

    def prepare(self, ctx: RequestContext, payload: dict[str, Any]) -> PreparedRequest:
        inspection, inspected = self.inspect_payload(payload)
        base_decision, decision = self._policy.evaluate_with_base(ctx, inspection)
        encoding_signals: dict[str, int] = {}
        for message in inspected:
            for reason, count in message.signals.items():
                encoding_signals[reason] = encoding_signals.get(reason, 0) + count
        provenance = TokenProvenance()
        outbound = None
        transformed_count = 0
        if decision.action is not Action.BLOCK:
            outbound, transformed_count = self._build_outbound(
                ctx,
                payload,
                inspected,
                decision.action in (Action.TRANSFORM, Action.ROUTE_LOCAL),
                provenance,
            )
        return PreparedRequest(
            inspected=inspected,
            entity_counts=inspection.entity_counts(),
            encoding_signals=encoding_signals,
            base_decision=base_decision,
            decision=decision,
            outbound=outbound,
            provenance=provenance,
            transformed_count=transformed_count,
        )
