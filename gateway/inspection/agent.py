"""Typed protocol inspection, with killable detector work before provider egress."""

from __future__ import annotations

import asyncio
import copy
import math
import multiprocessing
import time
from dataclasses import dataclass
from typing import Any

from gateway.domain import Action, InspectionResult, PolicyDecision, RequestContext
from gateway.inspection.preparation import DetectionError, PreparationService, TextInspectionService
from gateway.protocols.base import ValidatedRequest, replace_location
from gateway.transformations.tokens import TokenProvenance, canonicalize


@dataclass(slots=True)
class PreparedAgentRequest:
    request: ValidatedRequest
    outbound: dict[str, Any] | None
    decision: PolicyDecision
    entity_counts: dict[str, int]
    encoding_signals: dict[str, int]
    provenance: TokenProvenance
    transformed_count: int
    inspection_ms: float
    tool_registry: Any = None
    native_betas: tuple[str, ...] = ()


class AgentInputLimitExceeded(DetectionError):
    """A known gateway input bound, distinct from detector or privacy failures."""


def _inspect_worker(
    connection: Any, detectors: list[Any], texts: list[str], mixed_script: bool, deadline: float
) -> None:
    try:
        # CPU and address-space limits complement the parent wall-clock deadline.
        # No vault or token key is passed to the worker. No transcripts are saved.
        try:
            import resource

            resource.setrlimit(resource.RLIMIT_CPU, (max(1, math.ceil(deadline)),) * 2)
            resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3,) * 2)
        except (ImportError, ValueError, OSError):
            pass  # Wall-clock termination remains enforced on every platform.
        inspector = TextInspectionService(detectors, mixed_script)
        connection.send((True, [inspector.inspect_text(text) for text in texts]))
    except Exception:
        connection.send((False, None))
    finally:
        connection.close()


async def inspect_isolated(
    detectors: list[Any], texts: list[str], *, mixed_script: bool, deadline_seconds: float
) -> list[Any]:
    """Termination stops a stuck detector; an async timeout on a thread cannot."""
    methods = multiprocessing.get_all_start_methods()
    # Fork uses already-verified operator models on POSIX. Else spawn requires
    # serializable detectors and fails closed if one cannot be isolated.
    context = multiprocessing.get_context("fork" if "fork" in methods else "spawn")
    reader, writer = context.Pipe(duplex=False)
    process = context.Process(
        target=_inspect_worker,
        args=(writer, detectors, texts, mixed_script, deadline_seconds),
        daemon=True,
    )
    started = time.monotonic()
    try:
        process.start()
        writer.close()
        while not reader.poll():
            if time.monotonic() - started >= deadline_seconds:
                raise DetectionError("Detector deadline exceeded; reduce input or check detectors.")
            if not process.is_alive():
                raise DetectionError("Isolated detector failed; check detector configuration.")
            await asyncio.sleep(0.005)
        remaining = deadline_seconds - (time.monotonic() - started)
        if remaining <= 0:
            raise DetectionError("Detector deadline exceeded; reduce input or check detectors.")
        try:
            async with asyncio.timeout(remaining):
                success, result = await asyncio.to_thread(reader.recv)
        except TimeoutError as exc:
            raise DetectionError(
                "Detector deadline exceeded; reduce input or check detectors."
            ) from exc
        if not success:
            raise DetectionError("Content inspection failed; check encoding and detectors.")
        return result
    except (EOFError, OSError, TypeError, ValueError) as exc:
        raise DetectionError(
            "Isolated detector unavailable; check detector configuration."
        ) from exc
    finally:
        writer.close()
        reader.close()
        if process.pid is not None:
            if process.is_alive():
                process.terminate()
            await asyncio.to_thread(process.join, 0.5)
            if process.is_alive():
                process.kill()
                await asyncio.to_thread(process.join, 0.5)
            process.close()


class AgentPreparation:
    def __init__(
        self,
        preparation: PreparationService,
        *,
        max_input_chars: int,
        detector_timeout: float,
        mixed_script: bool = False,
    ) -> None:
        self.preparation = preparation
        self.max_input_chars = max_input_chars
        self.detector_timeout = detector_timeout
        self.mixed_script = mixed_script

    async def prepare(self, ctx: RequestContext, request: ValidatedRequest) -> PreparedAgentRequest:
        total = sum(len(location.text) for location in request.locations)
        if total > self.max_input_chars:
            raise AgentInputLimitExceeded(
                "Inspection character limit exceeded; compact inspectable history."
            )
        started = time.perf_counter()
        inspected = await inspect_isolated(
            self.preparation.detectors,
            [location.text for location in request.locations],
            mixed_script=self.mixed_script,
            deadline_seconds=self.detector_timeout,
        )
        aggregate = InspectionResult(spans=[span for spans, _ in inspected for span in spans])
        if request.tools:
            originals: dict[tuple[str, str], str] = {}
            for span in aggregate.spans:
                identity = (span.entity_type, canonicalize(span.text))
                previous = originals.setdefault(identity, span.text)
                if previous != span.text:
                    raise DetectionError(
                        "Canonical value variants are ambiguous for exact edits; "
                        "use consistent private-value spelling in tool history."
                    )
        _, decision = self.preparation._policy.evaluate_with_base(ctx, aggregate)
        provenance = TokenProvenance()
        counts = aggregate.entity_counts()
        signals: dict[str, int] = {}
        for _, findings in inspected:
            for name, count in findings.items():
                signals[name] = signals.get(name, 0) + count
        for location, (spans, _) in zip(request.locations, inspected, strict=True):
            if spans and location.structural:
                raise DetectionError(
                    "Sensitive structural content cannot be transformed safely; "
                    "change the schema or identifier."
                )
        outbound = None
        transformed = 0
        if decision.action is not Action.BLOCK:
            outbound = copy.deepcopy(request.payload)
            for location, (spans, _) in zip(request.locations, inspected, strict=True):
                if not location.structural and decision.action in (
                    Action.TRANSFORM,
                    Action.ROUTE_LOCAL,
                ):
                    result = self.preparation._transformer.transform(
                        ctx, location.text, spans, provenance
                    )
                    replace_location(outbound, location, result.text)
                    transformed += result.replaced
        return PreparedAgentRequest(
            request,
            outbound,
            decision,
            counts,
            signals,
            provenance,
            transformed,
            (time.perf_counter() - started) * 1000,
        )
