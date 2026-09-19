"""Detection-path benchmark.

    python scripts/benchmark.py --output dist/benchmark.json

Measures the part of the request path we control: screening, view construction,
detection, conflict resolution, span mapping, and transformation. The provider
call is excluded because it is someone else's latency and dominates the total —
including it would produce a number that says more about the upstream than about
us.

## What the number is and is not

It is a **regression signal on the machine that produced it**. It is not a
published figure, and this script records the hardware precisely so nobody
mistakes one for the other: a latency figure without stated hardware is a
comparison nobody can reproduce.

Release evidence requires a benchmark on clearly identified reference hardware.
That means publishing the machine details with the output, not running it
wherever CI happens to schedule and quoting the result.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gateway.config import Settings, build_detectors  # noqa: E402
from gateway.detectors.base import resolve_conflicts  # noqa: E402
from gateway.domain import RequestContext, Span  # noqa: E402
from gateway.normalization import build_detection_view, screen_text  # noqa: E402
from gateway.transformations.engine import TransformationEngine  # noqa: E402
from gateway.transformations.tokens import TokenMinter, TokenProvenance  # noqa: E402
from gateway.vault.store import KeyRing, SurrogateVault  # noqa: E402

#: Budget from docs/entity-taxonomy.md: P95 ≤ 150 ms for a 4 KB text request.
LATENCY_BUDGET_MS = 150.0

CTX = RequestContext("bench-tenant", "bench-conv", "bench-req", "bench-key")

#: Sized to the budget's reference request. Realistic in shape -- entities mixed
#: into prose rather than a wall of identifiers, because a detector's cost
#: depends on how often it matches.
_UNIT = (
    "Klienta Ilze Bērziņa personas kods ir 120385-12342, e-pasts "
    "a11@example.lv, konts LV80BANK0000435195001. Lūdzu sagatavo atbildi "
    "par piegādi uz Rīgu nākamnedēļ. Tālr. 29123456. "
)


def _sample(size_bytes: int) -> str:
    text = _UNIT
    while len(text.encode("utf-8")) < size_bytes:
        text += _UNIT
    return text[: size_bytes // 2]


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * fraction) - 1))
    return ordered[index]


def measure(label: str, function, iterations: int) -> dict[str, Any]:
    # A short warm-up: the first call pays for regex compilation and imports,
    # and reporting that as steady-state latency would overstate it.
    for _ in range(max(3, iterations // 20)):
        function()

    timings = []
    for _ in range(iterations):
        started = time.perf_counter()
        function()
        timings.append((time.perf_counter() - started) * 1000)

    return {
        "stage": label,
        "iterations": iterations,
        "p50_ms": round(statistics.median(timings), 3),
        "p95_ms": round(_percentile(timings, 0.95), 3),
        "p99_ms": round(_percentile(timings, 0.99), 3),
        "max_ms": round(max(timings), 3),
        "mean_ms": round(statistics.fmean(timings), 3),
    }


def build_stages(size_bytes: int):
    detectors = build_detectors(Settings())
    vault = SurrogateVault(key_ring=KeyRing(keys={1: b"\x01" * 32}, active_version=1))
    transformer = TransformationEngine(TokenMinter(b"\x02" * 32), vault)
    text = _sample(size_bytes)

    def screening() -> None:
        screen_text(text)

    def view() -> None:
        build_detection_view(text)

    prepared_view = build_detection_view(text)

    def detection() -> None:
        spans: list[Span] = []
        for detector in detectors:
            source = (
                prepared_view.folded
                if getattr(detector, "uses_folded_view", False)
                else prepared_view.text
            )
            spans.extend(detector.detect(source))
        resolve_conflicts(spans)

    def full_inspection() -> list[Span]:
        screen_text(text)
        current = build_detection_view(text)
        spans: list[Span] = []
        for detector in detectors:
            source = (
                current.folded if getattr(detector, "uses_folded_view", False) else current.text
            )
            spans.extend(detector.detect(source))
        mapped: list[Span] = []
        for span in resolve_conflicts(spans):
            start, end = current.map_span(span.start, span.end)
            if not current.verify_round_trip(span.start, span.end):
                continue
            mapped.append(
                Span(start, end, span.entity_type, text[start:end], span.score, span.detector)
            )
        return resolve_conflicts(mapped)

    prepared_spans = full_inspection()

    def transformation() -> None:
        transformer.transform(CTX, text, list(prepared_spans), TokenProvenance())

    def end_to_end() -> None:
        spans = full_inspection()
        transformer.transform(CTX, text, spans, TokenProvenance())

    return (
        [
            ("screening", screening),
            ("detection_view", view),
            ("detection", detection),
            ("inspection_with_mapping", full_inspection),
            ("transformation", transformation),
            ("end_to_end", end_to_end),
        ],
        len(prepared_spans),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--size", type=int, default=4096, help="Request size in bytes.")
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    stages, entity_count = build_stages(args.size)
    results = [measure(label, function, args.iterations) for label, function in stages]
    end_to_end = next(r for r in results if r["stage"] == "end_to_end")
    within_budget = end_to_end["p95_ms"] <= LATENCY_BUDGET_MS

    report = {
        "request_bytes": args.size,
        "entities_detected": entity_count,
        "iterations": args.iterations,
        "budget_ms": LATENCY_BUDGET_MS,
        "within_budget": within_budget,
        "stages": results,
        "machine": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "processor": platform.processor() or "unknown",
            "machine": platform.machine(),
        },
        "note": "Measured on the machine described above, which is NOT the published "
        "reference hardware. Treat as a regression signal, not a published figure.",
    }

    print(f"\nDetection path, {args.size} bytes, {entity_count} entities detected")
    print(f"{'stage':<26} {'p50':>8} {'p95':>8} {'p99':>8} {'max':>8}")
    for result in results:
        print(
            f"{result['stage']:<26} {result['p50_ms']:>8.3f} {result['p95_ms']:>8.3f} "
            f"{result['p99_ms']:>8.3f} {result['max_ms']:>8.3f}"
        )
    verdict = "within" if within_budget else "OVER"
    print(
        f"\nend-to-end p95 {end_to_end['p95_ms']} ms — {verdict} the {LATENCY_BUDGET_MS} ms budget"
    )
    print(f"machine: {report['machine']['platform']}")

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"wrote {args.output}")

    return 0 if within_budget else 1


if __name__ == "__main__":
    raise SystemExit(main())
