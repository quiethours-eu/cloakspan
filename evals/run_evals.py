"""``make evals`` — measure detection quality and print numbers we can publish.

Run::

    python -m evals.run_evals                 # dev split, human-readable
    python -m evals.run_evals --split holdout # the locked set. Read once.
    python -m evals.run_evals --json out.json # machine-readable

Until this prints a per-entity table we are guessing about our own product, and
"how good is your detection?" is the first question a serious buyer asks.

## The rule this tool enforces

**No aggregate score may conceal a failing entity or language.** The exit code
is non-zero when any entity/language pair is below its threshold, regardless of
how good the headline number looks. Thresholds come from
docs/entity-taxonomy.md and are frozen before the holdout set is read.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

from evals.datasets.schema import load_corpus
from evals.scoring import (
    Report,
    aggregate,
    failing_pairs,
    group_failures,
    score_corpus,
)
from gateway.config import build_detectors
from gateway.detectors.base import resolve_conflicts
from gateway.domain import Span
from gateway.normalization import SpanMappingError, build_detection_view

# Frozen thresholds, per docs/entity-taxonomy.md. (min precision, min recall).
THRESHOLDS: dict[str, tuple[float, float]] = {
    "AWS_ACCESS_KEY": (0.99, 0.99),
    "PRIVATE_KEY": (0.99, 0.99),
    "JWT": (0.99, 0.99),
    "OPENAI_API_KEY": (0.99, 0.99),
    "ANTHROPIC_API_KEY": (0.99, 0.99),
    "GITHUB_TOKEN": (0.99, 0.99),
    "SLACK_TOKEN": (0.99, 0.99),
    "LV_PERSONAL_CODE": (0.99, 0.99),
    "LT_PERSONAL_CODE": (0.99, 0.99),
    "EE_PERSONAL_CODE": (0.99, 0.99),
    "BALTIC_PERSONAL_CODE": (0.99, 0.99),
    "IBAN": (0.99, 0.99),
    "PAYMENT_CARD": (0.99, 0.99),
    "EMAIL_ADDRESS": (0.99, 0.99),
    # Asymmetric on purpose. Phone numbers have no checksum, so precision is
    # bought with a context requirement that deliberately costs recall: an
    # unlabelled number in a signature block is missed, and that is the trade
    # that keeps the detector switched on. Demanding 99% recall here would push
    # us to drop the context rule and flag every order number.
    "PHONE_NUMBER": (0.95, 0.90),
}
#: Contextual entities, once NER ships.
CONTEXTUAL_THRESHOLD = (0.85, 0.90)

#: P95 detection-path budget for a 4 KB request, per docs/entity-taxonomy.md.
LATENCY_BUDGET_MS = 150.0

BOLD, DIM, GREEN, RED, YELLOW, RESET = (
    "\033[1m",
    "\033[2m",
    "\033[32m",
    "\033[31m",
    "\033[33m",
    "\033[0m",
)


def build_predictor():
    """The detection path exactly as the pipeline runs it.

    Every stage the pipeline applies is applied here, because a harness that
    measures a *different* path measures nothing:

    * the detection view and its offset map, so gold spans (which index the
      original text) are comparable with predictions;
    * the folded/unfolded split, which is what catches homoglyphs;
    * conflict resolution, twice -- in view coordinates and again after mapping.
      This is where the LT/EE label collapse happens, and scoring raw detector
      output would hide it.

    Spans that fail to map or fail the round-trip check are dropped here rather
    than raising. The pipeline fails the request instead; for measurement, a
    dropped span is a false negative and shows up as one, which is the more
    useful signal in a report.
    """
    from gateway.config import Settings

    detectors = build_detectors(Settings())

    def predict(text: str) -> list[Span]:
        view = build_detection_view(text)
        view_spans: list[Span] = []
        for detector in detectors:
            source = view.folded if getattr(detector, "uses_folded_view", False) else view.text
            view_spans.extend(detector.detect(source))

        mapped: list[Span] = []
        for span in resolve_conflicts(view_spans):
            try:
                start, end = view.map_span(span.start, span.end)
            except SpanMappingError:
                continue
            if not view.verify_round_trip(span.start, span.end):
                continue
            mapped.append(
                Span(
                    start=start,
                    end=end,
                    entity_type=span.entity_type,
                    text=text[start:end],
                    score=span.score,
                    detector=span.detector,
                )
            )
        return resolve_conflicts(mapped)

    return predict


def measure_latency(predict, iterations: int = 40) -> dict[str, float]:
    """P50/P95 over a 4 KB request on this machine.

    Reported with the machine unnamed on purpose -- a latency figure without
    reference hardware is a comparison nobody can reproduce, so this is a
    regression signal for us, not a published number.
    """
    sample = ("Klienta personas kods ir 120385-12340, e-pasts a11@example.lv. " * 70)[:4096]
    timings = []
    for _ in range(iterations):
        started = time.perf_counter()
        predict(sample)
        timings.append((time.perf_counter() - started) * 1000)
    timings.sort()
    return {
        "p50_ms": round(statistics.median(timings), 3),
        "p95_ms": round(timings[int(len(timings) * 0.95) - 1], 3),
        "max_ms": round(timings[-1], 3),
        "input_bytes": len(sample.encode("utf-8")),
    }


def _row(label: str, counts, threshold: tuple[float, float] | None) -> str:
    status = " "
    if threshold:
        ok = counts.precision >= threshold[0] and counts.recall >= threshold[1]
        status = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
    return (
        f"  {label:<34} {counts.precision:>7.1%} {counts.recall:>8.1%} "
        f"{counts.f1:>7.1%} {counts.support:>6}  {counts.false_positive:>4}  {status}"
    )


def print_report(
    report: Report,
    adversarial: Report,
    known_gaps: Report,
    latency: dict[str, float],
) -> None:
    print(f"\n{BOLD}Detection evaluation{RESET}")
    print(
        f"{DIM}corpus v{report.corpus_version}  split={report.split}  "
        f"examples={report.examples_scored}{RESET}\n"
    )

    header = (
        f"  {'entity / language':<34} {'prec':>7} {'recall':>8} {'F1':>7} {'gold':>6}  {'FP':>4}"
    )
    print(f"{BOLD}Per entity{RESET}")
    print(header)
    for entity, counts in sorted(report.by_entity.items()):
        print(_row(entity, counts, THRESHOLDS.get(entity, CONTEXTUAL_THRESHOLD)))

    print(f"\n{BOLD}Per entity and language (the gate){RESET}")
    print(header)
    for key, counts in sorted(report.by_entity_language.items()):
        entity = key.split("/", 1)[0]
        print(_row(key, counts, THRESHOLDS.get(entity, CONTEXTUAL_THRESHOLD)))

    print(f"\n{BOLD}Per example kind{RESET}")
    print(header)
    for kind, counts in sorted(report.by_kind.items()):
        print(_row(kind, counts, None))

    total = aggregate(report)
    print(f"\n{BOLD}Aggregate{RESET} {DIM}(informational only — the gate is per pair){RESET}")
    print(_row("all entities", total, None))

    print(
        f"\n{BOLD}Adversarial (Unicode evasion){RESET} "
        f"{DIM}scored separately — known open until Phase 4{RESET}"
    )
    print(header)
    for entity, counts in sorted(adversarial.by_entity.items()):
        print(_row(entity, counts, None))
    if not adversarial.by_entity:
        print(f"  {DIM}no adversarial examples in this split{RESET}")

    print(
        f"\n{BOLD}Known gaps (deliberate non-detections){RESET} "
        f"{DIM}scored separately — recall here is expected to be low{RESET}"
    )
    print(header)
    for entity, counts in sorted(known_gaps.by_entity.items()):
        print(_row(entity, counts, None))
    if not known_gaps.by_entity:
        print(f"  {DIM}no known-gap examples in this split{RESET}")
    else:
        print(
            f"  {DIM}These are recall concessions the product has chosen. A "
            f"concession that appears in no example cannot be verified, and its "
            f"lowered threshold measures nothing.{RESET}"
        )

    print(f"\n{BOLD}Detection latency{RESET} {DIM}(this machine, not reference hardware){RESET}")
    within_budget = latency["p95_ms"] <= LATENCY_BUDGET_MS
    budget = f"{GREEN}within{RESET}" if within_budget else f"{RED}over{RESET}"
    print(
        f"  {latency['input_bytes']} bytes: p50 {latency['p50_ms']} ms, "
        f"p95 {latency['p95_ms']} ms, max {latency['max_ms']} ms "
        f"({budget} the {LATENCY_BUDGET_MS} ms budget)"
    )

    grouped = group_failures(report)
    for reason in ("missed", "spurious"):
        items = grouped.get(reason, [])
        if not items:
            continue
        colour = RED if reason == "missed" else YELLOW
        print(f"\n{BOLD}{colour}{reason.capitalize()} ({len(items)} shown){RESET}")
        for failure in items[:15]:
            print(
                f"  {DIM}{failure.example_id} [{failure.kind}/{failure.lang}]{RESET} "
                f"{failure.detail}"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the detection evaluation.")
    parser.add_argument("--split", default="dev", choices=("dev", "holdout"))
    parser.add_argument(
        "--alias-baltic-codes",
        action="store_true",
        help="Score LT and EE personal codes as one class. See evals/scoring.py.",
    )
    parser.add_argument("--json", type=Path, help="Write the machine-readable report here.")
    parser.add_argument(
        "--no-gate",
        action="store_true",
        help="Report without failing the exit code. For exploration, never for a release.",
    )
    args = parser.parse_args(argv)

    if args.split == "holdout":
        print(
            f"{YELLOW}Reading the LOCKED holdout split. Tuning a detector against "
            f"this number invalidates it.{RESET}",
            file=sys.stderr,
        )

    corpus = load_corpus(args.split)
    predict = build_predictor()

    report = score_corpus(corpus, predict, aliased=args.alias_baltic_codes)
    adversarial = score_corpus(
        corpus, predict, aliased=args.alias_baltic_codes, kinds=("adversarial",)
    )
    known_gaps = score_corpus(
        corpus, predict, aliased=args.alias_baltic_codes, kinds=("known_gap",)
    )
    latency = measure_latency(predict)

    print_report(report, adversarial, known_gaps, latency)

    failures = failing_pairs(report, THRESHOLDS, CONTEXTUAL_THRESHOLD)
    if failures:
        print(f"\n{BOLD}{RED}{len(failures)} entity/language pair(s) below threshold{RESET}")
        for key, counts, min_p, min_r in failures:
            print(
                f"  {key:<34} precision {counts.precision:.1%} (need {min_p:.0%}), "
                f"recall {counts.recall:.1%} (need {min_r:.0%})"
            )
        print(
            f"\n{DIM}Per docs/entity-taxonomy.md, an entity below threshold is removed "
            f"from the advertised support matrix or blocks the release.{RESET}"
        )
    else:
        print(f"\n{GREEN}All entity/language pairs meet their thresholds.{RESET}")

    if args.json:
        payload = {
            "report": report.as_dict(),
            "adversarial": adversarial.as_dict(),
            "known_gaps": known_gaps.as_dict(),
            "latency": latency,
            "thresholds": {k: list(v) for k, v in THRESHOLDS.items()},
            "contextual_threshold": list(CONTEXTUAL_THRESHOLD),
            "failing_pairs": [f[0] for f in failures],
        }
        args.json.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        print(f"{DIM}wrote {args.json}{RESET}")

    return 0 if (args.no_gate or not failures) else 1


if __name__ == "__main__":
    raise SystemExit(main())
