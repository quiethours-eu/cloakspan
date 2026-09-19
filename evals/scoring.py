"""Span-level scoring for the detection evaluation.

## Why span-level and not document-level

Document-level scoring ("did this document contain a personal code?") is easy
and useless: a detector that flags the whole document scores perfectly and
tokenises the entire prompt. Precision and recall have to be measured on the
thing we actually act on, which is a span.

## Matching

A prediction matches a gold span when ``(start, end, entity_type)`` are equal.
Strict, deliberately. A span that is one character off replaces one character
too few in the outbound text, which leaks a digit -- so "nearly right" is not
right.

Aliasing is available for the one case where strictness measures the wrong
thing: Lithuanian and Estonian personal codes are structurally identical and the
detectors emit both labels, with conflict resolution deterministically keeping
``EE_PERSONAL_CODE``. Scored strictly, Lithuanian recall is 0% while every
Lithuanian code is in fact detected and pseudonymised. Both numbers are
reported: the strict one because it is the truth about the labels, and the
aliased one because it is the truth about the protection.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from evals.datasets.schema import Corpus, Example
from gateway.domain import Span

#: Entity types that are genuinely the same identifier under two names.
BALTIC_CODE_ALIAS = {
    "LT_PERSONAL_CODE": "BALTIC_PERSONAL_CODE",
    "EE_PERSONAL_CODE": "BALTIC_PERSONAL_CODE",
}


@dataclass(slots=True)
class Counts:
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0

    @property
    def precision(self) -> float:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else 1.0

    @property
    def recall(self) -> float:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def support(self) -> int:
        return self.true_positive + self.false_negative

    def as_dict(self) -> dict[str, float | int]:
        return {
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "false_negative": self.false_negative,
            "support": self.support,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


@dataclass(slots=True)
class Failure:
    example_id: str
    kind: str
    lang: str
    reason: str
    detail: str


@dataclass(slots=True)
class Report:
    corpus_version: str
    split: str
    aliased: bool
    by_entity: dict[str, Counts] = field(default_factory=dict)
    by_language: dict[str, Counts] = field(default_factory=dict)
    by_entity_language: dict[str, Counts] = field(default_factory=dict)
    by_kind: dict[str, Counts] = field(default_factory=dict)
    failures: list[Failure] = field(default_factory=list)
    examples_scored: int = 0

    def as_dict(self) -> dict:
        return {
            "corpus_version": self.corpus_version,
            "split": self.split,
            "aliased": self.aliased,
            "examples_scored": self.examples_scored,
            "by_entity": {k: v.as_dict() for k, v in sorted(self.by_entity.items())},
            "by_language": {k: v.as_dict() for k, v in sorted(self.by_language.items())},
            "by_entity_language": {
                k: v.as_dict() for k, v in sorted(self.by_entity_language.items())
            },
            "by_kind": {k: v.as_dict() for k, v in sorted(self.by_kind.items())},
            "failures": [
                {
                    "example_id": f.example_id,
                    "kind": f.kind,
                    "lang": f.lang,
                    "reason": f.reason,
                    "detail": f.detail,
                }
                for f in self.failures
            ],
        }


def _alias(entity_type: str, aliased: bool) -> str:
    if not aliased:
        return entity_type
    return BALTIC_CODE_ALIAS.get(entity_type, entity_type)


def score_example(
    example: Example,
    predicted: list[Span],
    report: Report,
    *,
    aliased: bool,
    max_failures: int,
) -> None:
    gold_keys = {(s.start, s.end, _alias(s.entity_type, aliased)) for s in example.spans}
    predicted_keys = {(s.start, s.end, _alias(s.entity_type, aliased)) for s in predicted}

    def bump(entity: str, attribute: str) -> None:
        for bucket, key in (
            (report.by_entity, entity),
            (report.by_language, example.lang),
            (report.by_entity_language, f"{entity}/{example.lang}"),
            (report.by_kind, example.kind),
        ):
            counts = bucket.setdefault(key, Counts())
            setattr(counts, attribute, getattr(counts, attribute) + 1)

    for key in gold_keys & predicted_keys:
        bump(key[2], "true_positive")

    for key in gold_keys - predicted_keys:
        bump(key[2], "false_negative")
        if len(report.failures) < max_failures:
            report.failures.append(
                Failure(
                    example_id=example.id,
                    kind=example.kind,
                    lang=example.lang,
                    reason="missed",
                    detail=f"{key[2]} at [{key[0]}, {key[1]}) -> {example.text[key[0] : key[1]]!r}",
                )
            )

    for key in predicted_keys - gold_keys:
        bump(key[2], "false_positive")
        if len(report.failures) < max_failures:
            report.failures.append(
                Failure(
                    example_id=example.id,
                    kind=example.kind,
                    lang=example.lang,
                    reason="spurious",
                    detail=f"{key[2]} at [{key[0]}, {key[1]}) -> {example.text[key[0] : key[1]]!r}",
                )
            )

    report.examples_scored += 1


#: The kinds that make up the headline numbers. Adversarial examples are
#: excluded and scored into their own report: folding a known-open evasion gap
#: into the headline would understate detection quality today *and* hide the gap
#: closing tomorrow.
SCORED_KINDS = ("positive", "negative", "boundary", "mixed")


def score_corpus(
    corpus: Corpus,
    predict,
    *,
    aliased: bool = False,
    kinds: tuple[str, ...] = SCORED_KINDS,
    max_failures: int = 40,
) -> Report:
    """Score ``predict`` over the examples in ``corpus`` whose kind is in ``kinds``.

    ``predict`` takes text and returns the spans a detector set produced.
    """
    report = Report(corpus_version=corpus.version, split=corpus.split, aliased=aliased)
    for example in corpus.examples:
        if example.kind not in kinds:
            continue
        score_example(
            example,
            predict(example.text),
            report,
            aliased=aliased,
            max_failures=max_failures,
        )
    return report


def failing_pairs(
    report: Report, thresholds: dict[str, tuple[float, float]], default: tuple[float, float]
) -> list[tuple[str, Counts, float, float]]:
    """Entity/language pairs below their threshold.

    Returned per pair rather than aggregated, because an aggregate that passes
    while one language fails is the exact failure mode the release gate exists
    to prevent.
    """
    failures = []
    for key, counts in sorted(report.by_entity_language.items()):
        entity = key.split("/", 1)[0]
        min_precision, min_recall = thresholds.get(entity, default)
        if counts.precision < min_precision or counts.recall < min_recall:
            failures.append((key, counts, min_precision, min_recall))
    return failures


def aggregate(report: Report) -> Counts:
    total = Counts()
    for counts in report.by_entity.values():
        total.true_positive += counts.true_positive
        total.false_positive += counts.false_positive
        total.false_negative += counts.false_negative
    return total


def group_failures(report: Report) -> dict[str, list[Failure]]:
    grouped: dict[str, list[Failure]] = defaultdict(list)
    for failure in report.failures:
        grouped[failure.reason].append(failure)
    return dict(grouped)
