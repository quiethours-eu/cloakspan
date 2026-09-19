"""Evaluation corpus format and loader.

One example per line of JSONL::

    {"id": "lv-pos-0001",
     "lang": "lv",
     "kind": "positive",
     "text": "Klienta personas kods ir 120385-12340.",
     "spans": [{"start": 25, "end": 37, "entity_type": "LV_PERSONAL_CODE"}],
     "note": "hyphenated legacy form"}

``kind`` is one of:

``positive``
    Contains at least one entity that must be found.
``negative``
    Contains **no** entities. These carry the weight: a detector with perfect
    recall and no negative corpus is indistinguishable from one that flags
    everything.
``boundary``
    Near-misses that must not fire -- invalid checksums, order numbers,
    timestamps, product codes.
``adversarial``
    Deliberate evasion attempts. Failures here are expected until Phase 4 and
    are reported separately so they do not silently drag the headline numbers.
``known_gap``
    Entities the product has **decided** not to detect, carrying real gold
    spans and reported separately.

    These exist because a recall concession that appears nowhere in the corpus
    is indistinguishable from a concession nobody made. The unlabelled phone
    number is the case that prompted this: ``PHONE_NUMBER`` recall was lowered
    to 0.90 to pay for it, and no example in the corpus exercised it, so the
    lowered threshold measured nothing and the gap was invisible in every
    published number.
``mixed``
    More than one language in one document, which is how Baltic business text
    actually looks.

Every example is **synthetic**. No real personal data is in this repository:
identifiers are generated from the published check-digit algorithms and names
are drawn from a fixed fictional list. Provenance is recorded in
``evals/datasets/README.md``.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

DATASETS_ROOT = Path(__file__).resolve().parent

#: Splits. ``dev`` is for tuning. ``holdout`` is **locked**: it must never be
#: read while a detector is being changed, or the number it produces means
#: nothing.
SPLITS = ("dev", "holdout")

LANGUAGES = ("lv", "lt", "et", "en")

KINDS = ("positive", "negative", "boundary", "adversarial", "mixed", "known_gap")


@dataclass(frozen=True, slots=True)
class GoldSpan:
    start: int
    end: int
    entity_type: str

    def as_key(self) -> tuple[int, int, str]:
        return (self.start, self.end, self.entity_type)


@dataclass(frozen=True, slots=True)
class Example:
    id: str
    lang: str
    kind: str
    text: str
    spans: tuple[GoldSpan, ...] = ()
    note: str = ""

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"{self.id}: unknown kind {self.kind!r}")
        if self.kind in ("negative", "boundary") and self.spans:
            raise ValueError(f"{self.id}: {self.kind} examples must have no gold spans")
        for span in self.spans:
            if not 0 <= span.start < span.end <= len(self.text):
                raise ValueError(f"{self.id}: span {span} outside text bounds")

    def gold_text(self, span: GoldSpan) -> str:
        return self.text[span.start : span.end]


@dataclass(slots=True)
class Corpus:
    version: str
    split: str
    examples: list[Example] = field(default_factory=list)

    def by_language(self, lang: str) -> list[Example]:
        return [e for e in self.examples if e.lang == lang]

    def entity_types(self) -> set[str]:
        return {span.entity_type for e in self.examples for span in e.spans}

    def __len__(self) -> int:
        return len(self.examples)


def to_json_line(example: Example) -> str:
    payload = {
        "id": example.id,
        "lang": example.lang,
        "kind": example.kind,
        "text": example.text,
        "spans": [
            {"start": s.start, "end": s.end, "entity_type": s.entity_type} for s in example.spans
        ],
    }
    if example.note:
        payload["note"] = example.note
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def parse_json_line(line: str) -> Example:
    raw = json.loads(line)
    return Example(
        id=raw["id"],
        lang=raw["lang"],
        kind=raw["kind"],
        text=raw["text"],
        spans=tuple(GoldSpan(s["start"], s["end"], s["entity_type"]) for s in raw.get("spans", [])),
        note=raw.get("note", ""),
    )


def iter_examples(path: Path) -> Iterator[Example]:
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield parse_json_line(line)
            except Exception as exc:
                raise ValueError(f"{path}:{number}: {exc}") from exc


def load_corpus(split: str, root: Path | None = None) -> Corpus:
    """Load one split. Raises if the split is missing rather than returning empty.

    An eval harness that silently reports "0 examples, 100% precision" is worse
    than one that crashes.
    """
    if split not in SPLITS:
        raise ValueError(f"unknown split {split!r}; expected one of {SPLITS}")
    base = (root or DATASETS_ROOT) / split
    if not base.is_dir():
        raise FileNotFoundError(
            f"corpus split {split!r} not found at {base}. "
            "Run `python -m evals.datasets.generate` to build it."
        )

    version_file = base / "VERSION"
    version = version_file.read_text(encoding="utf-8").strip() if version_file.is_file() else "0"

    examples: list[Example] = []
    for path in sorted(base.glob("*.jsonl")):
        examples.extend(iter_examples(path))

    if not examples:
        raise ValueError(f"corpus split {split!r} at {base} contains no examples")

    seen: set[str] = set()
    for example in examples:
        if example.id in seen:
            raise ValueError(f"duplicate example id {example.id!r} in split {split!r}")
        seen.add(example.id)

    return Corpus(version=version, split=split, examples=examples)
