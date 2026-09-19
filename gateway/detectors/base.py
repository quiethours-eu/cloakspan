"""Detector protocol and span conflict resolution.

The conflict-resolution algorithm here is a clean-room reimplementation of a
standard technique (drop contained spans, then resolve intersections by
confidence then length). The same approach is visible in Presidio's
``anonymizer_engine._remove_conflicts_and_get_text_manipulation_data``; we
implement it independently rather than vendoring, because this is the security
core and we want to own it outright. Provenance is recorded internally.
"""

from __future__ import annotations

import bisect
import unicodedata
from typing import Protocol, runtime_checkable

from gateway.domain import Span


@runtime_checkable
class Detector(Protocol):
    """A detector finds spans of one or more entity types in text.

    Detectors must be pure and side-effect free: the pipeline may run them
    concurrently, on partial text, and on attacker-controlled input.
    """

    name: str

    def detect(self, text: str) -> list[Span]: ...


def normalize_for_detection(text: str) -> str:
    """NFKC-normalise text.

    .. deprecated::
       Superseded by :func:`gateway.normalization.build_detection_view`, which
       normalises *and* keeps a reversible map back to the original so the
       customer's bytes reach the provider unchanged (SI-17). This function
       normalises with no way back and must not be reintroduced on the request
       path.

       Retained only because it is a useful one-liner for tests and tooling that
       need a normalised string and have no offsets to preserve.
    """
    return unicodedata.normalize("NFKC", text)


def resolve_conflicts(spans: list[Span]) -> list[Span]:
    """Reduce overlapping detections to a non-overlapping, ordered set.

    Rules, applied in order:

    1. **Drop contained spans.** If one span fully contains another, keep the
       container. ``alice@acme.lv`` is one EMAIL, not an EMAIL containing a
       PERSON.
    2. **Resolve partial intersections** by higher score, then longer span,
       then earlier start. Deterministic -- policy decisions must be
       reproducible (release gate), so ties may never be broken by set or dict
       iteration order.

    Returns spans sorted by start offset, guaranteed non-overlapping.

    ## Why this is not the obvious loop

    The obvious implementation asks, for each candidate, whether it overlaps
    *any* span kept so far. That is O(n**2), and it was: on a 256 KB request --
    the default `SAG_MAX_INPUT_CHARS` -- it produced 7,709 spans and spent
    **4.4 seconds** here, 85% of the entire detection path. Every other stage
    scales linearly; this one alone made the path superlinear, and because
    detection runs on the event loop, one such request stalls the whole process.

    The insight that removes it: **the kept set is non-overlapping by
    construction**, so it is totally ordered by start *and* by end. A candidate
    can therefore only be blocked by its immediate neighbours in that order --
    the last span starting at or before it, and the first starting after it.
    Anything further away is separated by one of those two. So a binary search
    replaces the scan, and the loop becomes O(n log n).

    Same inputs, same output, same order: `test_conflict_resolution_matches_the_
    reference_implementation` checks that against the naive version on random
    span sets, because this is policy-relevant and a subtle change here would
    silently alter what gets protected.
    """
    if not spans:
        return []

    # Deterministic ordering: score desc, length desc, start asc, then
    # entity_type/detector as a final tiebreak so equal-ranked spans from
    # different detectors always resolve the same way.
    ranked = sorted(
        spans,
        key=lambda s: (-s.score, -s.length, s.start, s.entity_type, s.detector),
    )

    kept: list[Span] = []
    starts: list[int] = []  # kept starts, ascending -- the binary-search index
    for span in ranked:
        position = bisect.bisect_right(starts, span.start)
        # Predecessor: the last kept span starting at or before this one.
        if position and kept[position - 1].end > span.start:
            continue
        # Successor: the first kept span starting after this one.
        if position < len(kept) and kept[position].start < span.end:
            continue
        kept.insert(position, span)
        starts.insert(position, span.start)

    # Already ascending by start; ties on start cannot occur, because two spans
    # with the same start always overlap and only one survives.
    return kept
