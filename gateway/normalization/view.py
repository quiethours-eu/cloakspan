"""The detection view and its reversible offset map.

## What this replaces

The previous design normalised text and forwarded the normalised text, because
NFKC is not length-preserving and mapping offsets back was judged too risky. It
bought SI-01 (nothing unscanned is forwarded) at the cost of SI-17 (the
customer's bytes reach the provider unchanged), and it still missed homoglyphs
and zero-width characters -- so it paid for a benefit it did not fully receive.

This module gets both. Detection runs on a derived view; every view index maps
back to a range of original indices; replacement happens in the **original**.

## The two properties that make it safe

**Totality.** Every index of the original is covered by exactly one view
character's origin range, including characters dropped during normalisation.
Nothing in the original is unreachable from the view, which is what preserves
SI-01: we forward original bytes, but every original byte was accounted for
during inspection.

**Expansion.** A view span maps to the union of its characters' origin ranges,
so a detection over ``123`` in the view (from ``1<ZWSP>2<ZWSP>3``) maps back to
a span that *includes* both zero-width characters. Replacement removes them with
the digits. Leaving them behind would emit ``<TOKEN>​​`` -- ugly, and
a signal to an attacker that their invisible characters survived.

## Why clusters rather than characters

Normalising character by character would be simpler and would be wrong.
NFKC composes a base character with its following combining marks: ``a`` +
U+0304 becomes ``ā``. Per-character normalisation cannot see across that
boundary, so decomposed input would never match a detector looking for ``ā`` --
and decomposed input is exactly what arrives from some editors and some
operating systems.

So the unit of normalisation is a **cluster**: a base character plus every
following combining character. NFKC applied per cluster composes correctly, and
every character it produces maps to that cluster's origin range.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from gateway.normalization.confusables import CONFUSABLE_MAP, fold_confusables


class SpanMappingError(Exception):
    """A span could not be mapped back to the original safely.

    Always fatal for the request. A mapping we cannot validate would replace
    bytes we did not choose, and a silently adjusted span is a silently wrong
    span.
    """


def is_ignorable(ch: str) -> bool:
    """Characters dropped from the view: they are invisible and carry no text.

    ``Cf`` (format) covers zero-width space, zero-width joiner/non-joiner, the
    soft hyphen, and the bidirectional controls. ``Cc`` (control) covers the C0
    and C1 ranges, minus the whitespace that legitimately appears in prompts.

    Dropping these is what makes ``1<ZWSP>2`` detectable as ``12``. Their
    indices are not lost -- they are absorbed into the origin range of the
    neighbouring character, which is what makes replacement remove them.
    """
    if ch in "\t\n\r":
        return False
    category = unicodedata.category(ch)
    return category in ("Cf", "Cc") or ch == "﻿"


def _clusters(text: str):
    """Yield ``(start, end)`` for each base character plus its combining marks."""
    index, length = 0, len(text)
    while index < length:
        end = index + 1
        while end < length and unicodedata.combining(text[end]) != 0:
            end += 1
        yield index, end
        index = end


@dataclass(frozen=True, slots=True)
class DetectionView:
    """A normalised representation of one message, plus the way back.

    ``text`` is what unfolded detectors scan. ``folded`` is the confusable
    skeleton and is **the same length**, so both share ``origins`` exactly.
    """

    original: str
    text: str
    folded: str
    #: One ``(start, end)`` per character of ``text``: the half-open range of
    #: original indices that character derives from.
    origins: tuple[tuple[int, int], ...]

    def __post_init__(self) -> None:
        if len(self.text) != len(self.origins):
            raise SpanMappingError("offset map length does not match the view")
        if len(self.folded) != len(self.text):
            raise SpanMappingError("folded view length does not match the view")

    def map_span(self, start: int, end: int) -> tuple[int, int]:
        """Map a half-open view span to a half-open original span.

        Raises rather than clamping. A view span outside the view is a detector
        bug, and guessing what it meant is how the wrong bytes get replaced.
        """
        if not 0 <= start < end <= len(self.text):
            raise SpanMappingError(f"view span [{start}, {end}) is outside the view")
        origin_start = self.origins[start][0]
        origin_end = max(self.origins[index][1] for index in range(start, end))
        if not 0 <= origin_start < origin_end <= len(self.original):
            raise SpanMappingError(
                f"mapped span [{origin_start}, {origin_end}) is outside the original"
            )
        return origin_start, origin_end

    def verify_round_trip(self, view_start: int, view_end: int) -> bool:
        """Does re-viewing the mapped original text reproduce what was matched?

        **This is the load-bearing check.** It is what makes "only validated
        source spans are replaced" true rather than aspirational: a bug anywhere
        in the mapping cannot cause the wrong bytes to be replaced, because the
        replacement is rejected when the round trip disagrees.

        Compared on the *folded* view, because a detector may have matched
        there -- a Cyrillic ``З`` in the original folds to ``3``, and requiring
        the unfolded text to match would reject exactly the case this exists to
        catch.
        """
        try:
            origin_start, origin_end = self.map_span(view_start, view_end)
        except SpanMappingError:
            return False
        rebuilt = build_detection_view(self.original[origin_start:origin_end])
        return rebuilt.folded == self.folded[view_start:view_end]


#: ASCII characters for which building the view is provably the identity.
#:
#: A character qualifies only if all three passes leave it alone: it is not
#: ignorable (so it is not dropped), it is unchanged by NFKC, and it is not a
#: confusable (so folding does not rewrite it). 98 of the 128 ASCII code points
#: qualify; the 30 that do not are the C0 controls that `is_ignorable` strips --
#: ``\t``, ``\n`` and ``\r`` are deliberately kept, being ordinary content.
#:
#: Derived rather than hand-listed. A hand-written list would be a second
#: statement of the folding rules, free to drift from the first; this one is
#: wrong only if the rules themselves are.
_IDENTITY_ASCII = frozenset(
    ch
    for ch in map(chr, range(128))
    if not is_ignorable(ch) and ch not in CONFUSABLE_MAP and unicodedata.normalize("NFKC", ch) == ch
)


def build_detection_view(original: str) -> DetectionView:
    """Build the detection view and its offset map.

    Order matters and is fixed: drop ignorables, then NFKC per cluster, then
    fold confusables. Stripping invisibles *before* normalisation means
    ``1<ZWSP>2`` normalises as ``12``; the reverse order leaves the invisible
    inside a cluster boundary and the digits stay unjoined.

    ## The fast path

    Those three passes walk the string character by character and cluster by
    cluster in Python, and for most real prompts every one of them is the
    identity: plain ASCII has nothing to strip, nothing to normalise and
    nothing to fold. Detecting that up front costs one linear scan and skips
    all three -- measured **5.7x to 10.9x** faster, on what had become the
    largest stage of the detection path once conflict resolution stopped being
    quadratic.

    This is a shortcut through the work, not around it. The slow path still
    runs for anything non-ASCII, and it is the *only* path for text carrying
    confusables, invisibles or combining marks -- which is to say, for every
    evasion attempt this normalisation exists to defeat. Latin text with
    diacritics, all four corpus languages beyond English, and every adversarial
    example take the slow path unchanged.

    `test_the_fast_path_agrees_with_the_slow_path` compares the two on random
    input rather than trusting the reasoning above.
    """
    if not original:
        return DetectionView(original="", text="", folded="", origins=())

    if original.isascii() and _IDENTITY_ASCII.issuperset(original):
        # Every character maps to itself, so the offset map is the identity and
        # `text`, `folded` and `original` are the same string.
        return DetectionView(
            original=original,
            text=original,
            folded=original,
            origins=tuple(zip(range(len(original)), range(1, len(original) + 1), strict=True)),
        )

    # --- 1. Drop ignorables, remembering where they were. -------------------
    # A dropped run is absorbed by the *next* kept character, so replacing that
    # character's span removes the invisibles with it.
    stripped: list[str] = []
    stripped_origin: list[tuple[int, int]] = []
    pending_start: int | None = None

    for index, ch in enumerate(original):
        if is_ignorable(ch):
            if pending_start is None:
                pending_start = index
            continue
        start = pending_start if pending_start is not None else index
        pending_start = None
        stripped.append(ch)
        stripped_origin.append((start, index + 1))

    if pending_start is not None:
        # Trailing ignorables: attach to the last kept character, or -- if the
        # whole string was ignorable -- there is nothing to attach to and the
        # view is legitimately empty.
        if stripped_origin:
            last_start, _ = stripped_origin[-1]
            stripped_origin[-1] = (last_start, len(original))

    if not stripped:
        # The whole message was ignorable characters. The view is empty and no
        # original index is covered -- the one exception to totality, and it is
        # sound: there is nothing to detect *because* there is nothing visible.
        # Forwarding the original is forwarding a string with no text content.
        #
        # Stated rather than left implicit because "every index is covered" is
        # what SI-01 rests on, and an invariant with an undocumented exception
        # is worse than one with a documented one. Found by
        # ``test_building_a_view_never_raises`` on the input "\x08".
        return DetectionView(original=original, text="", folded="", origins=())

    stripped_text = "".join(stripped)

    # --- 2. NFKC per cluster, so composition works. -------------------------
    view_chars: list[str] = []
    origins: list[tuple[int, int]] = []

    for cluster_start, cluster_end in _clusters(stripped_text):
        cluster = stripped_text[cluster_start:cluster_end]
        normalized = unicodedata.normalize("NFKC", cluster)
        if not normalized:
            continue
        origin = (
            stripped_origin[cluster_start][0],
            stripped_origin[cluster_end - 1][1],
        )
        for out in normalized:
            view_chars.append(out)
            origins.append(origin)

    text = "".join(view_chars)
    return DetectionView(
        original=original,
        text=text,
        folded=fold_confusables(text),
        origins=tuple(origins),
    )


def map_and_validate(view: DetectionView, spans, *, on_reject) -> list[tuple[int, int, object]]:
    """Map view spans to original spans, dropping any that fail validation.

    Returns ``(origin_start, origin_end, span)`` triples. ``on_reject`` is
    called with the offending span and a reason so the caller can decide
    whether to fail the request -- this module does not choose that policy.
    """
    mapped: list[tuple[int, int, object]] = []
    for span in spans:
        try:
            origin_start, origin_end = view.map_span(span.start, span.end)
        except SpanMappingError as exc:
            on_reject(span, str(exc))
            continue
        if not view.verify_round_trip(span.start, span.end):
            on_reject(span, "round trip did not reproduce the matched text")
            continue
        mapped.append((origin_start, origin_end, span))
    return mapped
