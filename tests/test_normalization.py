"""The detection view, the offset map, folding, and screening.

ADR-0015 calls the offset map the highest-risk change in the plan: it sits
between detection and replacement, so a bug either corrupts customer text or
drops a detection. The mitigations it names, in order of value, are all here:

1. round-trip validation, which makes a mapping bug fail closed;
2. the property that input with no detections is forwarded byte-identical;
3. the property that replace-then-reverse reproduces the original;
4. a fixture corpus of every Unicode class we know attackers use.

The Baltic false-positive tests matter as much as the evasion ones. Blocking
``Bērziņa`` would break legitimate traffic in the exact market this product is
for, which is worse than the evasion it prevents.
"""

from __future__ import annotations

import unicodedata

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gateway.domain import RequestContext, Span
from gateway.normalization import (
    CONFUSABLE_MAP,
    SpanMappingError,
    SuspiciousEncodingError,
    build_detection_view,
    fold_confusables,
    screen_text,
)
from gateway.normalization.screening import (
    REASON_BIDI,
    REASON_CONFUSABLE,
    REASON_INVISIBLE,
    REASON_MIXED_SCRIPT,
    mixed_script_words,
    script_of,
)
from gateway.normalization.view import _IDENTITY_ASCII, is_ignorable
from gateway.restoration.engine import RestorationEngine
from gateway.transformations.engine import TransformationEngine
from gateway.transformations.tokens import TokenProvenance

ZWSP = "​"
ZWNJ = "‌"
SOFT_HYPHEN = "­"
RLO = "‮"
LRI = "⁦"

BALTIC_WORDS = [
    "Bērziņa",
    "Ozoliņš",
    "Šiauliai",
    "Kazlauskaitė",
    "Jõgeva",
    "Põhjala",
    "Tartumaa",
    "Ģertrūde",
    "Žemaitija",
    "Ülemiste",
]

SLOW = settings(
    max_examples=200,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None,
)


def covered_indices(view) -> set[int]:
    covered: set[int] = set()
    for start, end in view.origins:
        covered.update(range(start, end))
    return covered


ASCII = st.characters(min_codepoint=32, max_codepoint=126)


def _slow_build_detection_view(original: str):
    """`build_detection_view` with the ASCII fast path disabled.

    Forces the general implementation by making the fast path's guard fail,
    rather than re-implementing it here. A re-implementation would be a second
    copy of the folding rules, free to agree with the first for the wrong
    reason.

    The trick: prepend one non-ASCII character so the guard rejects the string,
    build, then drop that leading position and shift the offsets back.
    """
    marker = "é"  # non-ASCII, so the guard fails; one cluster, one view char
    view = build_detection_view(marker + original)
    return (
        view.text[1:],
        view.folded[1:],
        tuple((start - 1, end - 1) for start, end in view.origins[1:]),
    )


class TestAsciiFastPath:
    """The fast path must be a shortcut through the work, not around it.

    Building the view walks the string three times in Python -- strip, NFKC,
    fold -- and for plain ASCII all three are the identity. Skipping them is
    5.7x to 10.9x faster, and is sound only if the result is indistinguishable.
    """

    @given(text=st.text(alphabet=ASCII, min_size=1, max_size=120))
    @SLOW
    def test_the_fast_path_agrees_with_the_slow_path(self, text):
        """Random printable ASCII: both paths, same view."""
        fast = build_detection_view(text)
        slow_text, slow_folded, slow_origins = _slow_build_detection_view(text)
        assert (fast.text, fast.folded, fast.origins) == (slow_text, slow_folded, slow_origins)

    @pytest.mark.parametrize(
        ("text", "why"),
        [
            (f"12{ZWSP}345", "zero-width space must still be stripped"),
            (f"abc{SOFT_HYPHEN}def", "soft hyphen must still be stripped"),
            (f"{RLO}abc", "bidi control must still be stripped"),
            ("Кods", "Cyrillic homoglyph must still be folded"),
            ("１２３", "fullwidth digits must still be normalised"),
            ("a\x00b", "a C0 control is ignorable and must be dropped"),
        ],
    )
    def test_evasion_still_reaches_the_real_implementation(self, text, why):
        """The cases normalisation exists for must still be transformed.

        Asserted by result rather than by instrumentation: had the fast path
        wrongly claimed any of these, the view would come back equal to input.
        """
        view = build_detection_view(text)
        assert not (view.text == text and view.folded == text), why

    @pytest.mark.parametrize(
        "text",
        ["Bērziņa", "Kazlauskaitė", "Jõgeva", "Põhjala", "Ģertrūde"],
    )
    def test_diacritics_are_excluded_from_the_fast_path(self, text):
        """Non-ASCII must not take the shortcut, *even when the result matches*.

        These are already NFKC-composed, carry no confusables and nothing
        ignorable, so the slow path returns a view identical to its input. That
        makes "the output changed" useless as evidence here -- an earlier
        version of this test asserted exactly that and failed for a reason that
        was about the test, not the code.

        The property that actually matters is that the guard rejects them, so
        that is what is asserted. It keeps the fast path's correctness argument
        resting on "ASCII only", rather than on a coincidence about which
        non-ASCII characters happen to be transformation-invariant.
        """
        assert not _IDENTITY_ASCII.issuperset(text)
        assert build_detection_view(text).text == text  # slow path, same answer

    def test_plain_ascii_is_unchanged_by_either_path(self):
        text = "Personas kods 120385-12342, e-pasts a@b.lv\tand a newline\n"
        view = build_detection_view(text)
        assert view.text == text
        assert view.folded == text
        assert view.origins == tuple((i, i + 1) for i in range(len(text)))

    @given(text=st.text(alphabet=ASCII, min_size=1, max_size=80))
    @SLOW
    def test_round_trip_verification_still_holds_on_the_fast_path(self, text):
        """`verify_round_trip` is what makes replacement safe. The fast path
        must not weaken it."""
        view = build_detection_view(text)
        assert view.verify_round_trip(0, len(view.text))


# ---------------------------------------------------------------------------
# The offset map
# ---------------------------------------------------------------------------


class TestOffsetMapTotality:
    """Every original index must be reachable from the view.

    This is what preserves SI-01 while the original is forwarded: we send the
    customer's bytes, but no byte escaped inspection.
    """

    @pytest.mark.parametrize(
        "text",
        [
            "plain ascii",
            "120385-12342",
            f"120385{ZWSP}-12342",
            f"{ZWSP}{ZWSP}leading invisibles",
            f"trailing invisibles{ZWSP}{ZWSP}",
            "ﬁle",  # ligature expands
            "１２３",  # fullwidth digits contract in width, not count
            "Bērziņa",
            "Bērziņa",  # decomposed
            "120З85-12342",  # Cyrillic
            "ą́b",  # stacked combining marks
            "мир and world",
            "",
        ],
    )
    def test_every_original_index_is_covered(self, text):
        view = build_detection_view(text)
        assert covered_indices(view) == set(range(len(text)))

    @pytest.mark.parametrize("text", ["abc", f"a{ZWSP}b", "ﬁ", "Bērzina"])
    def test_origin_ranges_are_ordered_and_non_decreasing(self, text):
        view = build_detection_view(text)
        previous_end = 0
        for start, end in view.origins:
            assert start < end
            assert start >= 0 and end <= len(text)
            assert start >= previous_end or start == view.origins[0][0]
            previous_end = max(previous_end, end)

    def test_a_string_of_only_invisibles_yields_an_empty_view(self):
        """The one documented exception to totality.

        No original index is covered, because there is nothing visible to cover
        it with. Safe: forwarding the original forwards a string with no text
        content. Anything *else* producing an empty view would be a bug, which
        is what ``test_building_a_view_never_raises`` checks.
        """
        view = build_detection_view(ZWSP * 5)
        assert view.text == ""
        assert view.origins == ()
        assert covered_indices(view) == set()

    def test_folded_view_shares_indices_with_the_view(self):
        view = build_detection_view("120З85 and Аcme")
        assert len(view.folded) == len(view.text) == len(view.origins)


class TestSpanMapping:
    def test_a_span_over_stripped_characters_expands_to_include_them(self):
        """Replacement must remove the invisibles with the digits.

        Leaving them beside the token would emit ``<TOKEN>​`` and tell an
        attacker their insertion survived.
        """
        text = f"12{ZWSP}34"
        view = build_detection_view(text)
        assert view.text == "1234"
        start, end = view.map_span(0, 4)
        assert text[start:end] == text, "the mapped span must swallow the ZWSP"

    def test_a_span_over_an_expanded_ligature_maps_to_one_character(self):
        text = "ﬁle"
        view = build_detection_view(text)
        assert view.text == "file"
        start, end = view.map_span(0, 2)  # "fi" in the view
        assert (start, end) == (0, 1)
        assert text[start:end] == "ﬁ"

    @pytest.mark.parametrize("bounds", [(-1, 2), (0, 0), (3, 2), (0, 99)])
    def test_out_of_range_spans_raise_rather_than_clamp(self, bounds):
        """A silently adjusted span is a silently wrong span."""
        view = build_detection_view("abc")
        with pytest.raises(SpanMappingError):
            view.map_span(*bounds)

    def test_round_trip_accepts_a_faithful_span(self):
        view = build_detection_view("Kods 120385-12342 beigas")
        assert view.verify_round_trip(5, 17)

    def test_round_trip_accepts_a_folded_span(self):
        """The check compares on the folded view.

        Requiring the *unfolded* text to match would reject exactly the
        homoglyph case the folding exists to catch.
        """
        text = "Kods 120З85-12342 beigas"
        view = build_detection_view(text)
        assert view.folded[5:17] == "120385-12342"
        assert view.verify_round_trip(5, 17)


# ---------------------------------------------------------------------------
# Confusable folding
# ---------------------------------------------------------------------------


class TestFolding:
    def test_folding_is_length_preserving(self):
        """The property the whole single-map design rests on."""
        for source, target in CONFUSABLE_MAP.items():
            assert len(source) == 1 and len(target) == 1

    @given(text=st.text(max_size=200))
    @SLOW
    def test_folding_never_changes_length(self, text):
        assert len(fold_confusables(text)) == len(text)

    @pytest.mark.parametrize("word", BALTIC_WORDS)
    def test_baltic_diacritics_are_never_folded(self, word):
        """Folding these would corrupt the text this product exists to handle."""
        assert fold_confusables(word) == word

    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            ("120З85", "120385"),
            ("Аcme", "Acme"),
            ("рaypal", "paypal"),
            ("120385–12342", "120385-12342"),  # en dash
            ("120385‐12342", "120385-12342"),  # U+2010 hyphen
        ],
    )
    def test_known_confusables_fold(self, source, expected):
        assert fold_confusables(source) == expected

    def test_ascii_is_a_fixed_point(self):
        ascii_text = "".join(chr(c) for c in range(32, 127))
        assert fold_confusables(ascii_text) == ascii_text


# ---------------------------------------------------------------------------
# Screening
# ---------------------------------------------------------------------------


class TestScreening:
    def test_bidi_controls_block(self):
        result = screen_text(f"transfer {RLO}1000{LRI} EUR")
        assert result.is_blocking
        assert result.blocking == REASON_BIDI
        with pytest.raises(SuspiciousEncodingError) as caught:
            result.raise_if_blocking()
        assert caught.value.reason == REASON_BIDI

    def test_a_blocking_error_carries_no_content(self):
        secret = "SECRET-CANARY-VALUE"
        result = screen_text(f"{secret} {RLO}x")
        with pytest.raises(SuspiciousEncodingError) as caught:
            result.raise_if_blocking()
        assert secret not in str(caught.value)
        assert secret not in repr(caught.value)

    def test_dense_invisibles_block(self):
        padded = ZWSP.join("120385123420")
        result = screen_text(padded)
        assert result.is_blocking
        assert result.blocking == REASON_INVISIBLE

    def test_one_soft_hyphen_in_ordinary_prose_does_not_block(self):
        text = f"An ordinary sentence with a soft{SOFT_HYPHEN}hyphen in it."
        result = screen_text(text)
        assert not result.is_blocking
        assert result.signals[REASON_INVISIBLE] == 1

    def test_a_short_string_is_not_judged_by_ratio(self):
        """Two characters with one invisible is 50% and entirely innocent."""
        assert not screen_text(f"a{ZWNJ}").is_blocking

    def test_confusables_are_signalled_but_do_not_block(self):
        """Folding protects the value; blocking would only refuse the customer."""
        result = screen_text("Kods 120З85-12342")
        assert not result.is_blocking
        assert result.signals[REASON_CONFUSABLE] == 1

    def test_mixed_script_is_signalled_and_off_by_default(self):
        result = screen_text("pаypal")  # Cyrillic а inside a Latin word
        assert result.signals[REASON_MIXED_SCRIPT] == 1
        assert not result.is_blocking

    def test_mixed_script_blocks_when_the_operator_opts_in(self):
        result = screen_text("pаypal", block_mixed_script=True)
        assert result.is_blocking
        assert result.blocking == REASON_MIXED_SCRIPT

    @pytest.mark.parametrize("word", BALTIC_WORDS)
    def test_baltic_words_are_single_script(self, word):
        assert mixed_script_words(word) == 0
        assert not screen_text(word, block_mixed_script=True).is_blocking

    def test_a_wholly_cyrillic_sentence_is_not_mixed(self):
        """Russian text is one script. It is not an attack."""
        assert mixed_script_words("Это обычное предложение") == 0

    def test_digits_and_punctuation_are_script_neutral(self):
        assert script_of("5") is None
        assert script_of("-") is None
        assert script_of(" ") is None
        assert script_of("a") == "LATIN"
        assert script_of("а") == "CYRILLIC"
        assert script_of("ā") == "LATIN", "diacritics do not change script"

    def test_contract_references_are_not_mixed_script(self):
        assert mixed_script_words("Contract LV-2026-0042 signed") == 0


class TestIgnorableClassification:
    @pytest.mark.parametrize("ch", [ZWSP, ZWNJ, SOFT_HYPHEN, "﻿", RLO])
    def test_invisible_characters_are_ignorable(self, ch):
        assert is_ignorable(ch)

    @pytest.mark.parametrize("ch", ["a", " ", "\t", "\n", "\r", "ā", "5", "З"])
    def test_visible_and_layout_characters_are_kept(self, ch):
        assert not is_ignorable(ch)

    def test_newlines_survive_the_view(self):
        """Prompts are multi-line. Dropping newlines would mangle every one."""
        view = build_detection_view("line one\nline two")
        assert view.text == "line one\nline two"


# ---------------------------------------------------------------------------
# The two properties ADR-0015 names as the main mitigations
# ---------------------------------------------------------------------------


CTX = RequestContext("tenant-a", "conv-1", "req-1", "key-1")


@given(
    text=st.text(
        alphabet=st.characters(
            blacklist_categories=("Cs",),
            max_codepoint=0x2FFF,
        ),
        max_size=120,
    )
)
@SLOW
def test_text_with_no_detections_is_forwarded_byte_identical(text):
    """SI-17, as a universal statement.

    ADR-0015 calls this the single property most likely to catch a plausible
    offset-map bug: with no spans to replace, the transformation stage must be
    the identity function on the original.
    """
    from gateway.transformations.tokens import TokenMinter
    from gateway.vault.store import KeyRing, SurrogateVault

    vault = SurrogateVault(key_ring=KeyRing(keys={1: b"\x01" * 32}, active_version=1))
    transformer = TransformationEngine(TokenMinter(b"\x02" * 32), vault)

    result = transformer.transform(CTX, text, [], TokenProvenance())
    assert result.text == text


@given(
    prefix=st.text(alphabet="abcdefghijklmnopqrstuvwxyz ", max_size=30),
    value=st.text(alphabet="ghijklmnopqrstuwxyz", min_size=1, max_size=20),
    suffix=st.text(alphabet="abcdefghijklmnopqrstuvwxyz ", max_size=30),
)
@SLOW
def test_replace_then_reverse_reproduces_the_original(prefix, value, suffix):
    """Round-trip over the real transform/restore pair, on original coordinates."""
    from gateway.transformations.tokens import TokenMinter
    from gateway.vault.store import KeyRing, SurrogateVault

    vault = SurrogateVault(key_ring=KeyRing(keys={1: b"\x01" * 32}, active_version=1))
    minter = TokenMinter(b"\x02" * 32)
    transformer = TransformationEngine(minter, vault)
    restorer = RestorationEngine(vault)

    text = prefix + value + suffix
    span = Span(len(prefix), len(prefix) + len(value), "CUSTOM", value)
    provenance = TokenProvenance()

    transformed = transformer.transform(CTX, text, [span], provenance)
    assert restorer.restore(CTX, transformed.text, provenance).text == text


@given(text=st.text(max_size=200))
@SLOW
def test_building_a_view_never_raises(text):
    """The view is built on attacker-controlled input. It must be total.

    Totality has exactly one exception, and this asserts it positively rather
    than skipping it: when the view is empty, the original must contain no
    visible characters at all. That case is sound -- there is nothing to detect
    because there is nothing there -- but it is the kind of exception that
    should be checked, not assumed.
    """
    view = build_detection_view(text)
    assert len(view.text) == len(view.origins) == len(view.folded)

    if view.text:
        assert covered_indices(view) == set(range(len(text)))
    else:
        assert all(is_ignorable(ch) for ch in text), (
            "an empty view is only legitimate when the input was entirely invisible"
        )


@given(text=st.text(max_size=120))
@SLOW
def test_the_view_is_idempotent_under_rebuilding(text):
    """Viewing the view must not change it further.

    If it did, the round-trip check would reject faithful spans -- it rebuilds a
    view over the mapped original and compares.
    """
    once = build_detection_view(text)
    twice = build_detection_view(once.text)
    assert twice.text == once.text


class TestNormalizationDoesNotBreakDetection:
    """End-to-end: each evasion technique, through the real detector set."""

    @staticmethod
    def _detect(text: str):
        from evals.run_evals import build_predictor

        return build_predictor()(text)

    def test_cyrillic_homoglyph_in_a_personal_code(self):
        spans = self._detect("Kods 120385-12342".replace("3", "З", 1))
        assert any(s.entity_type == "LV_PERSONAL_CODE" for s in spans)

    def test_zero_width_inside_a_personal_code(self):
        spans = self._detect(f"Kods 1203{ZWSP}85-12342")
        assert any(s.entity_type == "LV_PERSONAL_CODE" for s in spans)

    def test_fullwidth_digits(self):
        fullwidth = "".join(chr(0xFF10 + int(c)) if c.isdigit() else c for c in "120385-12342")
        spans = self._detect(f"Kods {fullwidth}")
        assert any(s.entity_type == "LV_PERSONAL_CODE" for s in spans)

    def test_en_dash_instead_of_hyphen(self):
        """A customer pasting from a word processor, not an attacker."""
        spans = self._detect("Kods 120385–12342")
        assert any(s.entity_type == "LV_PERSONAL_CODE" for s in spans)

    def test_zero_width_inside_an_email(self):
        spans = self._detect(f"Mail ali{ZWSP}ce@acme.lv now")
        assert any(s.entity_type == "EMAIL_ADDRESS" for s in spans)

    def test_the_mapped_span_covers_the_evasion_characters(self):
        text = f"Kods 1203{ZWSP}85-12342 beigas"
        spans = [s for s in self._detect(text) if s.entity_type == "LV_PERSONAL_CODE"]
        assert spans
        assert ZWSP in text[spans[0].start : spans[0].end]

    @pytest.mark.parametrize("word", BALTIC_WORDS)
    def test_baltic_words_produce_no_detections(self, word):
        """The negative control for the whole feature."""
        assert self._detect(f"Klients {word} zvanīja.") == []

    def test_decomposed_and_precomposed_baltic_text_behave_alike(self):
        precomposed = "Bērziņa"
        decomposed = unicodedata.normalize("NFD", precomposed)
        assert precomposed != decomposed
        assert self._detect(precomposed) == self._detect(decomposed) == []
