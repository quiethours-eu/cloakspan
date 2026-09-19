"""Latvian, Lithuanian, and Estonian personal identity code recognizers.

These do not exist in Presidio. They are a core piece of our differentiation in
the Baltic market, and they are exactly the kind of detector that *must* use a
checksum: a bare 11-digit regex fires on order numbers, timestamps, and phone
numbers, and a false positive here means we pseudonymise something harmless and
degrade the model's answer for no reason.

Every algorithm below is a published national identifier specification, verified
against the documented check-digit rules. `REQUIRES_PRODUCTION_VALIDATION`:
the eval suite under evals/datasets/ carries known-valid and known-invalid
samples for each country, and precision/recall are reported per release.
"""

from __future__ import annotations

import re

from gateway.domain import Confidence, Span

# --------------------------------------------------------------------------
# Latvia
# --------------------------------------------------------------------------
# Two forms coexist:
#   * Legacy DDMMYY-XXXXX (birth-date based), with a check digit.
#   * Post-2017 "32xxxx-xxxxx" form, which carries NO date and, per the
#     national specification, is NOT checksum-validated the same way.
# We treat them differently rather than pretending one rule covers both.
_LV_PATTERN = re.compile(r"\b(\d{6})-(\d{5})\b")

#: The same code with the hyphen dropped. This is the form that comes out of
#: database extracts, CSV exports, and ERP screens, so it is at least as common
#: in a real prompt as the printed form -- and it was previously missed
#: entirely.
#:
#: Unlike the hyphenated form it is **not** structurally distinct: eleven digits
#: is also the Lithuanian and Estonian shape. Disambiguation is in
#: `_plain_code_label`.
_LV_PLAIN_PATTERN = re.compile(r"\b(\d{11})\b")

_LV_WEIGHTS = (1, 6, 3, 7, 9, 10, 5, 8, 4, 2)


def _lv_check_digit_valid(digits: str) -> bool:
    """Validate the Latvian legacy personal code check digit.

    Check digit = (1101 - sum(d_i * w_i)) mod 11 mod 10.
    """
    if len(digits) != 11 or not digits.isdigit():
        return False
    total = sum(int(digits[i]) * _LV_WEIGHTS[i] for i in range(10))
    expected = (1101 - total) % 11 % 10
    return expected == int(digits[10])


def _plausible_ddmmyy(ddmmyy: str) -> bool:
    day, month = int(ddmmyy[0:2]), int(ddmmyy[2:4])
    return 1 <= day <= 31 and 1 <= month <= 12


def detect_lv_personal_code(text: str) -> list[Span]:
    spans: list[Span] = []
    for match in _LV_PATTERN.finditer(text):
        first, second = match.group(1), match.group(2)
        digits = first + second

        if first.startswith("32"):
            # Post-2017 non-date form. No usable date check and the checksum
            # rule does not apply, so we report it at lower confidence rather
            # than claiming certainty we do not have.
            spans.append(
                Span(
                    start=match.start(),
                    end=match.end(),
                    entity_type="LV_PERSONAL_CODE",
                    text=match.group(0),
                    score=Confidence.MEDIUM.value,
                    detector="lv_personal_code",
                )
            )
            continue

        if not _plausible_ddmmyy(first):
            continue
        if not _lv_check_digit_valid(digits):
            continue

        spans.append(
            Span(
                start=match.start(),
                end=match.end(),
                entity_type="LV_PERSONAL_CODE",
                text=match.group(0),
                score=Confidence.CERTAIN.value,
                detector="lv_personal_code",
            )
        )
    return spans


# --------------------------------------------------------------------------
# Lithuania and Estonia -- asmens kodas / isikukood
# --------------------------------------------------------------------------
# One implementation, because the two are genuinely the same construction:
# 11 digits G YYMMDD NNN C, leading digit 1-6, and the *same* two-pass ISO
# 7064-style check digit. That is not a simplification on our part -- it is
# what the two published national specifications say, and it is why a valid
# Lithuanian code is always a valid Estonian one.
#
# Two identical implementations sitting side by side was itself a smell: it
# looked like two independent validations agreeing, when in fact there was only
# ever one rule.
_BALTIC_PATTERN = re.compile(r"\b([1-6]\d{10})\b")
_BALTIC_WEIGHTS_1 = (1, 2, 3, 4, 5, 6, 7, 8, 9, 1)
_BALTIC_WEIGHTS_2 = (3, 4, 5, 6, 7, 8, 9, 1, 2, 3)

_BALTIC_CENTURY = {1: 1800, 2: 1800, 3: 1900, 4: 1900, 5: 2000, 6: 2000}

#: How far back to look for the identifier's own name. Long enough for
#: "Kliento Jonas Petraitis asmens kodas yra", short enough that a term
#: belonging to a different sentence does not claim this number.
_LOCAL_WINDOW = 64

#: The strongest signal available, and the reason context works at all: a
#: document containing a personal code almost always *names* it, and it names it
#: in the language of the country that issued it. Substrings rather than whole
#: words, to cover the case endings both languages inflect through
#: (kodas/kodą/kodo, isikukood/isikukoodi).
_LOCAL_TERMS: dict[str, tuple[str, ...]] = {
    "LT": ("asmens kod", "asmenskod", "a.k.", "a. k."),
    "EE": ("isikukood",),
}

#: Weaker, document-scope signals. Used only when the identifier is not named,
#: and only when exactly one country is indicated.
_DOCUMENT_MARKERS: dict[str, tuple[re.Pattern[str], ...]] = {
    "LT": (
        re.compile(r"\blietuv", re.IGNORECASE),  # Lietuva, lietuvių, Lietuvos
        re.compile(r"\blithuania", re.IGNORECASE),
        # Stems, not nominatives. Both languages inflect place names heavily --
        # "Vilnius" appears as "Vilniaus", "Vilniuje", "Vilniun" -- and matching
        # only the dictionary form misses most real sentences. Caught by
        # `test_document_markers_attribute_an_unnamed_code` on "iš Vilniaus".
        re.compile(r"\b(vilni|kaun|klaipėd|šiauli|panevėž)", re.IGNORECASE),
        re.compile(r"\+370\b"),
        re.compile(r"\bLT\d{2}[A-Z0-9]{11,30}\b"),  # Lithuanian IBAN
        re.compile(r"\.lt\b", re.IGNORECASE),
    ),
    "EE": (
        re.compile(r"\beesti\b", re.IGNORECASE),
        re.compile(r"\bestonia", re.IGNORECASE),
        re.compile(r"\b(tallinn|tartu|pärnu|narva|jõgeva)", re.IGNORECASE),
        re.compile(r"\+372\b"),
        re.compile(r"\bEE\d{2}[A-Z0-9]{11,30}\b"),  # Estonian IBAN
        re.compile(r"\.ee\b", re.IGNORECASE),
    ),
}


#: Latvian context signals, kept separate from `_LOCAL_TERMS` and
#: `_DOCUMENT_MARKERS` on purpose.
#:
#: Those two drive `infer_country`, which answers "LT or EE?" for a code that is
#: already known to be LT/EE-shaped. Adding an "LV" entry there would let that
#: function return LV for a genuinely Lithuanian code that happens to appear in
#: a document mentioning Rīga -- a Latvian company's Lithuanian client is an
#: ordinary situation, not an exotic one. These signals answer a different
#: question, so they get their own names.
_LV_LOCAL_TERMS = ("personas kod", "personas kods", "p.k.", "p. k.")

_LV_DOCUMENT_MARKERS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\blatvij", re.IGNORECASE),  # Latvija, Latvijas, Latvijā
    re.compile(r"\blatvia", re.IGNORECASE),
    # Stems again, for the same reason as the Lithuanian and Estonian cities:
    # Latvian inflects place names heavily (Rīga, Rīgas, Rīgā).
    re.compile(r"\b(rīg|rig|liepāj|liepaj|daugavpil|jelgav|ventspil|jūrmal|jurmal)", re.IGNORECASE),
    re.compile(r"\+371\b"),
    re.compile(r"\bLV\d{2}[A-Z0-9]{11,30}\b"),  # Latvian IBAN
    re.compile(r"\.lv\b", re.IGNORECASE),
)


def _indicates_latvia(text: str, start: int) -> bool:
    """Whether the context around ``start`` points at Latvia.

    Same two scopes as `infer_country`: the identifier's own name nearby, then
    document-wide markers.
    """
    window = text[max(0, start - _LOCAL_WINDOW) : start].lower()
    if any(term in window for term in _LV_LOCAL_TERMS):
        return True
    return any(pattern.search(text) for pattern in _LV_DOCUMENT_MARKERS)


def _baltic_check_digit_valid(digits: str) -> bool:
    """Two-pass mod-11. Identical for Lithuania and Estonia."""
    total = sum(int(digits[i]) * _BALTIC_WEIGHTS_1[i] for i in range(10))
    remainder = total % 11
    if remainder == 10:
        total = sum(int(digits[i]) * _BALTIC_WEIGHTS_2[i] for i in range(10))
        remainder = total % 11
        if remainder == 10:
            remainder = 0
    return remainder == int(digits[10])


def _baltic_date_valid(digits: str) -> bool:
    if int(digits[0]) not in _BALTIC_CENTURY:
        return False
    month, day = int(digits[3:5]), int(digits[5:7])
    return 1 <= month <= 12 and 1 <= day <= 31


def infer_country(text: str, start: int) -> str | None:
    """Which country issued the code at ``start``, or None if undecidable.

    Two scopes, checked in order of how much they prove:

    1. **Local** -- the identifier's own name within the preceding window.
       Decisive, and it survives a document containing codes from both
       countries, because each number is judged by the term next to it.
    2. **Document** -- country names, cities, dialling codes, IBAN prefixes,
       TLDs. Used only when the identifier is unnamed, and only when exactly one
       country is indicated.

    Returns None when there is no signal, or when signals conflict. Guessing
    from a coin flip would produce a label that looks authoritative and is wrong
    half the time -- worse than admitting the ambiguity, because a wrong country
    on a personal identifier is the kind of error that ends up in a regulatory
    filing.
    """
    window = text[max(0, start - _LOCAL_WINDOW) : start].lower()

    # Nearest term wins, not "the set of terms present". In a document listing
    # an Estonian client and then a Lithuanian one, the second code's window
    # still contains the first client's "isikukood" -- and treating that as a
    # conflict would refuse to label a number whose own term sits three words
    # away. The term immediately preceding a number is the one naming it.
    # Found by `test_two_codes_in_one_document_are_judged_independently`.
    nearest: tuple[int, str] | None = None
    for country, terms in _LOCAL_TERMS.items():
        for term in terms:
            position = window.rfind(term)
            if position != -1 and (nearest is None or position > nearest[0]):
                nearest = (position, country)
    if nearest is not None:
        return nearest[1]

    document = {
        country
        for country, patterns in _DOCUMENT_MARKERS.items()
        if any(pattern.search(text) for pattern in patterns)
    }
    if len(document) == 1:
        return document.pop()
    return None


def _plain_code_label(text: str, start: int, digits: str) -> str | None:
    """Label an unhyphenated 11-digit code, or None to leave it to LT/EE.

    The two national constructions overlap in this form, and the check digits do
    not settle it: a Latvian code can satisfy the Lithuanian/Estonian rule as
    well, and roughly one in eleven does. So the decision runs in order of how
    much each signal proves:

    1. **Only the Latvian rule accepts the digits.** Then it is Latvian. The
       Lithuanian/Estonian detector will not claim it, because its own
       validation fails.
    2. **Both rules accept the digits, and context names LT or EE.** Yield --
       `detect_baltic_personal_code` will label it, and it has the better
       evidence.
    3. **Both rules accept, and context points at Latvia.** Label it Latvian.
    4. **Both rules accept, and nothing points anywhere.** Yield, which produces
       `BALTIC_PERSONAL_CODE`. That is the honest label, and the default policy
       routes it locally regardless -- the ambiguity costs a name, not
       protection.

    The hyphenated form never reaches this function: it is structurally
    unambiguous and is handled by `detect_lv_personal_code`.
    """
    if not _plausible_ddmmyy(digits[:6]) or not _lv_check_digit_valid(digits):
        return None
    if not (_baltic_date_valid(digits) and _baltic_check_digit_valid(digits)):
        return "LV_PERSONAL_CODE"
    if infer_country(text, start) is not None:
        return None
    if _indicates_latvia(text, start):
        return "LV_PERSONAL_CODE"
    return None


def detect_lv_personal_code_plain(text: str) -> list[Span]:
    """Detect Latvian personal codes written without the hyphen."""
    spans: list[Span] = []
    for match in _LV_PLAIN_PATTERN.finditer(text):
        label = _plain_code_label(text, match.start(), match.group(1))
        if label is None:
            continue
        spans.append(
            Span(
                start=match.start(),
                end=match.end(),
                entity_type=label,
                text=match.group(1),
                score=Confidence.CERTAIN.value,
                detector="lv_personal_code_plain",
            )
        )
    return spans


def detect_baltic_personal_code(text: str) -> list[Span]:
    """Detect LT/EE personal codes, labelling by country where context allows.

    Emits ``LT_PERSONAL_CODE`` or ``EE_PERSONAL_CODE`` when the country is
    determinable, and ``BALTIC_PERSONAL_CODE`` when it is not.
    """
    spans: list[Span] = []
    for match in _BALTIC_PATTERN.finditer(text):
        digits = match.group(1)
        if not _baltic_date_valid(digits) or not _baltic_check_digit_valid(digits):
            continue

        country = infer_country(text, match.start())
        entity_type = f"{country}_PERSONAL_CODE" if country else "BALTIC_PERSONAL_CODE"

        spans.append(
            Span(
                start=match.start(),
                end=match.end(),
                entity_type=entity_type,
                text=digits,
                # CERTAIN even when the country is unknown. The checksum makes
                # the *detection* certain; only the *label* is uncertain, and
                # scoring the ambiguous case lower would let a policy with a
                # `min_score` filter skip it -- losing protection over a naming
                # question.
                score=Confidence.CERTAIN.value,
                detector="baltic_personal_code",
            )
        )
    return spans


class BalticPersonalCodeDetector:
    """Detects LV, LT, and EE personal identity codes.

    Latvian codes in the printed form ``DDMMYY-XXXXX`` are structurally
    distinct and never ambiguous.

    Written **without** the hyphen -- the form database extracts and ERP exports
    produce -- they are eleven digits, which is also the Lithuanian and Estonian
    shape. `_plain_code_label` decides those, and this class drops the LT/EE
    span wherever the Latvian reading wins, because two spans over the same
    offsets would otherwise be resolved by `resolve_conflicts` on an
    alphabetical tiebreak rather than on the evidence.

    Lithuanian and Estonian codes are the same construction with the same check
    digit, so the digits alone cannot say which country issued one. Rather than
    letting conflict resolution pick a winner alphabetically -- which labelled
    every Lithuanian code as Estonian, and was measured doing exactly that on
    both the dev and holdout splits -- the recogniser reads the surrounding
    context and falls back to ``BALTIC_PERSONAL_CODE`` when it genuinely cannot
    tell.

    The default policy routes all four labels to the local model, so an
    ambiguous label never costs protection. See docs/entity-taxonomy.md.
    """

    name = "baltic_personal_codes"
    uses_folded_view = True

    def detect(self, text: str) -> list[Span]:
        hyphenated = detect_lv_personal_code(text)
        plain = detect_lv_personal_code_plain(text)

        claimed = {(span.start, span.end) for span in plain}
        baltic = [
            span
            for span in detect_baltic_personal_code(text)
            if (span.start, span.end) not in claimed
        ]
        return hyphenated + plain + baltic
