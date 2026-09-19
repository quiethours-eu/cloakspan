"""Baltic and international telephone number recognition.

Deterministic, and deliberately conservative. A phone recogniser is the easiest
detector in this product to get wrong in the direction that makes customers turn
it off: any run of 7-11 digits looks like a phone number, and prompts are full of
order numbers, part numbers, timestamps, and quantities.

## The rule

A number is detected only when **one** of these holds:

1. It carries an explicit country code (``+371``, ``+370``, ``+372``, or any
   E.164 ``+CC``) **and** the national significant number is the right length
   for that country.
2. It is in a national format **and** a phone context word appears within a
   short window before it -- ``tālr.``, ``tel.``, ``mob.``, ``phone``, and the
   Lithuanian/Estonian equivalents.

Rule 2 exists because "27 123 456" is a phone number in a Latvian signature
block and a quantity in an invoice line, and nothing in the digits distinguishes
them. Requiring the context word costs recall on unlabelled numbers and buys the
precision that keeps the detector switched on.

There is no checksum to lean on here, unlike personal codes and IBANs. Length
and prefix validity are all the structure the numbering plans give us, so
context does the rest of the work.

## What this is not

Not libphonenumber. It covers the three Baltic numbering plans plus a generic
E.164 shape, and it does not attempt carrier lookup, region inference, or
validation of every national plan on earth. That is the right scope for v1 and
the wrong scope to claim more than.
"""

from __future__ import annotations

import re

from gateway.domain import Confidence, Span

#: National numbering plans we validate by length and leading digit.
#: (country code, allowed leading digits, national significant number length)
_PLANS = {
    "371": (("2", "6", "8"), 8),  # Latvia: 2x mobile, 6x fixed, 8x service
    "370": (("6", "3", "4", "5", "7", "8"), 8),  # Lithuania
    "372": (("5", "3", "4", "6", "7", "8"), (7, 8)),  # Estonia: 7 or 8 digits
}

#: Context words that license a national-format match. Lower-cased comparison,
#: so the Baltic diacritics here must be exactly as they are typed.
_CONTEXT_WORDS = (
    "tālr",
    "talr",
    "tālrunis",
    "tel",
    "telefon",
    "telefonas",
    "telefon nr",
    "mob",
    "mobilais",
    "mobile",
    "phone",
    "call",
    "zvaniet",
    "skambinkite",
    "helista",
)

#: How far back to look for a context word. Long enough for "Telefona numurs:",
#: short enough that a context word two sentences away does not license a match.
_CONTEXT_WINDOW = 24

# +371 20 123 456 / +37120123456 / +371-2012-3456
_INTERNATIONAL = re.compile(r"\+(\d{1,3})[\s.\-]?((?:\d[\s.\-]?){6,14}\d)")

# National form: 7-8 digits, optionally grouped. Anchored on non-digit
# boundaries so it cannot bite a chunk out of a longer number.
_NATIONAL = re.compile(r"(?<![\d+])(\d(?:[\s.\-]?\d){6,7})(?![\d])")


def _digits(text: str) -> str:
    return re.sub(r"[\s.\-]", "", text)


def _plan_allows(country_code: str, national: str) -> bool:
    plan = _PLANS.get(country_code)
    if plan is None:
        # Some other country. Accept a plausible E.164 length and let the
        # explicit "+" carry the confidence -- a leading + is a strong signal
        # that the author meant a telephone number.
        return 7 <= len(national) <= 15
    leading, lengths = plan
    allowed = lengths if isinstance(lengths, tuple) else (lengths,)
    return len(national) in allowed and national.startswith(leading)


def _has_context(text: str, start: int) -> bool:
    window = text[max(0, start - _CONTEXT_WINDOW) : start].lower()
    return any(word in window for word in _CONTEXT_WORDS)


def _national_plan_match(national: str) -> bool:
    """Does this bare national number fit any Baltic plan?"""
    return any(
        len(national) in ((lengths,) if isinstance(lengths, int) else lengths)
        and national.startswith(leading)
        for leading, lengths in _PLANS.values()
    )


class PhoneNumberDetector:
    """Detects telephone numbers in Baltic and international formats."""

    name = "phone_number"
    uses_folded_view = True
    entity_type = "PHONE_NUMBER"

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        claimed: list[tuple[int, int]] = []

        for match in _INTERNATIONAL.finditer(text):
            country_code, rest = match.group(1), _digits(match.group(2))
            if not _plan_allows(country_code, rest):
                continue
            spans.append(
                Span(
                    start=match.start(),
                    end=match.end(),
                    entity_type=self.entity_type,
                    text=match.group(0),
                    # An explicit country code plus a valid national length is
                    # about as certain as a number without a checksum gets.
                    score=Confidence.CERTAIN.value,
                    detector=self.name,
                )
            )
            claimed.append((match.start(), match.end()))

        for match in _NATIONAL.finditer(text):
            if any(start <= match.start() < end for start, end in claimed):
                continue
            national = _digits(match.group(1))
            if not _national_plan_match(national):
                continue
            if not _has_context(text, match.start()):
                # Structurally a phone number, but so is an order reference.
                # Without a context word we decline rather than guess.
                continue
            spans.append(
                Span(
                    start=match.start(),
                    end=match.end(),
                    entity_type=self.entity_type,
                    text=match.group(1),
                    # HIGH, not CERTAIN: the context word could belong to a
                    # neighbouring clause.
                    score=Confidence.HIGH.value,
                    detector=self.name,
                )
            )

        return spans
