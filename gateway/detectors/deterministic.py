"""Deterministic PII detectors with checksum validation where one exists.

Everything here runs with zero heavy dependencies, which is what lets the
Community Edition ship as a small, fast, offline-capable container. Contextual
NER (PERSON, ORG, LOCATION, ADDRESS) requires the optional ``[ner]`` extra and a
locally provisioned model -- see gateway/detectors/ner.py.

Telephone numbers live in recognizers/baltic/phone_numbers.py rather than here,
because they are the one entity in the deterministic set with no checksum: the
recogniser leans on numbering-plan structure plus context words instead, and
that reasoning deserves its own module.
"""

from __future__ import annotations

import re

from gateway.domain import Confidence, Span

_EMAIL = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}(?![\w-])"
)

# IBAN: country code + 2 check digits + up to 30 alphanumerics, optionally
# printed in space-separated groups.
#
# The grouped form is not an edge case: it is how banks print IBANs on
# statements, invoices, and payment instructions, so it is the form most likely
# to appear in a prompt pasted out of a finance system. `iban_valid` has always
# stripped spaces; only the pattern was contiguous, which meant the validator
# was ready for an input the detector could never hand it.
_IBAN = re.compile(r"\b([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30})\b")

# Payment cards: 13-19 digits, contiguous or in a card-shaped grouping.
#
# The previous pattern, `(?:\d[ -]?){12,18}\d`, allowed a separator at *any*
# position, so `20231104-11220` -- an export date-stamp -- matched, and one such
# string in ten also passes Luhn. The holdout split caught exactly that: a
# boundary example asserting "date-like, not a payment card" was reported as a
# card.
#
# Luhn cannot rescue this. It is a transcription check, not an identity check;
# it says a digit string is *well-formed*, not that it is a card. Precision here
# has to come from the shape.
#
# Groupings accepted, which are the ones cards are actually written in:
#   * contiguous              4111111111111111
#   * fours                   4111 1111 1111 1111        (and 4-4-4-4-3 for 19)
#   * Amex                    3782 822463 10005          (4-6-5)
_CARD = re.compile(
    r"\b(?:"
    r"\d{13,19}"
    r"|\d{4}(?:[ -]\d{4}){2,3}(?:[ -]\d{1,3})?"
    r"|\d{4}[ -]\d{6}[ -]\d{5}"
    r")\b"
)

_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)


def luhn_valid(digits: str) -> bool:
    """Standard Luhn (mod-10) checksum, used for payment cards."""
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def iban_valid(iban: str) -> bool:
    """ISO 13616 mod-97 check.

    Move the first four characters to the end, map letters to numbers
    (A=10..Z=35), and require the resulting integer mod 97 to equal 1.
    """
    candidate = iban.replace(" ", "").upper()
    if len(candidate) < 15 or not candidate[:2].isalpha() or not candidate[2:4].isdigit():
        return False
    rearranged = candidate[4:] + candidate[:4]
    digits = []
    for char in rearranged:
        if char.isdigit():
            digits.append(char)
        elif char.isalpha():
            digits.append(str(ord(char) - ord("A") + 10))
        else:
            return False
    try:
        return int("".join(digits)) % 97 == 1
    except ValueError:
        return False


class EmailDetector:
    name = "email"
    uses_folded_view = True

    def detect(self, text: str) -> list[Span]:
        return [
            Span(
                start=m.start(),
                end=m.end(),
                entity_type="EMAIL_ADDRESS",
                text=m.group(0),
                score=Confidence.CERTAIN.value,
                detector=self.name,
            )
            for m in _EMAIL.finditer(text)
        ]


def _longest_valid_iban(candidate: str) -> str | None:
    """Return the longest prefix of ``candidate`` that passes the mod-97 check.

    Allowing spaces makes the pattern greedy across them, so
    ``"LV80 BANK 0000 4351 9500 1 PLEASE PAY BY FRIDAY"`` matches well past the
    IBAN. Rather than making the pattern cleverer -- and more fragile -- we trim
    back to the last group boundary that validates.

    Cut points are restricted to group boundaries (a space, or the end of the
    match). Trimming at arbitrary offsets would let the search land on a shorter
    string that passes mod-97 by luck, roughly 1 in 97 attempts, and report a
    sliced-in-half account number as an IBAN.
    """
    boundaries = [
        index
        for index in range(1, len(candidate) + 1)
        if index == len(candidate) or candidate[index] == " "
    ]
    for end in reversed(boundaries):
        prefix = candidate[:end]
        if iban_valid(prefix):
            return prefix
    return None


class IbanDetector:
    name = "iban"
    uses_folded_view = True

    def detect(self, text: str) -> list[Span]:
        spans = []
        for m in _IBAN.finditer(text):
            valid = _longest_valid_iban(m.group(1))
            if valid is None:
                continue
            start = m.start(1)
            spans.append(
                Span(
                    start=start,
                    end=start + len(valid),
                    entity_type="IBAN",
                    text=valid,
                    score=Confidence.CERTAIN.value,
                    detector=self.name,
                )
            )
        return spans


class PaymentCardDetector:
    """Luhn-validated payment card numbers.

    The Luhn check is what makes this usable. Without it, the pattern fires on
    any 13-19 digit run -- order numbers, timestamps, concatenated IDs -- and
    the customer disables the detector.
    """

    name = "payment_card"
    uses_folded_view = True

    def detect(self, text: str) -> list[Span]:
        spans = []
        for m in _CARD.finditer(text):
            raw = m.group(0)
            digits = re.sub(r"[ -]", "", raw)
            if not luhn_valid(digits):
                continue
            spans.append(
                Span(
                    start=m.start(),
                    end=m.end(),
                    entity_type="PAYMENT_CARD",
                    text=raw,
                    score=Confidence.CERTAIN.value,
                    detector=self.name,
                )
            )
        return spans


class IpAddressDetector:
    """IPv4 addresses.

    Scored MEDIUM, not CERTAIN: many IPs in prompts are documentation examples
    or private-range addresses that carry no personal data. Policy decides
    whether MEDIUM is enough to act on.
    """

    name = "ip_address"
    uses_folded_view = True

    def detect(self, text: str) -> list[Span]:
        return [
            Span(
                start=m.start(),
                end=m.end(),
                entity_type="IP_ADDRESS",
                text=m.group(0),
                score=Confidence.MEDIUM.value,
                detector=self.name,
            )
            for m in _IPV4.finditer(text)
        ]


def default_detectors() -> list[object]:
    """The zero-dependency detector set enabled by default."""
    from recognizers.baltic.personal_codes import BalticPersonalCodeDetector
    from recognizers.baltic.phone_numbers import PhoneNumberDetector
    from recognizers.secrets.detectors import SecretDetector

    return [
        SecretDetector(),
        EmailDetector(),
        BalticPersonalCodeDetector(),
        PhoneNumberDetector(),
        IbanDetector(),
        PaymentCardDetector(),
        IpAddressDetector(),
    ]
