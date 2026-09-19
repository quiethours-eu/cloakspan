"""Screening for encodings that exist to deceive a reader.

Separate from the detection view on purpose. The view's job is to make hidden
text *detectable*; this module's job is to decide whether the encoding itself is
evidence of an attack, independently of whether anything sensitive was found.

## Reason codes, never content

Every finding is a code and a count. A blocked request tells the operator
*which* class of encoding was refused and how many characters were involved, and
tells them nothing about the text -- a log that quoted the payload would make
the attack a way to write attacker-controlled strings into our logs
(SI-11).
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field

#: Bidirectional formatting controls. The Trojan Source class: they reorder how
#: text renders without changing what it contains, so a human reviewer and the
#: model see different things. There is no legitimate use in a prompt that
#: justifies that ambiguity, so this one blocks.
BIDI_CONTROLS = frozenset("‪‫‬‭‮⁦⁧⁨⁩؜‎‏")

#: Above this share of invisible characters, the text is being padded rather
#: than written. A signature block with one soft hyphen is fine; a personal code
#: with a zero-width space between every digit is not.
DEFAULT_IGNORABLE_RATIO = 0.10

#: Below this length the ratio is meaningless -- a two-character string with one
#: soft hyphen is 50% invisible and entirely innocent.
RATIO_MIN_LENGTH = 12

REASON_BIDI = "suspicious_encoding_bidi"
REASON_INVISIBLE = "suspicious_encoding_invisible"
REASON_MIXED_SCRIPT = "suspicious_encoding_mixed_script"
REASON_CONFUSABLE = "suspicious_encoding_confusable"

#: Scripts we resolve. Anything else is treated as its own script by name.
#: Derived from ``unicodedata.name`` rather than a bundled script table: the
#: name prefix is stable, already present in the standard library, and avoids a
#: data file whose version could drift from the confusables table.
_SCRIPT_PREFIXES = (
    "LATIN",
    "CYRILLIC",
    "GREEK",
    "ARABIC",
    "HEBREW",
    "ARMENIAN",
    "GEORGIAN",
    "HAN",
    "HIRAGANA",
    "KATAKANA",
    "HANGUL",
    "THAI",
    "DEVANAGARI",
)


class SuspiciousEncodingError(Exception):
    """The encoding itself is evidence of deception. Fails the request closed."""

    def __init__(self, reason: str, count: int) -> None:
        # Deliberately no content: reason code and count only.
        super().__init__(
            f"request refused: {reason} ({count} character(s)). The content is not logged."
        )
        self.reason = reason
        self.count = count


@dataclass(slots=True)
class ScreeningResult:
    """What screening found. Codes and counts, never text."""

    blocking: str | None = None
    blocking_count: int = 0
    signals: dict[str, int] = field(default_factory=dict)

    @property
    def is_blocking(self) -> bool:
        return self.blocking is not None

    def raise_if_blocking(self) -> None:
        if self.blocking is not None:
            raise SuspiciousEncodingError(self.blocking, self.blocking_count)


def script_of(ch: str) -> str | None:
    """The script of ``ch``, or None when it is script-neutral.

    Digits, punctuation, whitespace, and symbols are neutral: they appear in
    every script and carry no evidence either way. Treating them as a script
    would make every ordinary sentence "mixed".
    """
    if not ch.isalpha():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    for prefix in _SCRIPT_PREFIXES:
        if name.startswith(prefix):
            return prefix
    return name.split(" ", 1)[0]


def _words(text: str):
    """Yield maximal runs of alphanumeric characters."""
    start = None
    for index, ch in enumerate(text):
        if ch.isalnum():
            if start is None:
                start = index
        elif start is not None:
            yield text[start:index]
            start = None
    if start is not None:
        yield text[start:]


def mixed_script_words(text: str) -> int:
    """Count words containing letters from more than one script.

    ``Bērziņa``, ``Šiauliai`` and ``Jõgeva`` are Latin throughout -- the
    diacritics are Latin letters, not a second script -- so they must never
    count. That is the false positive that would block legitimate traffic in the
    exact market this product is for, and it is asserted directly in the tests.
    """
    count = 0
    for word in _words(text):
        scripts = {script_of(ch) for ch in word}
        scripts.discard(None)
        if len(scripts) > 1:
            count += 1
    return count


def screen_text(text: str, *, block_mixed_script: bool = False) -> ScreeningResult:
    """Screen one message for deceptive encoding.

    ``block_mixed_script`` is off by default. See the note below.
    """
    result = ScreeningResult()

    bidi = sum(1 for ch in text if ch in BIDI_CONTROLS)
    if bidi:
        result.signals[REASON_BIDI] = bidi
        result.blocking = REASON_BIDI
        result.blocking_count = bidi
        return result

    invisible = sum(
        1 for ch in text if unicodedata.category(ch) in ("Cf", "Cc") and ch not in "\t\n\r"
    )
    if invisible:
        result.signals[REASON_INVISIBLE] = invisible
        if len(text) >= RATIO_MIN_LENGTH and invisible / len(text) > DEFAULT_IGNORABLE_RATIO:
            result.blocking = REASON_INVISIBLE
            result.blocking_count = invisible
            return result

    from gateway.normalization.confusables import CONFUSABLE_MAP

    confusable = sum(1 for ch in text if ch in CONFUSABLE_MAP)
    if confusable:
        result.signals[REASON_CONFUSABLE] = confusable

    mixed = mixed_script_words(text)
    if mixed:
        result.signals[REASON_MIXED_SCRIPT] = mixed
        if block_mixed_script:
            result.blocking = REASON_MIXED_SCRIPT
            result.blocking_count = mixed

    return result
