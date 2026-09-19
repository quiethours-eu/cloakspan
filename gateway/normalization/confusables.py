"""Confusable folding — a pinned, curated, strictly 1:1 character map.

## Why this is not UTS #39

The Unicode confusables table maps some characters to *multi-character*
sequences (``œ`` → ``oe``). Supporting that would make the folded view a
different length from the view it is derived from, which means a second offset
map, composed with the first, on the most correctness-critical path in the
product.

The evasion we are actually defending against does not need it. An attacker
hiding a Latvian personal code swaps ASCII digits and letters for
visually identical Cyrillic or Greek ones; every such substitution is 1:1. So
this map is **restricted to 1:1 by construction**, verified at import, and the
folded view shares indices with its source exactly. No second map, no
composition, no class of offset bug.

Multi-character confusables are therefore **not** folded. That is a stated
limitation, not an oversight: ``œ`` and ``oe`` are not confusable in any
identifier this product detects, and buying that coverage with a second offset
map would be a bad trade.

## Why the table is in the repository

Not loaded from ICU, not fetched, not derived from whatever ``unicodedata``
version the base image happens to carry. Detection output is evidence a customer
shows a regulator, and a detection surface that changes when a base image is
rebuilt is not evidence. Pinned here, reviewable in a diff.

## What is deliberately absent

No fold from Baltic diacritics to bare Latin. ``ā ē ī ū č ģ ķ ļ ņ š ž ą ę ė į ų
õ ä ö ü`` are ordinary letters in the languages this product is for, they are
already Latin script, and folding them would corrupt the very text we exist to
handle. Asserted by ``test_baltic_diacritics_are_never_folded``.
"""

from __future__ import annotations

#: Cyrillic characters that are visually identical to Latin or ASCII digits.
_CYRILLIC = {
    "а": "a",  # а CYRILLIC SMALL LETTER A
    "е": "e",  # е CYRILLIC SMALL LETTER IE
    "о": "o",  # о CYRILLIC SMALL LETTER O
    "р": "p",  # р CYRILLIC SMALL LETTER ER
    "с": "c",  # с CYRILLIC SMALL LETTER ES
    "у": "y",  # у CYRILLIC SMALL LETTER U
    "х": "x",  # х CYRILLIC SMALL LETTER HA
    "і": "i",  # і CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "ј": "j",  # ј CYRILLIC SMALL LETTER JE
    "һ": "h",  # һ CYRILLIC SMALL LETTER SHHA
    "А": "A",  # А
    "В": "B",  # В
    "Е": "E",  # Е
    "К": "K",  # К
    "М": "M",  # М
    "Н": "H",  # Н
    "О": "O",  # О
    "Р": "P",  # Р
    "С": "C",  # С
    "Т": "T",  # Т
    "Х": "X",  # Х
    "Ѕ": "S",  # Ѕ
    "І": "I",  # І
    "Ј": "J",  # Ј
    # Digit lookalikes. These are the ones that matter for identifiers.
    "З": "3",  # З CYRILLIC CAPITAL LETTER ZE
    "з": "3",  # з CYRILLIC SMALL LETTER ZE
    "Ӏ": "1",  # Ӏ CYRILLIC LETTER PALOCHKA
    "Л": "N",  # Л -- weak, but seen in practice
}

#: Greek characters confusable with Latin.
_GREEK = {
    "α": "a",  # α
    "ο": "o",  # ο
    "ρ": "p",  # ρ
    "ν": "v",  # ν
    "υ": "u",  # υ
    "Α": "A",  # Α
    "Β": "B",  # Β
    "Ε": "E",  # Ε
    "Ζ": "Z",  # Ζ
    "Η": "H",  # Η
    "Ι": "I",  # Ι
    "Κ": "K",  # Κ
    "Μ": "M",  # Μ
    "Ν": "N",  # Ν
    "Ο": "O",  # Ο
    "Ρ": "P",  # Ρ
    "Τ": "T",  # Τ
    "Υ": "Y",  # Υ
    "Χ": "X",  # Χ
    "γ": "y",  # γ
}

#: Other scripts and symbol blocks with 1:1 Latin lookalikes.
_OTHER = {
    "İ": "I",  # İ LATIN CAPITAL LETTER I WITH DOT ABOVE
    "ı": "i",  # ı LATIN SMALL LETTER DOTLESS I
    "ǃ": "!",  # ǃ LATIN LETTER RETROFLEX CLICK
    "‐": "-",  # ‐ HYPHEN
    "‑": "-",  # ‑ NON-BREAKING HYPHEN
    "‒": "-",  # ‒ FIGURE DASH
    "–": "-",  # – EN DASH
    "—": "-",  # — EM DASH
    "―": "-",  # ― HORIZONTAL BAR
    "−": "-",  # − MINUS SIGN
    "⁄": "/",  # ⁄ FRACTION SLASH
    "∕": "/",  # ∕ DIVISION SLASH
    "ː": ":",  # ː MODIFIER LETTER TRIANGULAR COLON
    "：": ":",  # ： FULLWIDTH COLON (NFKC also handles this)
    "ԁ": "d",  # ԁ CYRILLIC SMALL LETTER KOMI DE
    "ԛ": "q",  # ԛ CYRILLIC SMALL LETTER QA
    "ɡ": "g",  # ɡ LATIN SMALL LETTER SCRIPT G
    "ⱥ": "a",  # ⱥ
}

#: The complete fold. Every entry maps exactly one character to exactly one
#: character -- enforced below, not merely intended.
CONFUSABLE_MAP: dict[str, str] = {**_CYRILLIC, **_GREEK, **_OTHER}

for _source, _target in CONFUSABLE_MAP.items():
    if len(_source) != 1 or len(_target) != 1:
        raise AssertionError(
            f"confusable map must be strictly 1:1; {_source!r} -> {_target!r} is not. "
            "A non-1:1 entry would desynchronise the folded view from its offset map."
        )
del _source, _target

#: Hyphen-like characters that fold to ASCII hyphen. Called out separately
#: because the Latvian personal code format depends on the hyphen, and a
#: customer pasting from a word processor supplies an en dash without noticing.
HYPHEN_CONFUSABLES = frozenset(ch for ch, target in CONFUSABLE_MAP.items() if target == "-")


def fold_confusables(text: str) -> str:
    """Fold visually confusable characters to their Latin/ASCII skeleton.

    Length-preserving by construction, so the result shares every index with
    ``text``. That property is what lets the folded view reuse the offset map
    built for the unfolded one, and it is asserted by
    ``test_folding_is_length_preserving``.
    """
    if not text:
        return text
    return "".join(CONFUSABLE_MAP.get(ch, ch) for ch in text)


def folds_to_ascii(text: str) -> bool:
    """Whether folding changes ``text`` at all. Used for audit signalling."""
    return fold_confusables(text) != text
