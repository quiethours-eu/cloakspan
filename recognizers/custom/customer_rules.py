"""Customer-defined detectors: exact dictionaries and regular expressions.

The product plan calls this "one of the most valuable product capabilities", and
it is right: a generic PII engine cannot know that "Project Aurora" is
confidential, and that is precisely the information a customer most fears
leaking.

Two detector types ship in v1. Semantic ("names of unreleased products")
classifiers are deliberately deferred -- deterministic rules are auditable,
explainable, and testable, which matters more than coverage for a control a
compliance officer has to sign off.
"""

from __future__ import annotations

import re

from gateway.domain import Confidence, Span

# Customer regexes are attacker-adjacent input: a careless pattern can hang the
# gateway (catastrophic backtracking) and become a denial-of-service vector.
MAX_PATTERN_LENGTH = 500


class UnsafePatternError(ValueError):
    """Raised when a customer-supplied pattern is rejected."""


class DictionaryDetector:
    """Exact, case-insensitive matching against a customer term list.

    Longest-first matching means "Acme Latvia SIA" wins over "Acme Latvia",
    so we pseudonymise the most specific term the customer registered.

    Implemented as a single compiled alternation rather than a loop over terms:
    with a few thousand dictionary entries, per-term scanning dominates request
    latency.
    """

    def __init__(
        self,
        terms: list[str],
        entity_type: str = "CUSTOMER_TERM",
        name: str = "customer_dictionary",
        *,
        case_sensitive: bool = False,
    ) -> None:
        self.name = name
        self.entity_type = entity_type
        cleaned = [t.strip() for t in terms if t and t.strip()]
        self._pattern: re.Pattern[str] | None = None
        if cleaned:
            ordered = sorted(set(cleaned), key=len, reverse=True)
            alternation = "|".join(re.escape(t) for t in ordered)
            # \b is wrong for terms that start or end with punctuation, so we
            # use lookarounds on word characters instead.
            self._pattern = re.compile(
                rf"(?<!\w)(?:{alternation})(?!\w)",
                re.UNICODE | (0 if case_sensitive else re.IGNORECASE),
            )

    def detect(self, text: str) -> list[Span]:
        if self._pattern is None:
            return []
        return [
            Span(
                start=m.start(),
                end=m.end(),
                entity_type=self.entity_type,
                text=m.group(0),
                score=Confidence.CERTAIN.value,
                detector=self.name,
            )
            for m in self._pattern.finditer(text)
        ]


class CustomRegexDetector:
    """A single customer-supplied pattern, e.g. ``AUR-[0-9]{6}``.

    Validation is intentionally strict. A customer regex runs on every request
    against attacker-influenced text, so a pattern with nested unbounded
    quantifiers is a denial-of-service primitive, not a detection rule.
    """

    def __init__(
        self,
        pattern: str,
        entity_type: str,
        name: str | None = None,
        *,
        case_sensitive: bool = True,
    ) -> None:
        self.name = name or f"custom_regex:{entity_type}"
        self.entity_type = entity_type.upper()
        self._pattern = self._compile_safely(pattern, case_sensitive=case_sensitive)

    @staticmethod
    def _compile_safely(pattern: str, *, case_sensitive: bool = True) -> re.Pattern[str]:
        if len(pattern) > MAX_PATTERN_LENGTH:
            raise UnsafePatternError(f"pattern exceeds {MAX_PATTERN_LENGTH} characters")

        # Reject the classic catastrophic-backtracking shapes: a quantified
        # group whose body is itself unbounded, e.g. (a+)+ or (a*)* or (a+)*.
        # This is a conservative heuristic, not a complete ReDoS analysis --
        # Python's `re` has no backtracking limit, so we prefer to refuse a few
        # legitimate patterns over accepting a hang.
        if re.search(r"\([^)]*[+*]\)\s*[+*{]", pattern):
            raise UnsafePatternError(
                "pattern contains nested unbounded quantifiers, which risks "
                "catastrophic backtracking; rewrite it with bounded repetition"
            )

        try:
            return re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
        except re.error as exc:
            raise UnsafePatternError(f"invalid regular expression: {exc}") from exc

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for match in self._pattern.finditer(text):
            # A zero-width match would produce an empty span and loop forever
            # in naive consumers; skip it.
            if match.end() == match.start():
                continue
            spans.append(
                Span(
                    start=match.start(),
                    end=match.end(),
                    entity_type=self.entity_type,
                    text=match.group(0),
                    score=Confidence.HIGH.value,
                    detector=self.name,
                )
            )
        return spans
