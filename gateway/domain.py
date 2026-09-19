"""Core domain models.

These types are the vocabulary the whole pipeline speaks. They are immutable
where possible so a later stage cannot silently mutate what an earlier stage
decided -- in a security pipeline, "who changed this span?" must always have a
single answer.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Confidence(float, enum.Enum):
    """Named confidence levels for detector results.

    Deterministic detectors with a checksum (Baltic IDs, IBAN, card numbers)
    earn CERTAIN. Pattern-only matches earn HIGH at best, because a regex that
    matches an email shape cannot know the string was not an example.
    """

    CERTAIN = 1.0
    HIGH = 0.85
    MEDIUM = 0.6
    LOW = 0.35


@dataclass(frozen=True, slots=True, order=True)
class Span:
    """A detected region of text.

    Ordering is by (start, end) so spans sort naturally; the transformation
    stage relies on being able to sort and reverse this list.
    """

    start: int
    end: int
    entity_type: str
    text: str
    score: float = 1.0
    detector: str = "unknown"

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError(f"invalid span bounds: [{self.start}, {self.end})")
        if len(self.text) != self.end - self.start:
            raise ValueError(
                f"span text length {len(self.text)} does not match bounds "
                f"[{self.start}, {self.end})"
            )

    @property
    def length(self) -> int:
        return self.end - self.start

    def overlaps(self, other: Span) -> bool:
        return not (self.end <= other.start or other.end <= self.start)

    def contains(self, other: Span) -> bool:
        return self.start <= other.start and other.end <= self.end


class Action(enum.StrEnum):
    """The four policy actions required by the product plan."""

    ALLOW = "allow"
    TRANSFORM = "transform"
    ROUTE_LOCAL = "route_local"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Identity and scope for one gateway request.

    Every security decision and every vault operation is keyed on this. There is
    no code path that reaches the vault without one, which is how security
    invariants SI-04 and SI-05 (no restoration and no mapping lookup without an
    authenticated tenant and conversation) are structurally enforced rather
    than merely tested. See docs/security-invariants.md.
    """

    tenant_id: str
    conversation_id: str
    request_id: str
    api_key_id: str
    application: str = "unknown"

    def __post_init__(self) -> None:
        for name in ("tenant_id", "conversation_id", "request_id", "api_key_id"):
            value = getattr(self, name)
            if not value or not isinstance(value, str):
                raise ValueError(f"{name} must be a non-empty string")


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """The outcome of policy evaluation. Always explainable."""

    action: Action
    destination: str
    rule_name: str
    policy_version: str
    matched_entities: tuple[str, ...] = ()
    reason: str = ""


@dataclass(slots=True)
class InspectionResult:
    """What the detection stage found, before policy runs."""

    spans: list[Span] = field(default_factory=list)

    def entity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for span in self.spans:
            counts[span.entity_type] = counts.get(span.entity_type, 0) + 1
        return counts

    def entity_types(self) -> set[str]:
        return {span.entity_type for span in self.spans}
