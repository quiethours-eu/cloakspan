"""Typed YAML policy engine.

Deliberately small. The product plan specifies four actions and priority
ordering; that does not justify OPA, a second process, a second language, and a
second failure domain (see ADR-0004). What it does justify is being rigorous
about the three properties a compliance officer will ask about:

* **Deterministic** -- the same input always yields the same decision. Rules are
  sorted by (priority desc, name asc); ties never depend on dict ordering.
* **Explainable** -- every decision names the rule that produced it.
* **Versioned** -- the policy version is stamped into every audit event, so a
  decision made six months ago can be reproduced.

Deny-overrides: BLOCK wins over everything at equal priority, because a policy
that accidentally allows is worse than one that accidentally blocks.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from gateway.domain import Action, InspectionResult, PolicyDecision, RequestContext


class PolicyError(Exception):
    """Raised when a policy document is invalid. Always fatal at load time."""


def _string_list(value: Any, *, rule_name: str, field_name: str) -> list[str]:
    """Validate a policy list without coercing malformed YAML scalars.

    ``frozenset("EMAIL_ADDRESS")`` is valid Python, but it produces a set of
    characters. In a policy, this silently disables the intended entity rule,
    so policy input must be checked before it reaches ``frozenset``.
    """
    if not isinstance(value, list):
        raise PolicyError(f"rule {rule_name!r}: '{field_name}' must be a list of strings")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise PolicyError(f"rule {rule_name!r}: '{field_name}' must contain only non-empty strings")
    return value


def _min_score(value: Any, *, rule_name: str) -> float:
    """Return a finite confidence threshold in the detector score range."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PolicyError(f"rule {rule_name!r}: 'min_score' must be a number from 0 to 1")
    score = float(value)
    if not math.isfinite(score) or not 0.0 <= score <= 1.0:
        raise PolicyError(f"rule {rule_name!r}: 'min_score' must be finite and between 0 and 1")
    return score


@dataclass(frozen=True, slots=True)
class Rule:
    name: str
    priority: int
    action: Action
    destination: str = ""
    entities: frozenset[str] = field(default_factory=frozenset)
    applications: frozenset[str] = field(default_factory=frozenset)
    min_score: float = 0.0

    def matches(
        self, ctx: RequestContext, inspection: InspectionResult
    ) -> tuple[bool, tuple[str, ...]]:
        """Return (matched, the entity types that caused the match)."""
        if self.applications and ctx.application not in self.applications:
            return False, ()

        if not self.entities:
            # A rule with no entity condition is a catch-all (the default rule).
            return True, ()

        present = {span.entity_type for span in inspection.spans if span.score >= self.min_score}
        matched = self.entities & present
        if not matched:
            return False, ()
        return True, tuple(sorted(matched))


class PolicyEngine:
    def __init__(self, rules: list[Rule], version: str, default_destination: str) -> None:
        if not rules:
            raise PolicyError("policy must contain at least one rule")
        # Deterministic evaluation order. BLOCK sorts before other actions at
        # equal priority so deny-overrides is a property of the ordering rather
        # than a special case in the loop.
        self._rules = sorted(
            rules,
            key=lambda r: (-r.priority, r.action is not Action.BLOCK, r.name),
        )
        self.version = version
        self._default_destination = default_destination

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    def with_rules(self, rules: list[Rule], *, version_suffix: str) -> PolicyEngine:
        """Compose operator filters with the policy and preserve audit provenance."""
        combined = self.rules + rules
        if len({rule.name for rule in combined}) != len(combined):
            raise PolicyError("filter rule name conflicts with an existing policy rule")
        return PolicyEngine(
            combined, f"{self.version}+{version_suffix}", self._default_destination
        )

    @property
    def required_destinations(self) -> frozenset[str]:
        """Provider names that a non-blocking rule can select.

        Configuration validation uses this at startup.  A policy referring to
        an unavailable provider must not discover that fact only after it has
        accepted a request containing sensitive data.
        """
        return frozenset(
            rule.destination or self._default_destination
            for rule in self._rules
            if rule.action is not Action.BLOCK
        )

    def evaluate(self, ctx: RequestContext, inspection: InspectionResult) -> PolicyDecision:
        for rule in self._rules:
            matched, entities = rule.matches(ctx, inspection)
            if not matched:
                continue
            return PolicyDecision(
                action=rule.action,
                destination=rule.destination or self._default_destination,
                rule_name=rule.name,
                policy_version=self.version,
                matched_entities=entities,
                reason=f"matched rule '{rule.name}' (priority {rule.priority})",
            )

        # Unreachable with a well-formed policy (the loader requires a
        # catch-all), but we fail closed rather than trusting that.
        return PolicyDecision(
            action=Action.BLOCK,
            destination="",
            rule_name="__implicit_deny__",
            policy_version=self.version,
            reason="no rule matched; failing closed",
        )

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    @classmethod
    def from_dict(cls, document: dict[str, Any], version: str | None = None) -> PolicyEngine:
        if not isinstance(document, dict):
            raise PolicyError("policy document must be a mapping")

        raw_rules = document.get("rules")
        if not isinstance(raw_rules, list) or not raw_rules:
            raise PolicyError("policy must define a non-empty 'rules' list")

        default_destination = document.get("default_destination", "external")

        rules: list[Rule] = []
        seen: set[str] = set()
        for index, raw in enumerate(raw_rules):
            if not isinstance(raw, dict):
                raise PolicyError(f"rule #{index} is not a mapping")

            name = raw.get("name")
            if not name or not isinstance(name, str):
                raise PolicyError(f"rule #{index} is missing a string 'name'")
            if name in seen:
                raise PolicyError(f"duplicate rule name: {name!r}")
            seen.add(name)

            action_block = raw.get("action") or {}
            if not isinstance(action_block, dict):
                raise PolicyError(f"rule {name!r}: 'action' must be a mapping")
            action_type = action_block.get("type")
            try:
                action = Action(action_type)
            except ValueError as exc:
                raise PolicyError(
                    f"rule {name!r}: unknown action type {action_type!r}; "
                    f"expected one of {[a.value for a in Action]}"
                ) from exc

            match_block = raw.get("match") or {}
            if not isinstance(match_block, dict):
                raise PolicyError(f"rule {name!r}: 'match' must be a mapping")

            entities = _string_list(
                match_block.get("entities", []),
                rule_name=name,
                field_name="entities",
            )
            applications = _string_list(
                match_block.get("applications", []),
                rule_name=name,
                field_name="applications",
            )
            min_score = _min_score(match_block.get("min_score", 0.0), rule_name=name)

            rules.append(
                Rule(
                    name=name,
                    priority=int(raw.get("priority", 0)),
                    action=action,
                    destination=action_block.get("destination", ""),
                    entities=frozenset(entities),
                    applications=frozenset(applications),
                    min_score=min_score,
                )
            )

        if not any(not r.entities and not r.applications for r in rules):
            raise PolicyError(
                "policy must contain a catch-all rule (no 'match' conditions) "
                "so every request has a defined outcome"
            )

        resolved_version = version or document.get("version") or "unversioned"
        return cls(rules, str(resolved_version), str(default_destination))

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyEngine:
        """Load a policy file.

        The version is derived from a SHA-256 of the file bytes when the
        document does not declare one, so an edited policy always produces a
        different version string in the audit log. A policy that changes
        without its version changing is an audit failure waiting to happen.
        """
        content = Path(path).read_bytes()
        document = yaml.safe_load(content)
        declared = (document or {}).get("version")
        version = declared or f"sha256:{hashlib.sha256(content).hexdigest()[:16]}"
        return cls.from_dict(document, version=str(version))
