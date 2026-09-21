"""Versioned, operator-owned filter definitions and their matching policy rules."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from gateway.domain import Action
from gateway.policy.engine import Rule
from recognizers.custom.customer_rules import CustomRegexDetector, DictionaryDetector


class FilterConfigurationError(ValueError):
    """Invalid filter configuration; startup must fail closed."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


NonEmpty = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Entity = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")]


class RegexMatcher(_Model):
    type: Literal["regex"]
    pattern: Annotated[str, Field(min_length=1, max_length=500)]
    case_sensitive: bool = True


class DictionaryMatcher(_Model):
    type: Literal["dictionary"]
    terms: Annotated[list[NonEmpty], Field(min_length=1)]
    case_sensitive: bool = False


class Filter(_Model):
    name: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")]
    entity_type: Entity
    match: Annotated[RegexMatcher | DictionaryMatcher, Field(discriminator="type")]
    action: Literal["transform", "block", "route_local"] = "transform"
    destination: NonEmpty | None = None
    priority: Annotated[int, Field(ge=0, le=1000)] | None = None
    enabled: bool = True

    def detector(self) -> CustomRegexDetector | DictionaryDetector:
        name = f"filter:{self.name}"
        if isinstance(self.match, RegexMatcher):
            return CustomRegexDetector(
                self.match.pattern,
                self.entity_type,
                name,
                case_sensitive=self.match.case_sensitive,
            )
        return DictionaryDetector(
            self.match.terms,
            self.entity_type,
            name,
            case_sensitive=self.match.case_sensitive,
        )

    def rule(self) -> Rule:
        defaults = {"transform": 60, "route_local": 90, "block": 100}
        return Rule(
            name=f"filter:{self.name}",
            priority=self.priority if self.priority is not None else defaults[self.action],
            action=Action(self.action),
            destination=self.destination or ("local" if self.action == "route_local" else ""),
            entities=frozenset({self.entity_type}),
        )


class FilterDocument(_Model):
    version: Annotated[int, Field(ge=1, le=1)]
    filters: list[Filter]


class _UniqueKeyLoader(yaml.SafeLoader):
    """A duplicated YAML key must not silently replace a protection setting."""

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in seen:
                raise FilterConfigurationError("filter YAML keys must be unique strings")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


class FilterSet:
    def __init__(self, document: FilterDocument, fingerprint: str) -> None:
        self.fingerprint = fingerprint
        self.detectors: list[CustomRegexDetector | DictionaryDetector] = []
        self.rules: list[Rule] = []
        names: set[str] = set()
        entities: set[str] = set()
        for index, item in enumerate(document.filters):
            if item.name in names or item.entity_type in entities:
                raise FilterConfigurationError(
                    f"filter #{index}: names and entity types must be unique"
                )
            names.add(item.name)
            entities.add(item.entity_type)
            if item.action == "block" and item.destination is not None:
                raise FilterConfigurationError(f"filter #{index}: block cannot have a destination")
            try:
                detector = item.detector()
            except ValueError:
                # Do not echo confidential dictionary entries or patterns into logs.
                raise FilterConfigurationError(
                    f"filter #{index}: invalid or unsafe matcher"
                ) from None
            if item.enabled:
                self.detectors.append(detector)
                self.rules.append(item.rule())

    @classmethod
    def from_yaml(cls, path: str | Path) -> FilterSet:
        try:
            content = Path(path).read_bytes()
            raw = yaml.load(content, Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass
            document = FilterDocument.model_validate(raw)
        except ValidationError as exc:
            locations = ", ".join(".".join(map(str, e["loc"])) for e in exc.errors())
            raise FilterConfigurationError(f"invalid filter fields: {locations}") from None
        except (OSError, yaml.YAMLError, UnicodeError):
            raise FilterConfigurationError("cannot read or parse filter file") from None
        return cls(document, hashlib.sha256(content).hexdigest()[:16])
