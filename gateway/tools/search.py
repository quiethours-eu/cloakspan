"""Local search patterns: scope paths and restore values as literal pattern text."""

from __future__ import annotations

import re
from collections.abc import Callable

from gateway.transformations.tokens import TOKEN_PATTERN


def restore_regex(
    pattern: str, restore_literal: Callable[[str], str], *, fixed: bool = False
) -> str:
    """Keep authored regex structure; restored private values cannot add regex syntax."""
    if not isinstance(pattern, str) or "\x00" in pattern:
        raise ValueError("Invalid local search pattern")
    if not TOKEN_PATTERN.search(pattern):
        return restore_literal(pattern)

    def replacement(match: re.Match[str]) -> str:
        value = restore_literal(match.group(0))
        if "\x00" in value:
            raise ValueError("Invalid local search pattern")
        if fixed:
            return value
        return re.escape(value).replace("\\\n", "\\n").replace("\\\r", "\\r")

    return TOKEN_PATTERN.sub(replacement, pattern)


def validate_glob(pattern: str) -> str:
    """A bounded relative glob cannot select a different search root.

    Braces are limited to simple filename alternatives; path separators and
    dot components in brace alternatives are refused. The execution client must
    enforce its own permissions and prevent symlink escape when walking files.
    """
    if (
        not isinstance(pattern, str)
        or not pattern
        or len(pattern) > 4096
        or any(character in pattern for character in "\x00\r\n\\:")
        or pattern.startswith(("/", "~", "!"))
        or any(part == ".." for part in pattern.split("/"))
    ):
        raise ValueError("Invalid local search pattern")
    without_braces = pattern
    for match in re.finditer(r"\{([^{}]+)\}", pattern):
        alternatives = match.group(1).split(",")
        if len(alternatives) < 2 or any(
            not alternative or alternative in {".", ".."} or "/" in alternative
            for alternative in alternatives
        ):
            raise ValueError("Invalid local search pattern")
        without_braces = without_braces.replace(match.group(0), "glob")
    if "{" in without_braces or "}" in without_braces:
        raise ValueError("Invalid local search pattern")
    return pattern


def restore_glob(pattern: str, restore_literal: Callable[[str], str]) -> str:
    """Preserve glob operators only from the original pattern, never replacements."""
    if not isinstance(pattern, str):
        raise ValueError("Invalid local search pattern")
    if not TOKEN_PATTERN.search(pattern):
        return validate_glob(restore_literal(pattern))

    def replacement(match: re.Match[str]) -> str:
        value = restore_literal(match.group(0))
        if any(character in value for character in "*?[]{}!\\"):
            raise ValueError("Invalid local search pattern")
        return value

    return validate_glob(TOKEN_PATTERN.sub(replacement, pattern))
