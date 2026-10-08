"""Literal argv restoration for a deliberately small POSIX shell subset.

Allowed programs read/write local files or run pytest. Operators, redirections,
expansions, command substitution, arbitrary interpreters, executable paths and
network commands are rejected even without placeholders. The client still
owns approvals, sandboxing and execution; this is not a shell/network sandbox.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable

from gateway.tools.search import restore_regex, validate_glob
from gateway.transformations.tokens import TOKEN_PATTERN


class ShellValidationError(ValueError):
    """The command is outside the supported literal argv grammar."""


_UNSUPPORTED_SYNTAX = re.compile(r"[\x00\r\n$`;|&<>()*?\[\]{}!\\~]")
_READ_FLAGS = {
    "cat": {"-n", "-b", "-s", "--"},
    "ls": {"-a", "-l", "-la", "-al", "-h", "-R", "--"},
    "wc": {"-l", "-w", "-c", "-m", "--"},
    "stat": {"--"},
    "head": {"--"},
    "tail": {"--"},
    "touch": {"--"},
    "mkdir": {"-p", "--"},
    "cp": {"--"},
    "mv": {"--"},
}
_TEST_FLAGS = {"-q", "-v", "-vv", "-x", "--disable-warnings", "--maxfail=1"}
_SEARCH_FLAGS = {
    "-n",
    "--line-number",
    "-i",
    "--ignore-case",
    "-l",
    "--files-with-matches",
    "-c",
    "--count",
    "-o",
    "--only-matching",
    "-F",
    "--fixed-strings",
    "-U",
    "--multiline",
    "--multiline-dotall",
    "--hidden",
    "--no-heading",
    "--files",
    "-q",
    "--quiet",
}


def _validate_source(command: str) -> None:
    """Quoted literals may contain pattern syntax; executable shell syntax may not."""
    quote: str | None = None
    escaped = False
    for character in command:
        if character in "\x00\r\n":
            raise ShellValidationError("Unsupported shell command")
        if escaped:
            escaped = False
            continue
        if quote:
            if character == quote:
                quote = None
            elif quote == '"' and character == "\\":
                escaped = True
            elif quote == '"' and character in "$`":
                raise ShellValidationError("Unsupported shell command")
        elif character in {"'", '"'}:
            quote = character
        elif _UNSUPPORTED_SYNTAX.match(character):
            raise ShellValidationError("Unsupported shell command")
    if quote is not None or escaped:
        raise ShellValidationError("Unsupported shell command")


def restore_shell(
    command: str,
    restore_literal: Callable[[str], str],
    validate_path: Callable[[str], str],
    *,
    restore_glob: Callable[[str], str] | None = None,
) -> str:
    """Return one safely quoted command without altering its executable or flags."""
    # Tokens contain shell operators themselves. Mask them before parsing,
    # then restore only the resulting literal arguments, never the program.
    placeholders: dict[str, str] = {}
    marker_prefix = "CLOAKSPAN_LITERAL_"
    while marker_prefix in command:
        marker_prefix += "X"

    def mask(match: re.Match[str]) -> str:
        marker = f"{marker_prefix}{len(placeholders)}Z"
        placeholders[marker] = match.group(0)
        return marker

    masked = TOKEN_PATTERN.sub(mask, command)
    _validate_source(masked)
    try:
        argv = shlex.split(masked, posix=True)
    except ValueError:
        raise ShellValidationError("Unsupported shell command") from None
    if not argv or len(argv) > 256:
        raise ShellValidationError("Unsupported shell command")

    def unmask(value: str) -> str:
        for marker, token in placeholders.items():
            value = value.replace(marker, token)
        return value

    argv = [unmask(value) for value in argv]
    program = argv[0]
    if TOKEN_PATTERN.search(program):
        raise ShellValidationError("Unsupported shell command")

    def path_argument(value: str) -> str:
        restored = restore_literal(value)
        if restored.startswith("-"):
            raise ShellValidationError("Unsupported shell command")
        return validate_path(restored)

    result = [program]
    values = argv[1:]
    if restore_glob is None:

        def default_glob(pattern: str) -> str:
            return validate_glob(restore_literal(pattern))

        restore_glob = default_glob
    if program == "pwd":
        if values:
            raise ShellValidationError("Unsupported shell command")
    elif program == "test":
        if len(values) != 2 or values[0] not in {"-f", "-d", "-e", "-r", "-w"}:
            raise ShellValidationError("Unsupported shell command")
        result.extend((values[0], path_argument(values[1])))
    elif program == "printf":
        if not values or values[0] != "%s":
            raise ShellValidationError("Unsupported shell command")
        result.append(values[0])
        result.extend(restore_literal(value) for value in values[1:])
    elif program in {"pytest", "python", "python3"}:
        if program != "pytest":
            if values[:2] != ["-m", "pytest"]:
                raise ShellValidationError("Unsupported shell command")
            result.extend(values[:2])
            values = values[2:]
        for value in values:
            if value in _TEST_FLAGS:
                result.append(value)
            elif value.startswith("-"):
                raise ShellValidationError("Unsupported shell command")
            else:
                result.append(path_argument(value))
    elif program in {"rg", "grep"}:
        fixed = bool({"-F", "--fixed-strings"} & set(values))
        listing = program == "rg" and "--files" in values
        pattern_seen = False
        flags_ended = False
        index = 0
        while index < len(values):
            value = values[index]
            if not flags_ended and value == "--":
                result.append(value)
                flags_ended = True
            elif not flags_ended and value in _SEARCH_FLAGS:
                if program == "grep" and value in {
                    "--files",
                    "--hidden",
                    "-U",
                    "--multiline",
                    "--multiline-dotall",
                }:
                    raise ShellValidationError("Unsupported shell command")
                result.append(value)
            elif not flags_ended and value in {
                "-e",
                "--regexp",
                "-g",
                "--glob",
                "-t",
                "--type",
                "-A",
                "-B",
                "-C",
                "-m",
                "--max-count",
            }:
                if index + 1 >= len(values):
                    raise ShellValidationError("Unsupported shell command")
                argument = values[index + 1]
                if value in {"-e", "--regexp"}:
                    if listing:
                        raise ShellValidationError("Unsupported shell command")
                    argument = restore_regex(argument, restore_literal, fixed=fixed)
                    pattern_seen = True
                elif value in {"-g", "--glob"}:
                    if program != "rg":
                        raise ShellValidationError("Unsupported shell command")
                    argument = restore_glob(argument)
                elif value in {"-t", "--type"}:
                    if program != "rg" or not re.fullmatch(
                        r"[A-Za-z][A-Za-z0-9_-]{0,31}", argument
                    ):
                        raise ShellValidationError("Unsupported shell command")
                elif not re.fullmatch(r"[0-9]{1,6}", argument):
                    raise ShellValidationError("Unsupported shell command")
                result.extend((value, argument))
                index += 2
                continue
            elif value.startswith("-"):
                raise ShellValidationError("Unsupported shell command")
            elif not listing and not pattern_seen:
                argument = restore_regex(value, restore_literal, fixed=fixed)
                if argument.startswith("-"):
                    raise ShellValidationError("Unsupported shell command")
                result.append(argument)
                pattern_seen = True
            else:
                result.append(path_argument(value))
            index += 1
        if not listing and not pattern_seen:
            raise ShellValidationError("Unsupported shell command")
    elif program == "find":
        index = 0
        paths = 0
        expression = False
        while index < len(values):
            value = values[index]
            if value in {"-name", "-iname"}:
                if index + 1 >= len(values):
                    raise ShellValidationError("Unsupported shell command")
                result.extend((value, restore_glob(values[index + 1])))
                index += 2
                expression = True
                continue
            if value in {"-maxdepth", "-mindepth", "-type"}:
                if index + 1 >= len(values):
                    raise ShellValidationError("Unsupported shell command")
                argument = values[index + 1]
                if (value == "-type" and argument not in {"f", "d"}) or (
                    value != "-type" and not re.fullmatch(r"[0-9]{1,3}", argument)
                ):
                    raise ShellValidationError("Unsupported shell command")
                result.extend((value, argument))
                index += 2
                expression = True
                continue
            if value == "-print":
                result.append(value)
                expression = True
            elif value.startswith("-") or expression:
                raise ShellValidationError("Unsupported shell command")
            else:
                result.append(path_argument(value))
                paths += 1
            index += 1
        if not paths:
            raise ShellValidationError("Unsupported shell command")
    elif program in _READ_FLAGS:
        paths = 0
        index = 0
        flags_ended = False
        while index < len(values):
            value = values[index]
            if not flags_ended and program in {"head", "tail"} and value == "-n":
                if index + 1 >= len(values) or not re.fullmatch(
                    r"[1-9][0-9]{0,6}", values[index + 1]
                ):
                    raise ShellValidationError("Unsupported shell command")
                result.extend(values[index : index + 2])
                index += 2
                continue
            if not flags_ended and value in _READ_FLAGS[program]:
                result.append(value)
                flags_ended = value == "--"
            elif value.startswith("-"):
                raise ShellValidationError("Unsupported shell command")
            else:
                result.append(path_argument(value))
                paths += 1
            index += 1
        if program in {"cp", "mv"} and paths != 2:
            raise ShellValidationError("Unsupported shell command")
        if program in {"cat", "wc", "head", "tail", "stat", "touch", "mkdir"} and not paths:
            raise ShellValidationError("Unsupported shell command")
    else:
        raise ShellValidationError("Unsupported shell command")
    return " ".join(shlex.quote(value) for value in result)
