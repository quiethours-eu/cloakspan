"""Fail closed when restoring executable arguments into registered tool sinks."""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from typing import Any

from gateway.domain import RequestContext
from gateway.restoration.engine import (
    RestorationEngine,
    RestorationOutcome,
    RestorationOutputTooLargeError,
)
from gateway.tools.patches import PatchValidationError, restore_patch
from gateway.tools.search import restore_glob, restore_regex
from gateway.tools.shell import ShellValidationError, restore_shell
from gateway.transformations.tokens import TOKEN_PATTERN, TokenProvenance

# Recognize unknown versions, malformed tags, casing changes, legacy numbered
# placeholders, and prefixes cut off mid-token. Normalization is used only for
# screening; it never changes the bytes being restored or written to files.
_TOKEN_LOOKALIKE = re.compile(
    r"<[A-Za-z][A-Za-z0-9_]{0,63}\s*:"
    r"|<[A-Z][A-Z0-9_]{0,63}_[0-9]+(?:>|$)"
    r"|<[A-Z][A-Z0-9_]{1,63}$"
    r"|(?<![A-Za-z0-9_])[A-Za-z][A-Za-z0-9_]{0,63}:[vV][0-9]+:[0-9a-fA-F]+>?"
)
_READ = {"read_file", "read", "Read"}
_EDIT = {"edit_file", "edit", "Edit"}
_WRITE = {"write_file", "write", "Write"}
_SHELL = {"shell", "run_shell", "exec_command", "Bash"}
_SEARCH = {"Grep", "Glob"}
_SUPPORTED = _READ | _EDIT | _WRITE | _SHELL | _SEARCH | {"apply_patch", "write_stdin", "TodoWrite"}


class ToolRestorationError(Exception):
    """A safe, fixed diagnostic; argument values never become error messages."""

    def __init__(
        self,
        code: str = "tool_restoration_refused",
        outcome: RestorationOutcome | None = None,
    ) -> None:
        super().__init__("Tool arguments could not be restored safely.")
        self.code = code
        self.outcome = outcome if outcome is not None else RestorationOutcome(text="")


def _has_placeholder(value: str) -> bool:
    return bool(
        TOKEN_PATTERN.search(value) or _TOKEN_LOOKALIKE.search(unicodedata.normalize("NFKC", value))
    )


def _has_malformed_placeholder(value: str) -> bool:
    without_tokens = TOKEN_PATTERN.sub("", value)
    return bool(_TOKEN_LOOKALIKE.search(unicodedata.normalize("NFKC", without_tokens)))


def _decode_arguments(arguments: str) -> dict[str, Any]:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result or _has_placeholder(key):
                raise ValueError("Invalid tool arguments")
            result[key] = value
        return result

    def invalid_constant(_: str) -> None:
        raise ValueError("Invalid tool arguments")

    parsed = json.loads(arguments, object_pairs_hook=object_pairs, parse_constant=invalid_constant)
    if not isinstance(parsed, dict):
        raise ValueError("Invalid tool arguments")
    # Nested values exist only in explicitly registered permission/todo shapes.
    # Bound JSON before visiting those shapes; handlers refuse all extra fields.
    stack = [(parsed, 0)]
    visited = 0
    while stack:
        node, depth = stack.pop()
        visited += 1
        if depth > 8 or visited > 4096:
            raise ValueError("Invalid tool arguments")
        if isinstance(node, (dict, list)):
            if len(node) > 128:
                raise ValueError("Invalid tool arguments")
            stack.extend(
                (child, depth + 1) for child in (node.values() if isinstance(node, dict) else node)
            )
    return parsed


class ToolRegistry:
    """Registered POSIX tools with a workspace root fixed by the operator.

    Local paths must resolve within that root now. The execution client must
    repeat filesystem/symlink checks at execution time to prevent races; the
    gateway neither executes tools nor grants sandbox or approval permissions.
    Unregistered tools are refused, including calls with no placeholders.
    """

    def __init__(self, workspace_root: str | Path) -> None:
        self.workspace_root = Path(workspace_root).resolve(strict=True)
        if not self.workspace_root.is_dir():
            raise ValueError("Tool workspace must be an existing directory")

    def _validate_path(self, value: str, *, cwd: Path | None = None) -> str:
        if (
            not value
            or any(character in value for character in "\x00\r\n\\")
            or ":" in value
            or value.startswith(("//", "~", "-"))
            or _has_placeholder(value)
        ):
            raise ValueError("Invalid local tool path")
        path = Path(value)
        if ".." in path.parts:
            raise ValueError("Invalid local tool path")
        candidate = path if path.is_absolute() else (cwd or self.workspace_root) / path
        resolved = candidate.resolve(strict=False)
        if not resolved.is_relative_to(self.workspace_root):
            raise ValueError("Invalid local tool path")
        return value

    def restore(
        self,
        ctx: RequestContext,
        name: str,
        arguments: str,
        provenance: TokenProvenance,
        restorer: RestorationEngine,
        *,
        custom: bool = False,
    ) -> tuple[str, RestorationOutcome]:
        """Restore a complete call atomically, retaining IDs/names/control fields."""
        aggregate = RestorationOutcome(text="")
        try:
            if name not in _SUPPORTED or _has_placeholder(name):
                raise ToolRestorationError("unsupported_tool", aggregate)
            if len(arguments.encode("utf-8")) > restorer.max_output_bytes:
                raise ToolRestorationError("tool_arguments_too_large", aggregate)
            restored_bytes = 0

            def content(value: str) -> str:
                nonlocal restored_bytes
                if not isinstance(value, str) or _has_malformed_placeholder(value):
                    raise ValueError("Invalid tool arguments")
                outcome = restorer.restore(
                    ctx,
                    value,
                    provenance,
                    max_output_bytes=max(0, restorer.max_output_bytes - restored_bytes),
                )
                aggregate.merge(outcome)
                if outcome.total_refused or _has_placeholder(outcome.text):
                    raise ToolRestorationError(outcome=aggregate)
                restored_bytes += len(outcome.text.encode("utf-8"))
                return outcome.text

            def path(value: str) -> str:
                return self._validate_path(content(value))

            def glob(value: str) -> str:
                if not isinstance(value, str) or _has_malformed_placeholder(value):
                    raise ValueError("Invalid tool arguments")
                return restore_glob(value, content)

            def patch(value: str) -> str:
                seen_paths: set[Path] = set()

                def patch_path(value: str) -> str:
                    restored_path = path(value)
                    candidate = Path(restored_path)
                    if not candidate.is_absolute():
                        candidate = self.workspace_root / candidate
                    canonical = candidate.resolve(strict=False)
                    if canonical in seen_paths:
                        raise ValueError("Invalid tool arguments")
                    seen_paths.add(canonical)
                    return restored_path

                restored = restore_patch(value, patch_path, content)
                # Parse the rebuilt grammar independently. Nothing restored may
                # become a new header, hunk marker or executable patch action.
                restore_patch(restored, self._validate_path, lambda text: text)
                return restored

            if custom:
                if name != "apply_patch":
                    raise ToolRestorationError("unsupported_tool_format", aggregate)
                result = patch(arguments)
            else:
                values = _decode_arguments(arguments)
                if name in _READ | _EDIT | _WRITE:
                    self._restore_file(name, values, path, content)
                elif name == "apply_patch":
                    if set(values) != {"patch"} or not isinstance(values["patch"], str):
                        raise ValueError("Invalid tool arguments")
                    values["patch"] = patch(values["patch"])
                elif name in _SHELL:
                    self._restore_shell(name, values, content, path, glob)
                elif name in _SEARCH:
                    self._restore_search(name, values, content, path, glob)
                elif name == "write_stdin":
                    self._validate_stdin(values)
                elif name == "TodoWrite":
                    self._restore_todos(values, content)
                result = json.dumps(values, ensure_ascii=False, separators=(",", ":"))
            if len(result.encode("utf-8")) > restorer.max_output_bytes:
                raise ToolRestorationError("tool_arguments_too_large", aggregate)
            aggregate.text = result
            return result, aggregate
        except ToolRestorationError:
            raise
        except RestorationOutputTooLargeError:
            raise ToolRestorationError("tool_arguments_too_large", aggregate) from None
        except (
            ValueError,
            TypeError,
            KeyError,
            RecursionError,
            OSError,
            PatchValidationError,
            ShellValidationError,
        ):
            raise ToolRestorationError(outcome=aggregate) from None

    @staticmethod
    def _restore_file(name: str, values: dict[str, Any], path, content) -> None:
        path_key = "file_path" if name in {"Read", "Edit", "Write"} else "path"
        required = {path_key}
        controls: dict[str, type] = {}
        restored_fields: set[str] = set()
        if name in _READ:
            controls = (
                {"offset": int, "limit": int}
                if name == "Read"
                else {"start_line": int, "end_line": int}
            )
        elif name in _WRITE:
            required.add("content")
            restored_fields.add("content")
        else:
            if name == "Edit" or "old_string" in values or "new_string" in values:
                restored_fields = {"old_string", "new_string"}
            else:
                restored_fields = {"old_text", "new_text"}
            required |= restored_fields
            controls = {"replace_all": bool}
        if not required <= set(values) or set(values) - required - set(controls):
            raise ValueError("Invalid tool arguments")
        for key, expected_type in controls.items():
            if key in values and (
                type(values[key]) is not expected_type
                or (expected_type is int and values[key] < (0 if key == "offset" else 1))
            ):
                raise ValueError("Invalid tool arguments")
        values[path_key] = path(values[path_key])
        for key in restored_fields:
            values[key] = content(values[key])

    def _restore_shell(self, name: str, values: dict[str, Any], content, path, glob) -> None:
        command_key = "cmd" if name == "exec_command" else "command"
        permitted = {command_key, "shell", "cwd"}
        if name == "exec_command":
            permitted |= {"workdir", "yield_time_ms", "max_output_tokens", "login", "tty"}
            permitted |= {
                "sandbox_permissions",
                "justification",
                "prefix_rule",
                "additional_permissions",
                "environment_id",
            }
        if name == "Bash":
            permitted |= {
                "timeout",
                "description",
                "run_in_background",
                "dangerouslyDisableSandbox",
            }
        if command_key not in values or set(values) - permitted:
            raise ValueError("Invalid tool arguments")
        if not isinstance(values[command_key], str) or _has_malformed_placeholder(
            values[command_key]
        ):
            raise ValueError("Invalid tool arguments")
        allowed_shells = {"sh", "bash", "/bin/sh", "/bin/bash"}
        if "shell" in values and values["shell"] not in allowed_shells:
            raise ValueError("Invalid tool arguments")
        for key in {"yield_time_ms", "max_output_tokens", "timeout"} & values.keys():
            if type(values[key]) is not int or values[key] < 1:
                raise ValueError("Invalid tool arguments")
        for key in {
            "login",
            "tty",
            "run_in_background",
            "dangerouslyDisableSandbox",
        } & values.keys():
            if type(values[key]) is not bool:
                raise ValueError("Invalid tool arguments")
        if "cwd" in values and "workdir" in values:
            raise ValueError("Invalid tool arguments")
        cwd = self.workspace_root
        for key in {"cwd", "workdir"} & values.keys():
            values[key] = path(values[key])
            candidate = Path(values[key])
            cwd = candidate if candidate.is_absolute() else self.workspace_root / candidate
        if "description" in values:
            # This client-local description is an explicitly registered prose
            # value. It grants no additional execution/approval permission.
            values["description"] = content(values["description"])
        if values.get("dangerouslyDisableSandbox", False):
            raise ValueError("Invalid tool arguments")
        if name == "exec_command":
            self._validate_exec_controls(values)
        values[command_key] = restore_shell(
            values[command_key],
            content,
            lambda value: self._validate_path(value, cwd=cwd),
            restore_glob=glob,
        )
        if "prefix_rule" in values:
            import shlex

            prefix = values["prefix_rule"]
            if shlex.split(values[command_key])[: len(prefix)] != prefix:
                raise ValueError("Invalid tool arguments")

    def _validate_exec_controls(self, values: dict[str, Any]) -> None:
        permission = values.get("sandbox_permissions", "use_default")
        if permission not in {"use_default", "require_escalated", "with_additional_permissions"}:
            raise ValueError("Invalid tool arguments")
        if "environment_id" in values:
            # Multiple execution environments require an operator-bound path
            # policy per environment. Accept their public declaration, but do
            # not authorize a tool aimed at an unknown alternate environment.
            raise ValueError("Invalid tool arguments")
        if "justification" in values and (
            not isinstance(values["justification"], str)
            or _has_placeholder(values["justification"])
            or permission != "require_escalated"
        ):
            raise ValueError("Invalid tool arguments")
        if "prefix_rule" in values:
            prefix = values["prefix_rule"]
            if (
                permission != "require_escalated"
                or not isinstance(prefix, list)
                or not 1 <= len(prefix) <= 32
                or any(
                    not isinstance(value, str) or not value or _has_placeholder(value)
                    for value in prefix
                )
            ):
                raise ValueError("Invalid tool arguments")
        if "additional_permissions" not in values:
            if permission == "with_additional_permissions":
                raise ValueError("Invalid tool arguments")
            return
        permissions = values["additional_permissions"]
        if (
            permission != "with_additional_permissions"
            or not isinstance(permissions, dict)
            or permissions.keys() - {"network", "file_system"}
        ):
            raise ValueError("Invalid tool arguments")
        network = permissions.get("network", {})
        if (
            not isinstance(network, dict)
            or network.keys() - {"enabled"}
            or type(network.get("enabled", False)) is not bool
            or network.get("enabled", False)
        ):
            raise ValueError("Invalid tool arguments")
        file_system = permissions.get("file_system", {})
        if not isinstance(file_system, dict) or file_system.keys() - {"read", "write"}:
            raise ValueError("Invalid tool arguments")
        for paths in file_system.values():
            if not isinstance(paths, list) or len(paths) > 64:
                raise ValueError("Invalid tool arguments")
            for value in paths:
                if not isinstance(value, str) or not Path(value).is_absolute():
                    raise ValueError("Invalid tool arguments")
                self._validate_path(value)

    @staticmethod
    def _validate_stdin(values: dict[str, Any]) -> None:
        if "session_id" not in values or values.keys() - {
            "session_id",
            "chars",
            "yield_time_ms",
            "max_output_tokens",
        }:
            raise ValueError("Invalid tool arguments")
        if type(values["session_id"]) is not int or not 0 <= values["session_id"] <= 2**31 - 1:
            raise ValueError("Invalid tool arguments")
        # Unbound interactive stdin could be executable code or a network
        # payload. Only polling and a literal interrupt need no sink receipt.
        if values.get("chars", "") not in {"", "\x03"}:
            raise ValueError("Invalid tool arguments")
        for key in {"yield_time_ms", "max_output_tokens"} & values.keys():
            if type(values[key]) is not int or values[key] < 0:
                raise ValueError("Invalid tool arguments")

    @staticmethod
    def _restore_search(name: str, values: dict[str, Any], content, path, glob) -> None:
        permitted = {"pattern", "path"}
        integer_controls = {"-A", "-B", "-C", "context", "head_limit", "offset"}
        boolean_controls = {"-i", "-n", "-o", "multiline"}
        if name == "Grep":
            permitted |= integer_controls | boolean_controls | {"glob", "type", "output_mode"}
        if "pattern" not in values or values.keys() - permitted:
            raise ValueError("Invalid tool arguments")
        if "path" in values:
            values["path"] = path(values["path"])
        if name == "Glob":
            values["pattern"] = glob(values["pattern"])
            return
        pattern = values["pattern"]
        if not isinstance(pattern, str) or _has_malformed_placeholder(pattern):
            raise ValueError("Invalid tool arguments")
        values["pattern"] = restore_regex(pattern, content)
        if "glob" in values:
            values["glob"] = glob(values["glob"])
        if "type" in values and (
            not isinstance(values["type"], str)
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", values["type"])
        ):
            raise ValueError("Invalid tool arguments")
        if "output_mode" in values and values["output_mode"] not in {
            "content",
            "files_with_matches",
            "count",
        }:
            raise ValueError("Invalid tool arguments")
        for key in integer_controls & values.keys():
            if type(values[key]) is not int or not 0 <= values[key] <= 1_000_000:
                raise ValueError("Invalid tool arguments")
        for key in boolean_controls & values.keys():
            if type(values[key]) is not bool:
                raise ValueError("Invalid tool arguments")

    @staticmethod
    def _restore_todos(values: dict[str, Any], content) -> None:
        if (
            values.keys() != {"todos"}
            or not isinstance(values["todos"], list)
            or len(values["todos"]) > 128
        ):
            raise ValueError("Invalid tool arguments")
        for todo in values["todos"]:
            if (
                not isinstance(todo, dict)
                or todo.keys() != {"content", "status", "activeForm"}
                or todo["status"] not in {"pending", "in_progress", "completed"}
            ):
                raise ValueError("Invalid tool arguments")
            todo["content"] = content(todo["content"])
            todo["activeForm"] = content(todo["activeForm"])
