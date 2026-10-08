"""Bind executable output to this request's declared tools and JSON schemas.

This is a bounded executable-tool schema subset, independent of the broader
structured-output schema visitor. It never resolves references, evaluates
patterns, changes tool choice, or grants permission to run a tool.
"""

from __future__ import annotations

import copy
import json
import math
from typing import Any

from gateway.domain import RequestContext
from gateway.restoration.engine import RestorationEngine, RestorationOutcome
from gateway.tools.patches import validate_apply_patch_format
from gateway.tools.registry import (
    _EDIT,
    _READ,
    _SEARCH,
    _SHELL,
    _SUPPORTED,
    _WRITE,
    ToolRegistry,
    ToolRestorationError,
)
from gateway.transformations.tokens import TokenProvenance

MAX_SCHEMA_DEPTH = 16
MAX_SCHEMA_NODES = 512
MAX_SCHEMA_COLLECTION = 128

_ANNOTATIONS = {
    "title",
    "description",
    "$comment",
    "default",
    "examples",
    "readOnly",
    "writeOnly",
    "deprecated",
}
_BOUNDS = {
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "minProperties",
    "maxProperties",
}
_NUMBER_BOUNDS = {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"}
_COMBINERS = {"allOf", "anyOf", "oneOf"}
_SCHEMA_FIELDS = (
    _ANNOTATIONS
    | _BOUNDS
    | _NUMBER_BOUNDS
    | _COMBINERS
    | {
        "type",
        "properties",
        "required",
        "additionalProperties",
        "enum",
        "const",
        "items",
        "uniqueItems",
        "$schema",
    }
)
_TYPES = {"null", "boolean", "object", "array", "number", "integer", "string"}


def _fail(code: str = "unsupported_tool_schema") -> None:
    raise ToolRestorationError(code)


def _json_literal(value: Any, *, depth: int = 0) -> None:
    """Bound enum/const values without coercion or Python equality surprises."""
    if depth > MAX_SCHEMA_DEPTH:
        _fail()
    if value is None or type(value) in {str, bool, int}:
        return
    if type(value) is float and math.isfinite(value):
        return
    if isinstance(value, (dict, list)):
        if len(value) > MAX_SCHEMA_COLLECTION:
            _fail()
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                _fail()
            values = value.values()
        else:
            values = value
        for item in values:
            _json_literal(item, depth=depth + 1)
        return
    _fail()


def _compile_schema(schema: Any, *, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [MAX_SCHEMA_NODES]
    budget[0] -= 1
    if depth > MAX_SCHEMA_DEPTH or budget[0] < 0:
        _fail()
    if type(schema) is bool:
        return
    if not isinstance(schema, dict) or schema.keys() - _SCHEMA_FIELDS:
        _fail()
    for key, value in schema.items():
        if key == "$schema":
            if value != "https://json-schema.org/draft/2020-12/schema":
                _fail()
        elif key in _ANNOTATIONS:
            # These were classified and inspected by the protocol visitor.
            # They grant no execution permissions and impose no assertions.
            continue
        if key == "type":
            types = value if isinstance(value, list) else [value]
            if (
                not types
                or len(types) > len(_TYPES)
                or any(not isinstance(kind, str) or kind not in _TYPES for kind in types)
                or len(set(types)) != len(types)
            ):
                _fail()
        elif key == "properties":
            if not isinstance(value, dict) or len(value) > MAX_SCHEMA_COLLECTION:
                _fail()
            for name, child in value.items():
                if not isinstance(name, str):
                    _fail()
                _compile_schema(child, depth=depth + 1, budget=budget)
        elif key == "required":
            if (
                not isinstance(value, list)
                or len(value) > MAX_SCHEMA_COLLECTION
                or any(not isinstance(name, str) for name in value)
                or len(set(value)) != len(value)
            ):
                _fail()
        elif key in {"additionalProperties", "items"}:
            _compile_schema(value, depth=depth + 1, budget=budget)
        elif key in _COMBINERS:
            if not isinstance(value, list) or not value or len(value) > MAX_SCHEMA_COLLECTION:
                _fail()
            for child in value:
                _compile_schema(child, depth=depth + 1, budget=budget)
        elif key in _BOUNDS:
            if type(value) is not int or value < 0:
                _fail()
        elif key in _NUMBER_BOUNDS:
            if type(value) not in {int, float} or not math.isfinite(value):
                _fail()
        elif key == "uniqueItems":
            if type(value) is not bool:
                _fail()
        elif key == "enum":
            if not isinstance(value, list) or not value or len(value) > MAX_SCHEMA_COLLECTION:
                _fail()
            for literal in value:
                _json_literal(literal)
        elif key == "const":
            _json_literal(value)


def _equal(left: Any, right: Any) -> bool:
    if type(left) is bool or type(right) is bool:
        return type(left) is type(right) and left == right
    if type(left) in {int, float} and type(right) in {int, float}:
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _equal(value, right[key]) for key, value in left.items()
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _equal(a, b) for a, b in zip(left, right, strict=True)
        )
    return left == right


def _is_type(value: Any, kind: str) -> bool:
    if kind == "null":
        return value is None
    if kind == "integer":
        return type(value) is int or (type(value) is float and value.is_integer())
    if kind == "number":
        return type(value) in {int, float}
    return type(value) is {"boolean": bool, "object": dict, "array": list, "string": str}[kind]


def _matches(schema: dict | bool, value: Any) -> bool:
    if type(schema) is bool:
        return schema
    if "type" in schema:
        kinds = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_is_type(value, kind) for kind in kinds):
            return False
    if "const" in schema and not _equal(value, schema["const"]):
        return False
    if "enum" in schema and not any(_equal(value, member) for member in schema["enum"]):
        return False
    for key in _COMBINERS & schema.keys():
        matches = [_matches(child, value) for child in schema[key]]
        if (key == "allOf" and not all(matches)) or (key == "anyOf" and not any(matches)):
            return False
        if key == "oneOf" and sum(matches) != 1:
            return False
    if isinstance(value, dict):
        if any(name not in value for name in schema.get("required", [])):
            return False
        properties = schema.get("properties", {})
        for name, item in value.items():
            child = properties.get(name, schema.get("additionalProperties", True))
            if not _matches(child, item):
                return False
        if len(value) < schema.get("minProperties", 0) or len(value) > schema.get(
            "maxProperties", math.inf
        ):
            return False
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get(
            "maxLength", math.inf
        ):
            return False
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", math.inf):
            return False
        if not all(_matches(schema.get("items", True), item) for item in value):
            return False
        if schema.get("uniqueItems", False) and any(
            _equal(value[index], item) for index, item in enumerate(value) for item in value[:index]
        ):
            return False
    if type(value) in {int, float}:
        if "minimum" in schema and value < schema["minimum"]:
            return False
        if "maximum" in schema and value > schema["maximum"]:
            return False
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            return False
        if "exclusiveMaximum" in schema and value >= schema["exclusiveMaximum"]:
            return False
    return True


def _fields_for(name: str) -> set[str]:
    if name in _READ | _WRITE | _EDIT:
        fields = {"file_path" if name in {"Read", "Edit", "Write"} else "path"}
        if name in _READ:
            return fields | (
                {"offset", "limit", "pages"} if name == "Read" else {"start_line", "end_line"}
            )
        if name in _WRITE:
            return fields | {"content"}
        return (
            fields
            | {"old_string", "new_string", "replace_all"}
            | ({"old_text", "new_text"} if name != "Edit" else set())
        )
    if name == "apply_patch":
        return {"patch"}
    if name == "write_stdin":
        return {"session_id", "chars", "yield_time_ms", "max_output_tokens"}
    if name == "TodoWrite":
        return {"todos"}
    if name in _SEARCH:
        fields = {"path", "pattern"}
        if name == "Grep":
            fields |= {
                "glob",
                "output_mode",
                "-i",
                "-n",
                "-o",
                "multiline",
                "-A",
                "-B",
                "-C",
                "context",
                "head_limit",
                "offset",
                "type",
            }
        return fields
    if name in _SHELL:
        fields = {"cmd" if name == "exec_command" else "command", "shell", "cwd"}
        if name == "exec_command":
            fields |= {"workdir", "yield_time_ms", "max_output_tokens", "login", "tty"}
            fields |= {
                "sandbox_permissions",
                "justification",
                "prefix_rule",
                "additional_permissions",
                "environment_id",
            }
        if name == "Bash":
            fields |= {"timeout", "description", "run_in_background", "dangerouslyDisableSandbox"}
        return fields
    _fail("unsupported_tool")


def _field_types(name: str) -> dict[str, Any]:
    integers = {
        "offset",
        "limit",
        "start_line",
        "end_line",
        "yield_time_ms",
        "max_output_tokens",
        "timeout",
        "session_id",
        "-A",
        "-B",
        "-C",
        "context",
        "head_limit",
    }
    booleans = {
        "replace_all",
        "login",
        "tty",
        "-i",
        "-n",
        "-o",
        "multiline",
        "run_in_background",
        "dangerouslyDisableSandbox",
    }
    fields = {
        field: "integer" if field in integers else "boolean" if field in booleans else "string"
        for field in _fields_for(name)
    }
    if name == "exec_command":
        fields["prefix_rule"] = ("string",)
        fields["additional_permissions"] = {
            "network": {"enabled": "boolean"},
            "file_system": {"read": ("string",), "write": ("string",)},
        }
    if name == "TodoWrite":
        fields["todos"] = ({"content": "string", "activeForm": "string", "status": "string"},)
    return fields


def _check_property_type(schema: dict | bool, expected: Any) -> None:
    if type(schema) is bool:
        return
    if "type" in schema:
        kinds = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        kind = (
            "object"
            if isinstance(expected, dict)
            else "array"
            if isinstance(expected, tuple)
            else expected
        )
        compatible = {kind} | ({"number"} if kind == "integer" else set())
        if not set(kinds) <= compatible:
            _fail()
    if isinstance(expected, dict):
        if (
            schema.get("properties", {}).keys() - expected.keys()
            or set(schema.get("required", [])) - expected.keys()
        ):
            _fail()
        for field, child in schema.get("properties", {}).items():
            _check_property_type(child, expected[field])
        if isinstance(schema.get("additionalProperties"), dict):
            _fail()
    elif isinstance(expected, tuple) and "items" in schema:
        _check_property_type(schema["items"], expected[0])
    for key in _COMBINERS & schema.keys():
        for child in schema[key]:
            _check_property_type(child, expected)


def _check_flat_contract(schema: dict | bool, fields: dict[str, Any]) -> None:
    if type(schema) is bool:
        return
    kinds = schema.get("type", ["object"])
    kinds = kinds if isinstance(kinds, list) else [kinds]
    if "object" not in kinds:
        _fail()
    if (
        set(schema.get("properties", {})) - fields.keys()
        or set(schema.get("required", [])) - fields.keys()
    ):
        _fail()
    for field, child in schema.get("properties", {}).items():
        _check_property_type(child, fields[field])
    for key in _COMBINERS & schema.keys():
        for child in schema[key]:
            _check_flat_contract(child, fields)


class BoundToolRegistry:
    """One immutable request's executable declarations and completion limits.

    ``restore`` may be called repeatedly for protocol snapshots. It never counts
    calls. ``validate_batch`` must run once on the complete final batch (including
    an empty batch), before the caller releases any executable output.
    """

    def __init__(self, registry: ToolRegistry, request_payload: dict, protocol: str) -> None:
        self.registry = registry
        self.protocol = protocol
        self.declared: dict[str, tuple[bool, dict | bool | None]] = {}
        self.required = False
        self.selected: tuple[str, bool] | None = None
        self.forbidden = False
        self.max_calls = 512
        try:
            if protocol not in {"responses", "messages"}:
                _fail("unsupported_tool_protocol")
            definitions = request_payload.get("tools", [])
            if not isinstance(definitions, list) or len(definitions) > MAX_SCHEMA_COLLECTION:
                _fail()
            for definition in definitions:
                if not isinstance(definition, dict):
                    _fail("unsupported_tool_format")
                name = definition["name"]
                if not isinstance(name, str) or name not in _SUPPORTED or name in self.declared:
                    _fail("unsupported_tool")
                custom = protocol == "responses" and definition.get("type") == "custom"
                if protocol == "responses" and definition.get("type") not in {"function", "custom"}:
                    _fail("unsupported_tool_format")
                if protocol == "messages" and definition.get("type") not in {None, "custom"}:
                    _fail("unsupported_tool_format")
                if custom:
                    if name != "apply_patch":
                        _fail("unsupported_tool_format")
                    validate_apply_patch_format(definition.get("format", {"type": "text"}))
                    schema = None
                else:
                    schema = definition["parameters" if protocol == "responses" else "input_schema"]
                    _compile_schema(schema)
                    _check_flat_contract(schema, _field_types(name))
                self.declared[name] = (custom, copy.deepcopy(schema))
            choice = request_payload.get(
                "tool_choice", "auto" if protocol == "responses" else {"type": "auto"}
            )
            if protocol == "responses":
                if isinstance(choice, str):
                    if choice not in {"auto", "none", "required"}:
                        _fail("invalid_tool_choice")
                    self.forbidden = choice == "none"
                    self.required = choice == "required"
                else:
                    if choice["type"] not in {"function", "custom"}:
                        _fail("invalid_tool_choice")
                    self.selected = (choice["name"], choice["type"] == "custom")
                    self.required = True
                if type(request_payload.get("parallel_tool_calls", True)) is not bool:
                    _fail("invalid_tool_choice")
                if request_payload.get("parallel_tool_calls", True) is False:
                    self.max_calls = 1
                if "max_tool_calls" in request_payload:
                    limit = request_payload["max_tool_calls"]
                    if type(limit) is not int or limit < 1:
                        _fail("invalid_tool_choice")
                    self.max_calls = min(self.max_calls, limit)
            else:
                kind = choice["type"]
                if kind not in {"auto", "any", "none", "tool"}:
                    _fail("invalid_tool_choice")
                self.forbidden = kind == "none"
                self.required = kind in {"any", "tool"}
                if kind == "tool":
                    self.selected = (choice["name"], False)
                if type(choice.get("disable_parallel_tool_use", False)) is not bool:
                    _fail("invalid_tool_choice")
                if choice.get("disable_parallel_tool_use", False):
                    self.max_calls = 1
            if self.required and not self.declared:
                _fail("invalid_tool_choice")
            if self.selected is not None:
                name, custom = self.selected
                if name not in self.declared or self.declared[name][0] != custom:
                    _fail("invalid_tool_choice")
        except ToolRestorationError:
            raise
        except (TypeError, ValueError, KeyError, RecursionError, OverflowError):
            raise ToolRestorationError("unsupported_tool_schema") from None

    def _call_allowed(self, name: str, custom: bool) -> None:
        if not isinstance(name, str) or type(custom) is not bool:
            _fail("undeclared_tool_call")
        if self.forbidden or name not in self.declared:
            _fail("undeclared_tool_call")
        if self.declared[name][0] != custom or (
            self.selected is not None and self.selected != (name, custom)
        ):
            _fail("tool_choice_violation")

    def validate_batch(self, calls: list[tuple[str, str, bool]]) -> None:
        """Enforce call-count and selection constraints on a complete response."""
        if not isinstance(calls, list):
            _fail("tool_choice_violation")
        if len(calls) > self.max_calls or (self.required and not calls):
            _fail("tool_choice_violation")
        for call in calls:
            if not isinstance(call, tuple) or len(call) != 3 or not isinstance(call[1], str):
                _fail("tool_choice_violation")
            name, _arguments, custom = call
            self._call_allowed(name, custom)

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
        self._call_allowed(name, custom)
        result, outcome = self.registry.restore(
            ctx, name, arguments, provenance, restorer, custom=custom
        )
        schema = self.declared[name][1]
        if not custom and not _matches(schema, json.loads(result)):
            outcome.text = ""
            raise ToolRestorationError("tool_schema_violation", outcome)
        return result, outcome
