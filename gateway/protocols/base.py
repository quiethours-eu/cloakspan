"""Strict, provider-independent primitives for inspectable agent protocols.

Locations retain the native shape. JSON-encoded argument locations identify a
string field in ``path`` and the decoded leaf in ``json_path``; rebuilding an
argument always uses a JSON serializer, never string substitution.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from gateway.api.schema import RequestRejected

MAX_DEPTH = 32
MAX_COLLECTION = 512
MAX_JSON_BYTES = 4 * 1024 * 1024
Path = tuple[str | int, ...]


@dataclass(frozen=True, slots=True)
class ContentLocation:
    path: Path
    text: str
    structural: bool = False
    json_path: Path | None = None


@dataclass(slots=True)
class ValidatedRequest:
    protocol: str
    payload: dict[str, Any]
    locations: list[ContentLocation]
    stream: bool

    @property
    def model(self) -> str:
        return self.payload["model"]

    @property
    def tools(self) -> list[dict[str, Any]]:
        return self.payload.get("tools", [])

    @property
    def tool_definitions(self) -> list[dict[str, Any]]:
        return self.tools


def reject(code: str = "invalid_request", detail: str | None = None) -> None:
    # Never interpolate keys, values, paths, or validation-library errors.
    raise RequestRejected(
        400 if code == "invalid_json" else 413 if code == "request_too_large" else 422,
        code,
        detail or "Request does not match the supported inspectable protocol contract.",
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            reject("invalid_json", "Duplicate JSON keys are not supported.")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    reject("invalid_json", "JSON numeric values must be finite.")


def bounded_json(value: Any) -> None:
    """Check decoded trees, including callers supplying Python objects directly."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_DEPTH:
            reject("request_too_large", "JSON nesting exceeds the supported limit.")
        if isinstance(node, dict):
            if len(node) > MAX_COLLECTION:
                reject("request_too_large", "JSON object exceeds the supported collection limit.")
            for key, item in node.items():
                if not isinstance(key, str):
                    reject("invalid_json", "JSON object keys must be strings.")
                stack.append((key, depth + 1))
                stack.append((item, depth + 1))
        elif isinstance(node, list):
            if len(node) > MAX_COLLECTION:
                reject("request_too_large", "JSON array exceeds the supported collection limit.")
            stack.extend((item, depth + 1) for item in node)
        elif isinstance(node, str):
            if any(0xD800 <= ord(char) <= 0xDFFF for char in node):
                reject("invalid_json", "JSON strings must contain valid Unicode characters.")
        elif isinstance(node, float):
            if not math.isfinite(node):
                reject("invalid_json", "JSON numeric values must be finite.")
        elif node is not None and type(node) not in (bool, int):
            reject("invalid_json", "Request contains a value that is not a JSON type.")


def loads_json(data: bytes | str) -> Any:
    """Decode unambiguous UTF-8 JSON without echoing rejected customer data."""
    if not isinstance(data, (bytes, str)):
        reject("invalid_json", "Request must be encoded as UTF-8 JSON.")
    try:
        if isinstance(data, bytes):
            if len(data) > MAX_JSON_BYTES:
                reject("request_too_large", "JSON body exceeds the supported byte limit.")
            data = data.decode("utf-8", errors="strict")
        elif len(data.encode("utf-8", errors="strict")) > MAX_JSON_BYTES:
            reject("request_too_large", "JSON body exceeds the supported byte limit.")
        result = json.loads(data, object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise RequestRejected(
            400, "invalid_json", "Request must contain valid UTF-8 JSON."
        ) from exc
    bounded_json(result)
    return result


def request_body(body: Any) -> dict[str, Any]:
    if isinstance(body, (str, bytes)):
        body = loads_json(body)
    bounded_json(body)
    if not isinstance(body, dict):
        raise RequestRejected(400, "invalid_request", "Request body must be a JSON object.")
    return body


def object_fields(
    value: Any, allowed: set[str], required: set[str] | None = None
) -> dict[str, Any]:
    if not isinstance(value, dict):
        reject()
    if not value.keys() <= allowed:
        reject("unknown_field", "Request includes a field outside the supported contract.")
    if required and not required <= value.keys():
        reject("invalid_request", "Request is missing a required protocol field.")
    return value


def array(value: Any, *, nonempty: bool = False) -> list[Any]:
    if not isinstance(value, list) or len(value) > MAX_COLLECTION or (nonempty and not value):
        reject()
    return value


def string(value: Any) -> str:
    if not isinstance(value, str):
        reject()
    return value


def boolean(value: Any) -> bool:
    if type(value) is not bool:
        reject()
    return value


def integer(value: Any, minimum: int = 0, maximum: int = 2**31 - 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        reject()
    return value


def number(value: Any, minimum: float, maximum: float) -> float | int:
    if type(value) not in (int, float) or (type(value) is float and not math.isfinite(value)):
        reject()
    if not minimum <= value <= maximum:
        reject()
    return value


def choice(value: Any, choices: set[str]) -> str:
    if not isinstance(value, str) or value not in choices:
        reject("unsupported_field", "Request selects an unsupported protocol capability.")
    return value


def identifier(value: Any, *, model: bool = False, tool: bool = False) -> str:
    value = string(value)
    pattern = r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}" if model else r"[A-Za-z0-9_-]{1,128}"
    if tool:
        pattern = r"[A-Za-z0-9_-]{1,64}"
    if re.fullmatch(pattern, value) is None:
        reject("invalid_identifier", "Protocol identifiers must match the supported grammar.")
    return value


def cache_control(value: Any) -> dict[str, Any]:
    source = object_fields(value, {"type", "ttl"}, {"type"})
    result: dict[str, Any] = {"type": choice(source["type"], {"ephemeral"})}
    if "ttl" in source:
        result["ttl"] = choice(source["ttl"], {"5m", "1h"})
    return result


class LocationBuilder:
    """Classify all strings, including arbitrary JSON keys and control values."""

    def __init__(self) -> None:
        self.content_paths: set[Path] = set()
        self.numeric_paths: set[Path] = set()
        self.json_fields: dict[Path, Any] = {}
        self.structural_json_fields: set[Path] = set()
        self.json_numeric_controls: dict[Path, set[Path]] = {}

    def numeric(self, value: int | float, path: Path) -> int | float:
        self.numeric_paths.add(path)
        return value

    def text(self, value: Any, path: Path) -> str:
        value = string(value)
        self.content_paths.add(path)
        return value

    def arguments(self, value: Any, path: Path) -> str:
        return self.encoded_object(value, path)

    def encoded_object(
        self,
        value: Any,
        path: Path,
        *,
        structural: bool = False,
        numeric_controls: set[Path] | None = None,
    ) -> str:
        decoded = loads_json(string(value))
        if not isinstance(decoded, dict):
            reject("invalid_arguments", "Function arguments must encode a JSON object.")
        self.json_fields[path] = decoded
        if structural:
            self.structural_json_fields.add(path)
        if numeric_controls:
            self.json_numeric_controls[path] = numeric_controls
        return json.dumps(decoded, ensure_ascii=False, separators=(",", ":"), allow_nan=False)

    def json_content(self, value: Any, path: Path, *, structural: bool = False) -> Any:
        """Copy a bounded JSON value and classify its strings and keys."""
        if isinstance(value, dict):
            return {
                key: self.json_content(item, path + (key,), structural=structural)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [
                self.json_content(item, path + (index,), structural=structural)
                for index, item in enumerate(value)
            ]
        if isinstance(value, str) and not structural:
            self.content_paths.add(path)
        elif type(value) in (int, float):
            self.numeric_paths.add(path)
        return value

    def finish(self, payload: dict[str, Any]) -> list[ContentLocation]:
        locations: list[ContentLocation] = []

        def walk(value: Any, path: Path, json_path: Path | None = None) -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    child = (json_path or ()) + (key,) if json_path is not None else None
                    target = path if json_path is not None else path + (key,)
                    locations.append(ContentLocation(target, key, True, child))
                    walk(item, target, child)
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    child = (json_path or ()) + (index,) if json_path is not None else None
                    walk(item, path if json_path is not None else path + (index,), child)
            elif isinstance(value, str):
                if path in self.json_fields and json_path is None:
                    walk(self.json_fields[path], path, ())
                else:
                    structural = (
                        json_path is None and path not in self.content_paths
                    ) or path in self.structural_json_fields
                    locations.append(ContentLocation(path, value, structural, json_path))
            elif (
                type(value) in (int, float)
                and (json_path is not None or path in self.numeric_paths)
                and json_path not in self.json_numeric_controls.get(path, set())
            ):
                # Numeric customer values can carry detectable identifiers too.
                # They cannot become string placeholders without changing JSON
                # and schema semantics, so sensitive numeric content must block.
                try:
                    text = str(value) if type(value) is int else format(Decimal(str(value)), "f")
                except ValueError:
                    reject(
                        "invalid_json", "JSON integer exceeds the supported representation limit."
                    )
                locations.append(ContentLocation(path, text, True, json_path))

        walk(payload, ())
        return locations


def replace_location(payload: dict[str, Any], location: ContentLocation, text: str) -> None:
    """Replace a text leaf, maintaining valid nested JSON argument encoding."""
    if location.structural:
        raise ValueError("Structural locations cannot be transformed.")
    if text == location.text:
        return
    target: Any = payload
    for part in location.path[:-1]:
        target = target[part]
    key = location.path[-1]
    if location.json_path is None:
        target[key] = text
        return
    decoded = loads_json(target[key])
    if not location.json_path:
        decoded = text
    else:
        leaf = decoded
        for part in location.json_path[:-1]:
            leaf = leaf[part]
        leaf[location.json_path[-1]] = text
    target[key] = json.dumps(decoded, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


_SCHEMA_TEXT = {"title", "description", "$comment"}
_SCHEMA_STRING = {
    "$schema",
    "$id",
    "$anchor",
    "$dynamicAnchor",
    "$ref",
    "$dynamicRef",
    "pattern",
    "format",
    "contentEncoding",
    "contentMediaType",
}
_SCHEMA_NUMBER = {"multipleOf", "maximum", "exclusiveMaximum", "minimum", "exclusiveMinimum"}
_SCHEMA_COUNT = {
    "maxLength",
    "minLength",
    "maxItems",
    "minItems",
    "maxContains",
    "minContains",
    "maxProperties",
    "minProperties",
}
_SCHEMA_BOOL = {"uniqueItems", "readOnly", "writeOnly", "deprecated"}
_SCHEMA_OBJECT = {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"}
_SCHEMA_CHILD = {
    "items",
    "contains",
    "additionalProperties",
    "unevaluatedProperties",
    "unevaluatedItems",
    "propertyNames",
    "not",
    "if",
    "then",
    "else",
    "contentSchema",
}
_SCHEMA_ARRAY = {"allOf", "anyOf", "oneOf", "prefixItems"}
_SCHEMA_OTHER = {"type", "required", "enum", "const", "default", "examples", "dependentRequired"}
_SCHEMA_FIELDS = (
    _SCHEMA_TEXT
    | _SCHEMA_STRING
    | _SCHEMA_NUMBER
    | _SCHEMA_COUNT
    | _SCHEMA_BOOL
    | _SCHEMA_OBJECT
    | _SCHEMA_CHILD
    | _SCHEMA_ARRAY
    | _SCHEMA_OTHER
)


def json_schema(value: Any, path: Path, builder: LocationBuilder) -> dict[str, Any] | bool:
    """Rebuild supported JSON Schema, treating semantic strings as structural.

    Descriptions and examples can be transformed. Keys, enum/default values,
    patterns, types and references affect validation and must remain identical.
    Remote schema references would introduce uninspected provider input.
    """
    if type(value) is bool:
        return value
    source = object_fields(value, _SCHEMA_FIELDS)
    result: dict[str, Any] = {}
    for key, item in source.items():
        child = path + (key,)
        if key in _SCHEMA_TEXT:
            result[key] = builder.text(item, child)
        elif key in _SCHEMA_STRING:
            result[key] = string(item)
            if key in {"$ref", "$dynamicRef"} and not item.startswith("#"):
                reject("uninspectable_field", "External schema references are not supported.")
        elif key in _SCHEMA_NUMBER:
            if type(item) not in (int, float) or (type(item) is float and not math.isfinite(item)):
                reject()
            result[key] = builder.numeric(item, child)
        elif key in _SCHEMA_COUNT:
            result[key] = builder.numeric(integer(item), child)
        elif key in _SCHEMA_BOOL:
            result[key] = boolean(item)
        elif key in _SCHEMA_OBJECT:
            if not isinstance(item, dict):
                reject()
            result[key] = {
                name: json_schema(schema, child + (name,), builder) for name, schema in item.items()
            }
        elif key in _SCHEMA_CHILD:
            result[key] = json_schema(item, child, builder)
        elif key in _SCHEMA_ARRAY:
            result[key] = [
                json_schema(schema, child + (index,), builder)
                for index, schema in enumerate(array(item, nonempty=True))
            ]
        elif key == "type":
            types = {"null", "boolean", "object", "array", "number", "string", "integer"}
            result[key] = (
                [choice(t, types) for t in array(item, nonempty=True)]
                if isinstance(item, list)
                else choice(item, types)
            )
        elif key == "required":
            result[key] = [string(name) for name in array(item)]
            if len(set(result[key])) != len(result[key]):
                reject()
        elif key == "dependentRequired":
            if not isinstance(item, dict):
                reject()
            result[key] = {name: [string(s) for s in array(names)] for name, names in item.items()}
        elif key == "enum":
            result[key] = builder.json_content(array(item, nonempty=True), child, structural=True)
        elif key == "examples":
            result[key] = builder.json_content(array(item), child)
        else:
            result[key] = builder.json_content(item, child, structural=True)
    return result
