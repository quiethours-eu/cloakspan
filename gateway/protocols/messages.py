"""Native Messages contract; inspect text, tool schemas, calls and replay results."""

from __future__ import annotations

import json
import re
from typing import Any

from gateway.protocols.base import (
    LocationBuilder,
    Path,
    ValidatedRequest,
    array,
    boolean,
    cache_control,
    choice,
    identifier,
    integer,
    json_schema,
    loads_json,
    number,
    object_fields,
    reject,
    request_body,
    string,
)

# These controls select capabilities whose text/tool/cache shapes are covered
# by this contract. They never permit opaque thinking or server-side state.
# Pinned Claude Code 2.1.293 retains the first two even when experimental betas
# are disabled. Unsupported beta headers fail closed at the API boundary.
SUPPORTED_MESSAGES_BETAS = frozenset(
    {
        "claude-code-20250219",
        "effort-2025-11-24",
        "interleaved-thinking-2025-05-14",
        "context-1m-2025-08-07",
        "extended-cache-ttl-2025-04-11",
        "prompt-caching-2024-07-31",
        "token-counting-2024-11-01",
        "token-efficient-tools-2025-02-19",
        "fine-grained-tool-streaming-2025-05-14",
    }
)

_FIELDS = {
    "model",
    "messages",
    "max_tokens",
    "stream",
    "system",
    "tools",
    "tool_choice",
    "temperature",
    "top_p",
    "top_k",
    "stop_sequences",
    "service_tier",
    "thinking",
    "metadata",
    "cache_control",
    "output_config",
}
_OPAQUE = {"container", "mcp_servers", "context_management"}

_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"


def _metadata(value: Any) -> dict[str, str]:
    """Validate local-only opaque identity controls; never allow arbitrary text.

    The official SDK accepts an opaque identifier. Pinned Claude Code instead
    sends three typed identifiers encoded as a JSON string. The runtime consumes
    this metadata locally after inspection; it is never provider telemetry.
    """
    source = object_fields(value, {"user_id"})
    if "user_id" not in source:
        return {}
    user_id = string(source["user_id"])
    if len(user_id) > 512:
        reject("invalid_metadata", "Metadata identity exceeds the supported limit.")
    if user_id.startswith("{"):
        identity = object_fields(
            loads_json(user_id),
            {"device_id", "account_uuid", "session_id"},
            {"device_id", "account_uuid", "session_id"},
        )
        device = string(identity["device_id"])
        account = string(identity["account_uuid"])
        session = string(identity["session_id"])
        if (
            re.fullmatch(r"[0-9a-f]{64}", device) is None
            or (account and re.fullmatch(_UUID, account) is None)
            or re.fullmatch(_UUID, session) is None
        ):
            reject("invalid_metadata", "Metadata identity must contain supported opaque IDs.")
        return {"user_id": json.dumps(identity, separators=(",", ":"), ensure_ascii=True)}
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}", user_id) is None:
        reject("invalid_metadata", "Metadata identity must be a bounded opaque ID.")
    return {"user_id": user_id}


def _text(value: Any, path: Path, builder: LocationBuilder) -> dict[str, Any]:
    source = object_fields(value, {"type", "text", "cache_control", "citations"}, {"type", "text"})
    result: dict[str, Any] = {
        "type": choice(source["type"], {"text"}),
        "text": builder.text(source["text"], path + ("text",)),
    }
    if "cache_control" in source:
        result["cache_control"] = cache_control(source["cache_control"])
    if "citations" in source:
        if array(source["citations"]):
            reject("uninspectable_field", "Citation references are not supported on replay.")
        result["citations"] = []
    return result


def _block(value: Any, path: Path, builder: LocationBuilder, role: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        reject()
    kind = value.get("type")
    if not isinstance(kind, str):
        reject()
    if kind == "text":
        return _text(value, path, builder)
    if kind == "tool_use" and role == "assistant":
        source = object_fields(
            value, {"type", "id", "name", "input", "cache_control"}, {"type", "id", "name", "input"}
        )
        if not isinstance(source["input"], dict):
            reject("invalid_arguments", "Native tool input must be a JSON object.")
        result = {
            "type": "tool_use",
            "id": identifier(source["id"]),
            "name": identifier(source["name"], tool=True),
            "input": builder.json_content(source["input"], path + ("input",)),
        }
    elif kind == "tool_result" and role == "user":
        source = object_fields(
            value,
            {"type", "tool_use_id", "content", "is_error", "cache_control"},
            {"type", "tool_use_id", "content"},
        )
        content = source["content"]
        result = {
            "type": "tool_result",
            "tool_use_id": identifier(source["tool_use_id"]),
            "content": builder.text(content, path + ("content",))
            if isinstance(content, str)
            else [
                _text(block, path + ("content", index), builder)
                for index, block in enumerate(array(content))
            ],
        }
        if "is_error" in source:
            result["is_error"] = boolean(source["is_error"])
    else:
        reject(
            "uninspectable_field",
            "Only text and correctly associated tool content blocks are supported.",
        )
    if "cache_control" in source:
        result["cache_control"] = cache_control(source["cache_control"])
    return result


def _tool(value: Any, path: Path, builder: LocationBuilder) -> dict[str, Any]:
    source = object_fields(
        value,
        {"type", "name", "description", "input_schema", "cache_control"},
        {"name", "input_schema"},
    )
    result: dict[str, Any] = {
        "name": identifier(source["name"], tool=True),
        "input_schema": json_schema(source["input_schema"], path + ("input_schema",), builder),
    }
    if not isinstance(result["input_schema"], dict):
        reject()
    if "type" in source:
        result["type"] = choice(source["type"], {"custom"})
    if "description" in source:
        result["description"] = builder.text(source["description"], path + ("description",))
    if "cache_control" in source:
        result["cache_control"] = cache_control(source["cache_control"])
    return result


def _tool_choice(value: Any) -> dict[str, Any]:
    source = object_fields(value, {"type", "name", "disable_parallel_tool_use"}, {"type"})
    kind = choice(source["type"], {"auto", "any", "none", "tool"})
    result: dict[str, Any] = {"type": kind}
    if kind == "tool":
        if "name" not in source:
            reject()
        result["name"] = identifier(source["name"], tool=True)
    elif "name" in source:
        reject()
    if "disable_parallel_tool_use" in source:
        result["disable_parallel_tool_use"] = boolean(source["disable_parallel_tool_use"])
    return result


def parse_messages_request(body: Any) -> ValidatedRequest:
    """Rebuild the native request; unsupported blocks never survive validation."""
    body = request_body(body)
    if body.keys() & _OPAQUE:
        reject(
            "uninspectable_field",
            "Opaque provider state is disabled.",
        )
    source = object_fields(body, _FIELDS, {"model", "messages", "max_tokens"})
    builder = LocationBuilder()
    result: dict[str, Any] = {
        "model": identifier(source["model"], model=True),
        "max_tokens": integer(source["max_tokens"], 1),
        "messages": [],
    }
    seen_calls: set[str] = set()
    seen_results: set[str] = set()
    for index, message in enumerate(array(source["messages"], nonempty=True)):
        msg = object_fields(message, {"role", "content"}, {"role", "content"})
        role = choice(msg["role"], {"user", "assistant"})
        content = msg["content"]
        path = ("messages", index, "content")
        blocks = (
            builder.text(content, path)
            if isinstance(content, str)
            else [
                _block(block, path + (block_index,), builder, role)
                for block_index, block in enumerate(array(content, nonempty=True))
            ]
        )
        if isinstance(blocks, list):
            for block in blocks:
                if block["type"] == "tool_use":
                    if block["id"] in seen_calls:
                        reject("invalid_history", "Replayed tool identifiers must be unique.")
                    seen_calls.add(block["id"])
                elif block["type"] == "tool_result":
                    call_id = block["tool_use_id"]
                    if call_id not in seen_calls or call_id in seen_results:
                        reject(
                            "invalid_history", "Tool results must match a preceding unique call."
                        )
                    seen_results.add(call_id)
        result["messages"].append({"role": role, "content": blocks})
    if "system" in source:
        system = source["system"]
        result["system"] = (
            builder.text(system, ("system",))
            if isinstance(system, str)
            else [
                _text(block, ("system", index), builder)
                for index, block in enumerate(array(system))
            ]
        )
    if "stream" in source:
        result["stream"] = boolean(source["stream"])
    for field in ("temperature", "top_p"):
        if field in source:
            result[field] = number(source[field], 0, 1)
    if "top_k" in source:
        result["top_k"] = integer(source["top_k"])
    if "stop_sequences" in source:
        result["stop_sequences"] = [
            builder.text(stop, ("stop_sequences", index))
            for index, stop in enumerate(array(source["stop_sequences"]))
        ]
    if "service_tier" in source:
        result["service_tier"] = choice(source["service_tier"], {"auto", "standard_only"})
    if "thinking" in source:
        thinking = object_fields(source["thinking"], {"type"}, {"type"})
        result["thinking"] = {"type": choice(thinking["type"], {"disabled"})}
    if "metadata" in source:
        result["metadata"] = _metadata(source["metadata"])
    if "cache_control" in source:
        result["cache_control"] = cache_control(source["cache_control"])
    if "output_config" in source:
        output = object_fields(source["output_config"], {"effort"})
        result["output_config"] = (
            {"effort": choice(output["effort"], {"low", "medium", "high", "xhigh", "max"})}
            if "effort" in output
            else {}
        )
    if "tools" in source:
        result["tools"] = [
            _tool(tool, ("tools", index), builder)
            for index, tool in enumerate(array(source["tools"]))
        ]
        names = [tool["name"] for tool in result["tools"]]
        if len(set(names)) != len(names):
            reject("invalid_tools", "Tool names must be unique.")
    if "tool_choice" in source:
        result["tool_choice"] = _tool_choice(source["tool_choice"])
        if result["tool_choice"]["type"] == "tool" and not any(
            tool["name"] == result["tool_choice"]["name"] for tool in result.get("tools", [])
        ):
            reject("invalid_tools", "Selected tool must be declared in this request.")
    locations = builder.finish(result)
    if (
        sum(
            location.path[-2:] == ("cache_control", "type") and location.text == "ephemeral"
            for location in locations
        )
        > 4
    ):
        reject("invalid_cache_control", "At most four explicit cache breakpoints are supported.")
    return ValidatedRequest("messages", result, locations, result.get("stream", False))
