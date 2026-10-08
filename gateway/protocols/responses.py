"""Strict Responses requests with typed locations in their original shape."""

from __future__ import annotations

import json
import re
from typing import Any

from gateway.api.schema import RequestRejected
from gateway.protocols.base import (
    LocationBuilder,
    Path,
    ValidatedRequest,
    array,
    boolean,
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

_FIELDS = {
    "model",
    "input",
    "instructions",
    "stream",
    "store",
    "background",
    "tools",
    "tool_choice",
    "parallel_tool_calls",
    "max_output_tokens",
    "max_tool_calls",
    "temperature",
    "top_p",
    "truncation",
    "text",
    "reasoning",
    "service_tier",
    "include",
    "prompt_cache_key",
    "client_metadata",
}
_OPAQUE = {
    "previous_response_id",
    "metadata",
    "prompt",
    "prompt_cache_retention",
    "user",
    "safety_identifier",
    "conversation",
}

_CODEX_METADATA_IDS = {
    "x-codex-installation-id",
    "session_id",
    "thread_id",
    "x-codex-window-id",
    "turn_id",
    "x-codex-parent-thread-id",
    "parent_turn_id",
    "root_turn_id",
    "x-openai-subagent",
}
_TURN_IDS = {
    "installation_id",
    "session_id",
    "thread_id",
    "turn_id",
    "window_id",
    "context_window_id",
    "forked_from_thread_id",
    "parent_thread_id",
    "parent_turn_id",
    "root_turn_id",
}
_TURN_TEXT = {
    "agent_name",
    "subagent_kind",
    "thread_source",
    "turn_trigger",
    "sandbox",
    "sandbox_mode",
}
_TURN_COUNTS = {"window_number", "forked_from_ordinal_exclusive", "turn_started_at_unix_ms"}
_TURN_FLAGS = {
    "auto_review_enabled",
    "node_repl_auto_review_required",
    "node_repl_disabled",
    "history_ingest_requested",
    "analytics_enabled",
}
_TURN_FIELDS = (
    _TURN_IDS
    | _TURN_TEXT
    | _TURN_COUNTS
    | _TURN_FLAGS
    | {
        "request_kind",
        "compaction",
        "workspaces",
        "tool_namespaces_info",
        "model",
        "reasoning_effort",
    }
)
_REASONING_EFFORTS = {"none", "minimal", "low", "medium", "high", "xhigh", "max"}


def _bounded_text(value: Any, limit: int = 4096) -> str:
    value = string(value)
    if len(value) > limit:
        reject("request_too_large", "Client metadata exceeds its supported text limit.")
    return value


def _window_id(value: Any) -> str:
    """Codex adds a bounded decimal context-window ordinal to its session ID."""
    value = string(value)
    match = re.fullmatch(r"([A-Za-z0-9_-]{1,128}):([0-9]{1,10})", value)
    if match is None or int(match[2]) > 2**31 - 1:
        reject("invalid_identifier", "Protocol identifiers must match the supported grammar.")
    return value


def _turn_metadata(value: Any) -> dict[str, Any]:
    """The pinned Codex attribution snapshot, consumed locally by the runtime.

    These fields cannot select a provider or authorize a session/tool. Extra
    app-server metadata and MCP attribution are not part of this profile.
    """
    source = object_fields(value, _TURN_FIELDS)
    result: dict[str, Any] = {}
    for key, item in source.items():
        if item is None:
            reject()
        if key in _TURN_IDS:
            result[key] = _window_id(item) if key == "window_id" else identifier(item)
        elif key == "model":
            result[key] = identifier(item, model=True)
        elif key == "reasoning_effort":
            result[key] = choice(item, _REASONING_EFFORTS)
        elif key in _TURN_TEXT:
            result[key] = _bounded_text(item, 128)
        elif key in _TURN_COUNTS:
            result[key] = integer(item, 0, 2**63 - 1)
        elif key in _TURN_FLAGS:
            result[key] = boolean(item)
        elif key == "request_kind":
            result[key] = choice(item, {"turn", "prewarm", "compaction", "memory"})
        elif key == "compaction":
            meta = object_fields(
                item,
                {"trigger", "reason", "implementation", "phase", "strategy"},
                {"trigger", "reason", "implementation", "phase", "strategy"},
            )
            result[key] = {
                "trigger": choice(meta["trigger"], {"manual", "auto"}),
                "reason": choice(
                    meta["reason"],
                    {"user_requested", "context_limit", "model_downshift", "comp_hash_changed"},
                ),
                "implementation": choice(meta["implementation"], {"responses"}),
                "phase": choice(
                    meta["phase"], {"standalone_turn", "pre_turn", "mid_turn", "post_turn"}
                ),
                "strategy": choice(meta["strategy"], {"memento", "prefix_compaction"}),
            }
        elif key == "workspaces":
            if not isinstance(item, dict):
                reject()
            workspaces = {}
            for workspace, details in item.items():
                _bounded_text(workspace)
                details = object_fields(
                    details, {"associated_remote_urls", "latest_git_commit_hash", "has_changes"}
                )
                rebuilt = {}
                if "associated_remote_urls" in details:
                    remotes = details["associated_remote_urls"]
                    if not isinstance(remotes, dict):
                        reject()
                    rebuilt["associated_remote_urls"] = {
                        _bounded_text(name, 128): _bounded_text(url)
                        for name, url in remotes.items()
                    }
                if "latest_git_commit_hash" in details:
                    rebuilt["latest_git_commit_hash"] = identifier(
                        details["latest_git_commit_hash"]
                    )
                if "has_changes" in details:
                    rebuilt["has_changes"] = boolean(details["has_changes"])
                workspaces[workspace] = rebuilt
            result[key] = workspaces
        elif key == "tool_namespaces_info":
            if not isinstance(item, dict):
                reject()
            namespaces = {}
            for namespace, details in item.items():
                identifier(namespace, tool=True)
                details = object_fields(details, {"name", "functions"}, {"name", "functions"})
                functions = details["functions"]
                if not isinstance(functions, dict):
                    reject()
                entries = {}
                for name, function in functions.items():
                    identifier(name, tool=True)
                    function = object_fields(
                        function,
                        {"name", "direct", "code_mode_name", "deferred", "source"},
                        {"name", "direct", "code_mode_name", "deferred", "source"},
                    )
                    owner = object_fields(function["source"], {"kind", "server_name"}, {"kind"})
                    owner_kind = choice(owner["kind"], {"harness", "mcp"})
                    if owner_kind == "mcp":
                        object_fields(owner, {"kind", "server_name"}, {"kind", "server_name"})
                        owner = {"kind": "mcp", "server_name": identifier(owner["server_name"])}
                    elif "server_name" in owner:
                        reject()
                    else:
                        owner = {"kind": "harness"}
                    entries[name] = {
                        "name": identifier(function["name"], tool=True),
                        "direct": boolean(function["direct"]),
                        "code_mode_name": None
                        if function["code_mode_name"] is None
                        else identifier(function["code_mode_name"], model=True),
                        "deferred": boolean(function["deferred"]),
                        "source": owner,
                    }
                namespaces[namespace] = {
                    "name": identifier(details["name"], tool=True),
                    "functions": entries,
                }
            result[key] = namespaces
    return result


def _client_metadata(value: Any, builder: LocationBuilder) -> dict[str, str]:
    source = object_fields(value, _CODEX_METADATA_IDS | {"x-codex-turn-metadata"})
    result = {}
    for key, item in source.items():
        if key in _CODEX_METADATA_IDS:
            result[key] = _window_id(item) if key == "x-codex-window-id" else identifier(item)
        else:
            raw = _bounded_text(item, 64 * 1024)
            rebuilt = _turn_metadata(loads_json(raw))
            result[key] = builder.encoded_object(
                json.dumps(rebuilt, ensure_ascii=False, separators=(",", ":")),
                ("client_metadata", key),
                structural=True,
                numeric_controls={(field,) for field in _TURN_COUNTS},
            )
    return result


def _text_block(value: Any, path: Path, builder: LocationBuilder, role: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        reject()
    kind = value.get("type")
    if not isinstance(kind, str):
        reject()
    if kind in {"input_image", "input_file", "image", "file"}:
        reject(
            "uninspectable_field", "Images and file references need a dedicated inspection path."
        )
    if kind == "input_text" or (kind == "output_text" and role == "assistant"):
        source = object_fields(value, {"type", "text", "annotations"}, {"type", "text"})
        result: dict[str, Any] = {
            "type": kind,
            "text": builder.text(source["text"], path + ("text",)),
        }
        if "annotations" in source:
            if kind != "output_text" or array(source["annotations"]):
                reject("uninspectable_field", "Nonempty annotations are not supported on replay.")
            result["annotations"] = []
        return result
    if kind == "refusal" and role == "assistant":
        source = object_fields(value, {"type", "refusal"}, {"type", "refusal"})
        return {"type": "refusal", "refusal": builder.text(source["refusal"], path + ("refusal",))}
    reject("uninspectable_field", "Only inspectable text content blocks are supported.")


def _item(value: Any, path: Path, builder: LocationBuilder) -> dict[str, Any]:
    if not isinstance(value, dict):
        reject()
    kind = value.get("type", "message")
    if not isinstance(kind, str):
        reject()
    if kind == "message":
        source = object_fields(
            value, {"type", "role", "content", "id", "status", "phase"}, {"role", "content"}
        )
        role = choice(source["role"], {"developer", "system", "user", "assistant"})
        content = source["content"]
        result: dict[str, Any] = {
            "role": role,
            "content": builder.text(content, path + ("content",))
            if isinstance(content, str)
            else [
                _text_block(block, path + ("content", index), builder, role)
                for index, block in enumerate(array(content, nonempty=True))
            ],
        }
        if "type" in source:
            result["type"] = "message"
        if "phase" in source:
            if role != "assistant":
                reject()
            result["phase"] = (
                None
                if source["phase"] is None
                else choice(source["phase"], {"commentary", "final_answer"})
            )
    elif kind == "reasoning":
        source = object_fields(
            value,
            {"type", "id", "summary", "content", "encrypted_content", "status"},
            {"type", "summary"},
        )
        if (
            array(source["summary"])
            or source.get("content") not in (None, [])
            or source.get("encrypted_content") is not None
        ):
            reject(
                "uninspectable_field", "Reasoning replay must be an empty inspectable placeholder."
            )
        result = {"type": "reasoning", "summary": []}
        for field in ("content", "encrypted_content"):
            if field in source:
                result[field] = source[field]
        if "status" in source and source["status"] is None:
            result["status"] = None
    elif kind in {"function_call", "custom_tool_call"}:
        content_field = "arguments" if kind == "function_call" else "input"
        source = object_fields(
            value,
            {"type", "id", "call_id", "name", content_field, "status"},
            {"type", "call_id", "name", content_field},
        )
        result = {
            "type": kind,
            "call_id": identifier(source["call_id"]),
            "name": identifier(source["name"], tool=True),
            content_field: builder.arguments(source[content_field], path + (content_field,))
            if kind == "function_call"
            else builder.text(source[content_field], path + (content_field,)),
        }
    elif kind in {"function_call_output", "custom_tool_call_output"}:
        source = object_fields(
            value, {"type", "id", "call_id", "output", "status"}, {"type", "call_id", "output"}
        )
        output = source["output"]
        result = {
            "type": kind,
            "call_id": identifier(source["call_id"]),
            "output": builder.text(output, path + ("output",))
            if isinstance(output, str)
            else [
                _text_block(block, path + ("output", index), builder, "user")
                for index, block in enumerate(array(output, nonempty=True))
            ],
        }
    else:
        reject(
            "uninspectable_field",
            "Opaque state, reasoning, and unsupported input items cannot be replayed.",
        )
    if "id" in source:
        result["id"] = identifier(source["id"])
    if "status" in source:
        if kind != "reasoning" or source["status"] is not None:
            result["status"] = choice(source["status"], {"completed", "incomplete"})
    return result


def _tool(value: Any, path: Path, builder: LocationBuilder) -> dict[str, Any]:
    if not isinstance(value, dict):
        reject()
    kind = value.get("type")
    if not isinstance(kind, str):
        reject()
    if kind == "function":
        source = object_fields(
            value,
            {"type", "name", "description", "parameters", "strict", "defer_loading"},
            {"type", "name", "parameters"},
        )
        result: dict[str, Any] = {
            "type": "function",
            "name": identifier(source["name"], tool=True),
            "parameters": json_schema(source["parameters"], path + ("parameters",), builder),
        }
        if "strict" in source:
            result["strict"] = boolean(source["strict"])
    elif kind == "custom":
        source = object_fields(
            value, {"type", "name", "description", "format", "defer_loading"}, {"type", "name"}
        )
        result = {"type": "custom", "name": identifier(source["name"], tool=True)}
        if "format" in source:
            from gateway.tools.patches import PatchValidationError, validate_apply_patch_format

            if source["name"] != "apply_patch":
                fmt = object_fields(source["format"], {"type"}, {"type"})
                result["format"] = {"type": choice(fmt["type"], {"text"})}
            else:
                try:
                    result["format"] = validate_apply_patch_format(source["format"])
                except PatchValidationError as exc:
                    raise RequestRejected(
                        422,
                        "unsupported_tool_format",
                        "Use the supported pinned apply_patch grammar.",
                    ) from exc
    else:
        reject(
            "uninspectable_field",
            "Only defined function tools and text custom tools are supported.",
        )
    if "description" in source:
        result["description"] = builder.text(source["description"], path + ("description",))
    if "defer_loading" in source:
        if boolean(source["defer_loading"]):
            reject("unsupported_field", "Deferred tool loading is disabled in this client profile.")
        result["defer_loading"] = False
    return result


def _tool_choice(value: Any) -> str | dict[str, Any]:
    if isinstance(value, str):
        return choice(value, {"none", "auto", "required"})
    source = object_fields(value, {"type", "name"}, {"type", "name"})
    return {
        "type": choice(source["type"], {"function", "custom"}),
        "name": identifier(source["name"], tool=True),
    }


def _text(value: Any, path: Path, builder: LocationBuilder) -> dict[str, Any]:
    source = object_fields(value, {"format", "verbosity"})
    result: dict[str, Any] = {}
    if "verbosity" in source:
        result["verbosity"] = choice(source["verbosity"], {"low", "medium", "high"})
    if "format" in source:
        fmt = source["format"]
        if not isinstance(fmt, dict):
            reject()
        kind = fmt.get("type")
        if not isinstance(kind, str):
            reject()
        if kind in {"text", "json_object"}:
            object_fields(fmt, {"type"}, {"type"})
            result["format"] = {"type": kind}
        elif kind == "json_schema":
            object_fields(
                fmt, {"type", "name", "schema", "strict", "description"}, {"type", "name", "schema"}
            )
            built: dict[str, Any] = {
                "type": "json_schema",
                "name": identifier(fmt["name"], tool=True),
                "schema": json_schema(fmt["schema"], path + ("format", "schema"), builder),
            }
            if "strict" in fmt:
                built["strict"] = boolean(fmt["strict"])
            if "description" in fmt:
                built["description"] = builder.text(
                    fmt["description"], path + ("format", "description")
                )
            result["format"] = built
        else:
            reject("unsupported_field", "Unsupported structured output format.")
    return result


def parse_responses_request(body: Any) -> ValidatedRequest:
    """Validate and rebuild text, tools and inspectable replay; refuse opaque state."""
    body = request_body(body)
    if body.keys() & _OPAQUE:
        reject(
            "uninspectable_field",
            "Stored continuation, arbitrary metadata, and cache identifiers are disabled.",
        )
    source = object_fields(body, _FIELDS, {"model", "input"})
    builder = LocationBuilder()
    result: dict[str, Any] = {"model": identifier(source["model"], model=True)}
    input_value = source["input"]
    if isinstance(input_value, str):
        result["input"] = builder.text(input_value, ("input",))
    else:
        result["input"] = [
            _item(item, ("input", index), builder)
            for index, item in enumerate(array(input_value, nonempty=True))
        ]
        seen_calls: dict[str, str] = {}
        seen_outputs: set[str] = set()
        seen_ids: set[str] = set()
        for item in result["input"]:
            if "id" in item:
                if item["id"] in seen_ids:
                    reject("invalid_history", "Replayed item identifiers must be unique.")
                seen_ids.add(item["id"])
            kind = item.get("type", "message")
            if kind in {"function_call", "custom_tool_call"}:
                if item["call_id"] in seen_calls:
                    reject("invalid_history", "Replayed call identifiers must be unique.")
                seen_calls[item["call_id"]] = kind
            elif kind in {"function_call_output", "custom_tool_call_output"}:
                call_id = item["call_id"]
                expected = "function_call" if kind == "function_call_output" else "custom_tool_call"
                if seen_calls.get(call_id) != expected or call_id in seen_outputs:
                    reject("invalid_history", "Tool results must match a preceding unique call.")
                seen_outputs.add(call_id)
    if "instructions" in source:
        result["instructions"] = builder.text(source["instructions"], ("instructions",))
    if "prompt_cache_key" in source:
        result["prompt_cache_key"] = identifier(source["prompt_cache_key"])
    if "client_metadata" in source:
        result["client_metadata"] = _client_metadata(source["client_metadata"], builder)
    for field in ("stream", "parallel_tool_calls"):
        if field in source:
            result[field] = boolean(source[field])
    for field in ("store", "background"):
        if field in source:
            if boolean(source[field]):
                reject(
                    "continuation_unsupported",
                    "Provider retention and background continuation are disabled.",
                )
            result[field] = False
    # Explicitly prevent provider retention even if its default changes.
    result["store"] = False
    for field in ("max_output_tokens", "max_tool_calls"):
        if field in source:
            result[field] = integer(source[field], 1)
    for field, bounds in (("temperature", (0, 2)), ("top_p", (0, 1))):
        if field in source:
            result[field] = number(source[field], *bounds)
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
        if isinstance(result["tool_choice"], dict):
            selected = result["tool_choice"]
            if not any(
                tool["name"] == selected["name"] and tool["type"] == selected["type"]
                for tool in result.get("tools", [])
            ):
                reject("invalid_tools", "Selected tool must be declared in this request.")
    if "truncation" in source:
        result["truncation"] = choice(source["truncation"], {"auto", "disabled"})
    if "service_tier" in source:
        result["service_tier"] = choice(
            source["service_tier"],
            {"auto", "default", "flex", "scale", "priority", "fast", "ultrafast"},
        )
    if "text" in source:
        result["text"] = _text(source["text"], ("text",), builder)
    if "reasoning" in source:
        reasoning = object_fields(source["reasoning"], {"effort", "summary"})
        result["reasoning"] = {}
        if "effort" in reasoning:
            result["reasoning"]["effort"] = choice(reasoning["effort"], _REASONING_EFFORTS)
        if "summary" in reasoning:
            result["reasoning"]["summary"] = choice(
                reasoning["summary"], {"auto", "concise", "detailed"}
            )
    if "include" in source:
        include = array(source["include"])
        result["include"] = [choice(item, {"reasoning.encrypted_content"}) for item in include]
        if len(set(result["include"])) != len(result["include"]):
            reject()
    return ValidatedRequest(
        "responses", result, builder.finish(result), result.get("stream", False)
    )
