"""Strict Responses and Messages output visitors and SSE state machines.

Prose may stream before completion. Executable events remain private until the
entire response succeeds and every tool call passes destination-aware validation.
"""

from __future__ import annotations

import copy
import json
import math
import re
from collections.abc import AsyncIterable, AsyncIterator
from typing import TYPE_CHECKING, Any

from gateway.api.schema import RequestRejected
from gateway.domain import RequestContext
from gateway.protocols.base import bounded_json
from gateway.restoration.engine import (
    MAX_RESTORED_CONTENT_BYTES,
    RestorationEngine,
    RestorationOutcome,
    RestorationOutputTooLargeError,
)
from gateway.streaming.sse import (
    MAX_EVENT_BYTES,
    StreamProtocolError,
    encode_event,
    json_object,
    parse_sse,
)
from gateway.streaming.tokens import IncrementalRestorer
from gateway.transformations.tokens import TokenProvenance

if TYPE_CHECKING:
    from gateway.tools.registry import ToolRegistry

MAX_ITEMS = 512
_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_TOOL_KINDS = {"function_call", "custom_tool_call"}
_STOP_REASONS = {
    "end_turn",
    "tool_use",
    "max_tokens",
    "refusal",
    "pause_turn",
    "stop_sequence",
    "model_context_window_exceeded",
}


def _keys(value: Any, allowed: set[str], required: set[str] = frozenset()) -> dict:
    if not isinstance(value, dict) or set(value) - allowed or required - set(value):
        raise StreamProtocolError()
    return value


def _string(value: Any) -> str:
    if not isinstance(value, str):
        raise StreamProtocolError()
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise StreamProtocolError() from exc
    return value


def _identifier(value: Any, *, name: bool = False, model: bool = False) -> str:
    value = _string(value)
    pattern = _MODEL if model else _NAME if name else _IDENTIFIER
    if not pattern.fullmatch(value):
        raise StreamProtocolError()
    return value


def _index(value: Any, maximum: int = MAX_ITEMS) -> int:
    if type(value) is not int or value < 0 or value >= maximum:
        raise StreamProtocolError()
    return value


def _size(value: Any) -> int:
    try:
        return len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"))
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise StreamProtocolError() from exc


def _usage(value: Any, *, messages: bool = False) -> dict:
    allowed = (
        {"input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"}
        if messages
        else {"input_tokens", "output_tokens", "total_tokens", "codex_rollout_budget_units"}
    )
    nested = (
        {"cache_creation", "server_tool_use", "output_tokens_details"}
        if messages
        else {"input_tokens_details", "output_tokens_details"}
    )
    enumerated = (
        {
            "service_tier": {None, "standard", "priority", "batch"},
            # The native output contract admits these named regions only. A
            # new region requires qualification instead of free-form labels.
            "inference_geo": {None, "us", "global", "not_available"},
        }
        if messages
        else {}
    )
    nullable = nested | (
        {"cache_creation_input_tokens", "cache_read_input_tokens"}
        if messages
        else {"codex_rollout_budget_units"}
    )
    usage = _keys(value, allowed | nested | enumerated.keys())
    for key, count in usage.items():
        if key in enumerated:
            if not isinstance(count, (str, type(None))) or count not in enumerated[key]:
                raise StreamProtocolError()
        elif key in nullable and count is None:
            continue
        elif key == "codex_rollout_budget_units":
            if type(count) not in (int, float) or not math.isfinite(count) or count < 0:
                raise StreamProtocolError()
        elif key in nested:
            detail_keys = {
                "input_tokens_details": {"cached_tokens", "cache_write_tokens"},
                "output_tokens_details": {"thinking_tokens"} if messages else {"reasoning_tokens"},
                "cache_creation": {"ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens"},
                "server_tool_use": {"web_search_requests", "web_fetch_requests"},
            }[key]
            _keys(count, detail_keys)
            if any(type(n) is not int or n < 0 for n in count.values()):
                raise StreamProtocolError()
        elif type(count) is not int or count < 0:
            raise StreamProtocolError()
    return copy.deepcopy(usage)


def _part(value: Any) -> dict:
    _keys(value, {"type", "text", "refusal", "annotations", "logprobs"}, {"type"})
    kind = value["type"]
    if kind == "output_text":
        _keys(value, {"type", "text", "annotations", "logprobs"}, {"type", "text"})
        _string(value["text"])
        if value.get("annotations", []) != [] or value.get("logprobs", []) not in (None, []):
            raise StreamProtocolError()
    elif kind == "refusal":
        _keys(value, {"type", "refusal"}, {"type", "refusal"})
        _string(value["refusal"])
    else:
        raise StreamProtocolError()
    return copy.deepcopy(value)


def _item(value: Any, *, completed: bool, max_items: int) -> dict:
    if not isinstance(value, dict):
        raise StreamProtocolError()
    kind = value.get("type")
    common = {"type", "id", "status", "internal_chat_message_metadata_passthrough"}
    if value.get("internal_chat_message_metadata_passthrough") is not None:
        raise StreamProtocolError("unsupported_provider_content")
    if kind == "message":
        _keys(value, common | {"role", "content", "phase"}, {"id", "type", "role", "content"})
        if value.get("phase") not in (None, "commentary", "final_answer"):
            raise StreamProtocolError()
        if value["role"] != "assistant" or not isinstance(value["content"], list):
            raise StreamProtocolError()
        if len(value["content"]) > max_items:
            raise StreamProtocolError("provider_item_limit")
        for part in value["content"]:
            _part(part)
    elif kind in _TOOL_KINDS:
        field = "arguments" if kind == "function_call" else "input"
        _keys(
            value,
            common
            | {"call_id", "name", field, "namespace", "caller", "async", "encrypted_function_args"},
            {"id", "type", "call_id", "name", field},
        )
        if (
            value.get("namespace") is not None
            or value.get("caller") not in (None, {"type": "direct"})
            or value.get("async") not in (None, False)
            or value.get("encrypted_function_args") not in (None, [])
        ):
            raise StreamProtocolError("unsupported_provider_content")
        if "async" in value and value["async"] is not None and type(value["async"]) is not bool:
            raise StreamProtocolError()
        _identifier(value["call_id"])
        _identifier(value["name"], name=True)
        _string(value[field])
    elif kind == "reasoning":
        _keys(
            value, common | {"summary", "content", "encrypted_content"}, {"type", "id", "summary"}
        )
        # An empty, inspectable item carries no continuation bytes or token
        # dependencies. Including the encrypted-content request control never
        # authorizes a returned string or signed/encrypted replay state.
        if (
            value["summary"] != []
            or value.get("content") not in (None, [])
            or value.get("encrypted_content") is not None
        ):
            raise StreamProtocolError("unsupported_provider_content")
    else:
        # Signed/encrypted reasoning, remote files, images and unknown tool
        # families need a separately reviewed continuation/content contract.
        raise StreamProtocolError("unsupported_provider_content")
    _identifier(value["id"])
    status = value.get("status", "completed" if completed else "in_progress")
    if status != ("completed" if completed else "in_progress") and not (
        kind != "message" and status is None
    ):
        raise StreamProtocolError()
    return copy.deepcopy(value)


def _response(
    value: Any, *, completed: bool, max_items: int, expected_request: dict | None = None
) -> dict:
    required = {"id", "output", "status"}
    basic = required | {
        "object",
        "created_at",
        "completed_at",
        "model",
        "usage",
        "error",
        "incomplete_details",
        "end_turn",
        "usage_metadata",
    }
    controls = {
        "parallel_tool_calls",
        "store",
        "background",
        "max_output_tokens",
        "max_tool_calls",
        "previous_response_id",
        "service_tier",
        "temperature",
        "top_p",
        "truncation",
        "reasoning",
        "text",
        "tool_choice",
        "tools",
        "metadata",
        "instructions",
        "user",
        "safety_identifier",
        "prompt_cache_key",
        "prompt_cache_retention",
        "top_logprobs",
        "conversation",
        "prompt",
        "moderation",
        "access_programs",
        "prompt_cache_options",
        "prompt_cache_diagnostics",
    }
    _keys(value, basic | controls, required)
    _identifier(value["id"])
    if value.get("object", "response") != "response":
        raise StreamProtocolError()
    if _string(value["status"]) not in ({"completed"} if completed else {"queued", "in_progress"}):
        raise StreamProtocolError("upstream_response_failed")
    for field in ("created_at", "completed_at"):
        timestamp = value.get(field)
        if timestamp is not None and (
            type(timestamp) not in (int, float) or not math.isfinite(timestamp) or timestamp < 0
        ):
            raise StreamProtocolError()
    if "created_at" in value and value["created_at"] is None:
        raise StreamProtocolError()
    for field in (
        "conversation",
        "prompt",
        "moderation",
        "access_programs",
        "prompt_cache_options",
        "prompt_cache_diagnostics",
        "usage_metadata",
    ):
        if value.get(field) is not None:
            raise StreamProtocolError("unsupported_provider_content")
    if value.get("end_turn") is not None and type(value["end_turn"]) is not bool:
        raise StreamProtocolError()
    if "model" in value:
        _identifier(value["model"], model=True)
    if value.get("error") is not None or value.get("incomplete_details") is not None:
        raise StreamProtocolError("upstream_response_failed")
    if "usage" in value and value["usage"] is not None:
        _usage(value["usage"])
    for key in ("parallel_tool_calls", "store", "background"):
        if (
            key in value
            and type(value[key]) is not bool
            and not (key == "background" and value[key] is None)
        ):
            raise StreamProtocolError()
    if value.get("store", False) or value.get("background", False):
        raise StreamProtocolError("unsupported_provider_continuation")
    for key in ("max_output_tokens", "max_tool_calls"):
        if value.get(key) is not None and (type(value[key]) is not int or value[key] < 1):
            raise StreamProtocolError()
    for key in ("temperature", "top_p"):
        if value.get(key) is not None and (
            type(value[key]) not in (int, float)
            or not math.isfinite(value[key])
            or not 0 <= value[key] <= (2 if key == "temperature" else 1)
        ):
            raise StreamProtocolError()
    choices = {
        "service_tier": {None, "auto", "default", "flex", "priority", "scale", "fast", "ultrafast"},
        "truncation": {None, "disabled", "auto"},
        "prompt_cache_retention": {None, "in_memory", "24h"},
    }
    for key, permitted in choices.items():
        if key in value and (
            not isinstance(value[key], (str, type(None))) or value[key] not in permitted
        ):
            raise StreamProtocolError()
    if value.get("previous_response_id") is not None:
        raise StreamProtocolError("unsupported_provider_continuation")
    for key in ("user", "safety_identifier", "prompt_cache_key"):
        if value.get(key) is not None and (
            expected_request is None or value[key] != expected_request.get(key)
        ):
            raise StreamProtocolError("unsupported_provider_content")
        if value.get(key) is not None:
            _string(value[key])
    metadata = value.get("metadata")
    if metadata is not None:
        if (
            not isinstance(metadata, dict)
            or len(metadata) > 16
            or any(
                not isinstance(key, str)
                or len(key) > 64
                or not isinstance(item, str)
                or len(item) > 512
                for key, item in metadata.items()
            )
        ):
            raise StreamProtocolError()
        if metadata and (expected_request is None or metadata != expected_request.get("metadata")):
            raise StreamProtocolError("provider_snapshot_mismatch")
    if value.get("top_logprobs") is not None:
        count = value["top_logprobs"]
        if type(count) is not int or not 0 <= count <= 20:
            raise StreamProtocolError()
    # Inspectable request echoes are accepted only when they are the exact
    # sanitized values sent in this exchange. Reuse the native request parser
    # to validate their explicit schema rather than recursively passing through
    # arbitrary provider dictionaries. They remain sanitized in output.
    echoes = {"model": value.get("model", "provider"), "input": ""}
    for key in ("instructions", "tools", "tool_choice", "text"):
        if key not in value or value[key] is None:
            continue
        content_bearing = (
            key == "instructions"
            or key == "tools"
            and bool(value[key])
            or key == "tool_choice"
            and isinstance(value[key], dict)
            or key == "text"
            and isinstance(value[key], dict)
            and value[key].get("format", {"type": "text"}) != {"type": "text"}
        )
        if content_bearing and (
            expected_request is None or value[key] != expected_request.get(key)
        ):
            raise StreamProtocolError("provider_snapshot_mismatch")
        echoes[key] = value[key]
    from gateway.protocols.responses import parse_responses_request

    try:
        parse_responses_request(echoes)
    except Exception as exc:
        raise StreamProtocolError() from exc
    if value.get("reasoning") is not None:
        _keys(value["reasoning"], {"effort", "summary", "context", "generate_summary", "mode"})
        if value["reasoning"].get("effort") not in {
            None,
            "none",
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh",
            "max",
        }:
            raise StreamProtocolError()
        if value["reasoning"].get("summary") not in {None, "auto", "concise", "detailed"}:
            raise StreamProtocolError()
        if value["reasoning"].get("generate_summary") not in {None, "auto", "concise", "detailed"}:
            raise StreamProtocolError()
        if value["reasoning"].get("context") not in {None, "auto", "current_turn", "all_turns"}:
            raise StreamProtocolError()
        if value["reasoning"].get("mode") not in {None, "standard", "pro"}:
            raise StreamProtocolError()
    if not isinstance(value["output"], list) or len(value["output"]) > max_items:
        raise StreamProtocolError("provider_item_limit")
    total_items = len(value["output"])
    identifiers: set[str] = set()
    calls: set[str] = set()
    for item in value["output"]:
        _item(item, completed=completed, max_items=max_items)
        if item["type"] == "message":
            total_items += len(item["content"])
            if total_items > max_items:
                raise StreamProtocolError("provider_item_limit")
        if item["id"] in identifiers or ("call_id" in item and item["call_id"] in calls):
            raise StreamProtocolError()
        identifiers.add(item["id"])
        if "call_id" in item:
            calls.add(item["call_id"])
    return copy.deepcopy(value)


def _block(value: Any, *, start: bool = False) -> dict:
    if not isinstance(value, dict):
        raise StreamProtocolError()
    kind = value.get("type")
    if kind == "text":
        _keys(value, {"type", "text", "citations"}, {"type", "text"})
        _string(value["text"])
        if value.get("citations", []) not in (None, []) or start and value["text"]:
            raise StreamProtocolError()
    elif kind == "tool_use":
        _keys(
            value,
            {"type", "id", "name", "input", "caller", "toolset_name"},
            {"type", "id", "name", "input"},
        )
        if (
            value.get("caller") not in (None, {"type": "direct"})
            or value.get("toolset_name") is not None
        ):
            raise StreamProtocolError("unsupported_provider_content")
        _identifier(value["id"])
        _identifier(value["name"], name=True)
        if not isinstance(value["input"], dict) or start and value["input"] != {}:
            raise StreamProtocolError()
        # Use the same strict decoder/nesting and scalar checks as SSE JSON.
        json_object(json.dumps(value["input"], ensure_ascii=False, allow_nan=False))
    else:
        raise StreamProtocolError("unsupported_provider_content")
    return copy.deepcopy(value)


def _stop(value: dict, expected_request: dict | None) -> None:
    reason = _string(value.get("stop_reason"))
    if reason not in _STOP_REASONS:
        raise StreamProtocolError()
    sequence = value.get("stop_sequence")
    if reason == "stop_sequence":
        _string(sequence)
        if expected_request is None or sequence not in expected_request.get("stop_sequences", []):
            raise StreamProtocolError("provider_snapshot_mismatch")
    elif sequence is not None:
        raise StreamProtocolError()
    if value.get("container") is not None:
        raise StreamProtocolError("unsupported_provider_continuation")
    details = value.get("stop_details")
    if details is not None:
        _keys(details, {"type", "category", "explanation"}, {"type"})
        if (
            reason != "refusal"
            or details["type"] != "refusal"
            or details.get("category")
            not in (
                None,
                "cyber",
                "bio",
                "frontier_llm",
                "reasoning_extraction",
                "general_harms",
            )
        ):
            raise StreamProtocolError()
        if details.get("explanation") is not None:
            _string(details["explanation"])


def _message(
    value: Any, *, start: bool, max_items: int, expected_request: dict | None = None
) -> dict:
    _keys(
        value,
        {
            "id",
            "type",
            "role",
            "model",
            "content",
            "stop_reason",
            "stop_sequence",
            "usage",
            "container",
            "diagnostics",
            "stop_details",
        },
        {"id", "type", "role", "content"},
    )
    _identifier(value["id"])
    if value["type"] != "message" or value["role"] != "assistant":
        raise StreamProtocolError()
    if "model" in value:
        _identifier(value["model"], model=True)
    if "usage" in value:
        _usage(value["usage"], messages=True)
    if not isinstance(value["content"], list) or len(value["content"]) > max_items:
        raise StreamProtocolError("provider_item_limit")
    if start and value["content"]:
        raise StreamProtocolError()
    if start:
        if value.get("stop_reason") is not None or value.get("stop_sequence") is not None:
            raise StreamProtocolError()
        if value.get("stop_details") is not None:
            raise StreamProtocolError()
    else:
        _stop(value, expected_request)
    if value.get("container") is not None or value.get("diagnostics") is not None:
        raise StreamProtocolError("unsupported_provider_content")
    calls: set[str] = set()
    for block in value["content"]:
        _block(block)
        if block["type"] == "tool_use":
            if block["id"] in calls:
                raise StreamProtocolError()
            calls.add(block["id"])
    if calls and value.get("stop_reason") != "tool_use":
        raise StreamProtocolError("upstream_response_failed")
    return copy.deepcopy(value)


def _restore_tool(
    tools: ToolRegistry,
    ctx: RequestContext,
    name: str,
    arguments: str,
    provenance: TokenProvenance,
    restorer: RestorationEngine,
    *,
    custom: bool = False,
) -> tuple[str, RestorationOutcome]:
    try:
        return tools.restore(ctx, name, arguments, provenance, restorer, custom=custom)
    except Exception as exc:
        error = StreamProtocolError("tool_restoration_failed")
        original = getattr(exc, "outcome", None)
        if isinstance(original, RestorationOutcome):
            error.outcome = RestorationOutcome(text="")
            error.outcome.merge(original)
        raise error from exc


def _validate_batch(tools: ToolRegistry, calls: list[tuple[str, str, bool]]) -> None:
    validate = getattr(tools, "validate_batch", None)
    if validate is not None:
        try:
            validate(calls)
        except Exception as exc:
            error = StreamProtocolError("tool_restoration_failed")
            original = getattr(exc, "outcome", None)
            if isinstance(original, RestorationOutcome):
                error.outcome = RestorationOutcome(text="")
                error.outcome.merge(original)
            raise error from exc


def _restore_response(
    protocol: str,
    response: dict,
    ctx: RequestContext,
    provenance: TokenProvenance,
    restorer: RestorationEngine,
    tools: ToolRegistry,
    *,
    max_items: int = MAX_ITEMS,
    max_output_bytes: int = MAX_RESTORED_CONTENT_BYTES,
    expected_request: dict | None = None,
) -> tuple[dict, RestorationOutcome]:
    """Validate and restore a buffered response atomically, including all tools."""
    if max_items < 1 or max_output_bytes < 1:
        raise ValueError("output limits must be positive")
    if _size(response) > max_output_bytes:
        raise StreamProtocolError("provider_output_too_large")
    outcome = RestorationOutcome(text="")
    content_bytes = 0
    if protocol == "responses":
        result = _response(
            response, completed=True, max_items=max_items, expected_request=expected_request
        )
        _validate_batch(
            tools,
            [
                (
                    item["name"],
                    item["arguments"] if item["type"] == "function_call" else item["input"],
                    item["type"] == "custom_tool_call",
                )
                for item in result["output"]
                if item["type"] in _TOOL_KINDS
            ],
        )
        for item in result["output"]:
            if item["type"] == "message":
                for part in item["content"]:
                    field = "text" if part["type"] == "output_text" else "refusal"
                    restored = restorer.restore(
                        ctx,
                        part[field],
                        provenance,
                        max_output_bytes=max_output_bytes - content_bytes,
                    )
                    part[field] = restored.text
                    outcome.merge(restored)
                    content_bytes += len(restored.text.encode("utf-8"))
            elif item["type"] in _TOOL_KINDS:
                field = "arguments" if item["type"] == "function_call" else "input"
                item[field], restored = _restore_tool(
                    tools,
                    ctx,
                    item["name"],
                    item[field],
                    provenance,
                    restorer,
                    custom=item["type"] == "custom_tool_call",
                )
                outcome.merge(restored)
                content_bytes += len(item[field].encode("utf-8"))
                if content_bytes > max_output_bytes:
                    raise StreamProtocolError("provider_output_too_large")
    elif protocol == "messages":
        result = _message(
            response, start=False, max_items=max_items, expected_request=expected_request
        )
        _validate_batch(
            tools,
            [
                (block["name"], json.dumps(block["input"]), False)
                for block in result["content"]
                if block["type"] == "tool_use"
            ],
        )
        for block in result["content"]:
            if block["type"] == "text":
                restored = restorer.restore(
                    ctx,
                    block["text"],
                    provenance,
                    max_output_bytes=max_output_bytes - content_bytes,
                )
                block["text"] = restored.text
                content_bytes += len(restored.text.encode("utf-8"))
            else:
                arguments, restored = _restore_tool(
                    tools, ctx, block["name"], json.dumps(block["input"]), provenance, restorer
                )
                block["input"] = json_object(arguments)
                content_bytes += len(arguments.encode("utf-8"))
            outcome.merge(restored)
            if content_bytes > max_output_bytes:
                raise StreamProtocolError("provider_output_too_large")
        details = result.get("stop_details")
        if details is not None and details.get("explanation") is not None:
            restored = restorer.restore(
                ctx,
                details["explanation"],
                provenance,
                max_output_bytes=max_output_bytes - content_bytes,
            )
            details["explanation"] = restored.text
            outcome.merge(restored)
    else:
        raise ValueError("unknown protocol")
    if _size(result) > max_output_bytes:
        raise StreamProtocolError("provider_output_too_large")
    return result, outcome


def restore_response(
    protocol: str,
    response: dict,
    ctx: RequestContext,
    provenance: TokenProvenance,
    restorer: RestorationEngine,
    tools: ToolRegistry,
    *,
    max_items: int = MAX_ITEMS,
    max_output_bytes: int = MAX_RESTORED_CONTENT_BYTES,
    expected_request: dict | None = None,
) -> tuple[dict, RestorationOutcome]:
    if protocol not in {"responses", "messages"}:
        raise ValueError("unknown protocol")
    if max_items < 1 or max_output_bytes < 1:
        raise ValueError("output limits must be positive")
    try:
        bounded_json(response)
        return _restore_response(
            protocol,
            response,
            ctx,
            provenance,
            restorer,
            tools,
            max_items=max_items,
            max_output_bytes=max_output_bytes,
            expected_request=expected_request,
        )
    except RestorationOutputTooLargeError as exc:
        raise StreamProtocolError("provider_output_too_large") from exc
    except RequestRejected as exc:
        raise StreamProtocolError() from exc
    except (TypeError, KeyError, ValueError, RecursionError) as exc:
        raise StreamProtocolError() from exc


class _Machine:
    def __init__(
        self,
        ctx,
        provenance,
        restorer,
        tools,
        outcome,
        max_items,
        max_output_bytes,
        expected_request,
    ):
        self.ctx = ctx
        self.provenance = provenance
        self.restorer = restorer
        self.tools = tools
        self.outcome = outcome
        self.max_items = max_items
        self.max_output_bytes = max_output_bytes
        self.expected_request = expected_request
        self.started = False
        self.terminal = False
        self.pending: list[dict] = []
        self.pending_bytes = 0
        self.raw_bytes = 0
        self.restored_bytes = 0
        self.sequence = -1
        self.sequence_mode: bool | None = None
        self.sequenced = False
        self.emit_sequence = 0
        self.total_items = 0

    def add_item(self):
        self.total_items += 1
        if self.total_items > self.max_items:
            raise StreamProtocolError("provider_item_limit")

    def event(self, value: dict, allowed: set[str], required: set[str] = frozenset()):
        _keys(value, allowed | {"type", "sequence_number"}, required | {"type"})
        present = "sequence_number" in value
        if self.sequence_mode is None:
            self.sequence_mode = present
        elif present != self.sequence_mode:
            raise StreamProtocolError()
        if "sequence_number" in value:
            sequence = value["sequence_number"]
            if type(sequence) is not int or sequence <= self.sequence:
                raise StreamProtocolError()
            self.sequence = sequence
            self.sequenced = True
        if self.terminal:
            raise StreamProtocolError()

    def text_buffer(self) -> IncrementalRestorer:
        return IncrementalRestorer(
            self.ctx, self.provenance, self.restorer, self.outcome, self.max_output_bytes
        )

    def count(self, text: str, *, restored: bool = False):
        count = len(text.encode("utf-8"))
        if restored:
            self.restored_bytes += count
            size = self.restored_bytes
        else:
            self.raw_bytes += count
            size = self.raw_bytes
        if size > self.max_output_bytes:
            raise StreamProtocolError("provider_output_too_large")

    def hold(self, value: dict):
        self.pending_bytes += _size(value)
        if self.pending_bytes > self.max_output_bytes:
            raise StreamProtocolError("provider_output_too_large")
        self.pending.append(copy.deepcopy(value))

    def encode(self, value: dict, *, responses: bool) -> bytes:
        value = copy.deepcopy(value)
        if responses and self.sequenced:
            value["sequence_number"] = self.emit_sequence
            self.emit_sequence += 1
        return encode_event(value, value["type"])


class _Responses(_Machine):
    def __init__(self, *args):
        super().__init__(*args)
        self.response_id: str | None = None
        self.items: list[dict] = []
        self.ids: set[str] = set()
        self.calls: set[str] = set()
        self.in_progress = False

    def located(self, event: dict) -> dict:
        index = _index(event.get("output_index"), self.max_items)
        if index >= len(self.items):
            raise StreamProtocolError()
        state = self.items[index]
        if state["done"] or event.get("item_id") != state["raw"]["id"]:
            raise StreamProtocolError()
        return state

    def part_state(self, event: dict, state: dict) -> dict:
        index = _index(event.get("content_index"), self.max_items)
        if state["raw"]["type"] != "message" or index >= len(state["parts"]):
            raise StreamProtocolError()
        return state["parts"][index]

    def item_snapshot(self, state: dict, *, restored: bool) -> dict:
        result = copy.deepcopy(state.get("final_raw", state["raw"]))
        if "final_raw" not in state:
            result["status"] = "completed"
        if result["type"] == "message":
            result["content"] = []
            for part in state["parts"]:
                snapshot = copy.deepcopy(part["raw"])
                field = "text" if snapshot["type"] == "output_text" else "refusal"
                snapshot[field] = part["buffer"].text if restored else part["buffer"].raw
                result["content"].append(snapshot)
        elif result["type"] in _TOOL_KINDS:
            field = "arguments" if result["type"] == "function_call" else "input"
            result[field] = state["restored"] if restored else state["arguments"]
        return result

    def compare_item(self, snapshot: dict, state: dict):
        validated = _item(snapshot, completed=True, max_items=self.max_items)
        expected = self.item_snapshot(state, restored=False)
        # Providers can omit optional empty annotations/logprobs/status in one
        # snapshot. Content, identity, association and arguments must agree.
        for item in (validated, expected):
            if item.get("status") is None:
                item["status"] = "completed"
            item.setdefault("internal_chat_message_metadata_passthrough", None)
            if item["type"] == "message":
                item.setdefault("phase", None)
            elif item["type"] == "reasoning":
                item["content"] = []
                item.setdefault("encrypted_content", None)
            else:
                item.setdefault("namespace", None)
                item["caller"] = None
                item["async"] = False
                item["encrypted_function_args"] = []
        if (
            validated["type"] == "message"
            and "final_raw" not in state
            and expected["phase"] is None
        ):
            # Phase can first become known in the completed output snapshot.
            # Once assigned it is stable across subsequent final snapshots.
            expected["phase"] = validated["phase"]
        if validated["type"] == "message":
            for part in validated["content"]:
                if part["type"] == "output_text":
                    part.setdefault("annotations", [])
                    part["logprobs"] = []
            for part in expected["content"]:
                if part["type"] == "output_text":
                    part.setdefault("annotations", [])
                    part["logprobs"] = []
        if validated != expected:
            raise StreamProtocolError("provider_snapshot_mismatch")

    def release_tools(self) -> list[dict]:
        _validate_batch(
            self.tools,
            [
                (
                    state["raw"]["name"],
                    state["arguments"],
                    state["raw"]["type"] == "custom_tool_call",
                )
                for state in self.items
                if state["raw"]["type"] in _TOOL_KINDS
            ],
        )
        for state in self.items:
            if state["raw"]["type"] not in _TOOL_KINDS:
                continue
            state["restored"], outcome = _restore_tool(
                self.tools,
                self.ctx,
                state["raw"]["name"],
                state["arguments"],
                self.provenance,
                self.restorer,
                custom=state["raw"]["type"] == "custom_tool_call",
            )
            self.count(state["restored"], restored=True)
            self.outcome.merge(outcome)
        result: list[dict] = []
        delta_sent: set[int] = set()
        for event in self.pending:
            index = event["output_index"]
            state = self.items[index]
            kind = event["type"]
            custom = state["raw"]["type"] == "custom_tool_call"
            prefix = (
                "response.custom_tool_call_input" if custom else "response.function_call_arguments"
            )
            field = "input" if custom else "arguments"
            if kind == prefix + ".delta":
                if index in delta_sent:
                    continue
                event["delta"] = state["restored"]
                delta_sent.add(index)
            elif kind == prefix + ".done":
                if index not in delta_sent:
                    delta = {
                        "type": prefix + ".delta",
                        "item_id": state["raw"]["id"],
                        "output_index": index,
                        "delta": state["restored"],
                    }
                    result.append(delta)
                    delta_sent.add(index)
                event[field] = state["restored"]
            elif kind == "response.output_item.done":
                event["item"] = self.item_snapshot(state, restored=True)
            result.append(event)
        return result

    def handle(self, event: dict) -> list[dict]:
        kind = event.get("type")
        if kind in {"error", "response.failed", "response.incomplete"}:
            raise StreamProtocolError("upstream_response_failed")
        if kind in {"response.created", "response.in_progress"}:
            self.event(event, {"response"}, {"response"})
            response = _response(
                event["response"],
                completed=False,
                max_items=self.max_items,
                expected_request=self.expected_request,
            )
            if response["output"]:
                raise StreamProtocolError()
            if kind == "response.created":
                if self.started:
                    raise StreamProtocolError()
                self.started = True
                self.response_id = response["id"]
            elif not self.started or self.in_progress or self.items:
                raise StreamProtocolError()
            else:
                self.in_progress = True
            if response["id"] != self.response_id:
                raise StreamProtocolError()
            return [copy.deepcopy(event)]
        if not self.started:
            raise StreamProtocolError()
        if kind == "response.output_item.added":
            self.event(event, {"output_index", "item"}, {"output_index", "item"})
            index = _index(event["output_index"], self.max_items)
            item = _item(event["item"], completed=False, max_items=self.max_items)
            if index != len(self.items) or item["id"] in self.ids:
                raise StreamProtocolError()
            self.ids.add(item["id"])
            state = {
                "raw": item,
                "done": False,
                "parts": [],
                "arguments": "",
                "argument_chunks": [],
                "args_done": False,
            }
            if item["type"] == "message":
                if item["content"]:
                    raise StreamProtocolError()
            elif item["type"] in _TOOL_KINDS:
                field = "arguments" if item["type"] == "function_call" else "input"
                if item[field] or item["call_id"] in self.calls:
                    raise StreamProtocolError()
                self.calls.add(item["call_id"])
            self.items.append(state)
            self.add_item()
            if item["type"] in _TOOL_KINDS:
                self.hold(event)
                return []
            return [copy.deepcopy(event)]
        if kind in {"response.content_part.added", "response.content_part.done"}:
            self.event(
                event,
                {"output_index", "item_id", "content_index", "part"},
                {"output_index", "item_id", "content_index", "part"},
            )
            state = self.located(event)
            part = _part(event["part"])
            index = _index(event["content_index"], self.max_items)
            if state["raw"]["type"] != "message":
                raise StreamProtocolError()
            if kind.endswith("added"):
                field = "text" if part["type"] == "output_text" else "refusal"
                if index != len(state["parts"]) or part[field]:
                    raise StreamProtocolError()
                state["parts"].append({"raw": part, "buffer": self.text_buffer(), "done": False})
                self.add_item()
                return [copy.deepcopy(event)]
            tracked = self.part_state(event, state)
            field = "text" if part["type"] == "output_text" else "refusal"
            if (
                tracked["done"]
                or not tracked["buffer"].closed
                or part["type"] != tracked["raw"]["type"]
            ):
                raise StreamProtocolError()
            if part[field] != tracked["buffer"].raw:
                raise StreamProtocolError("provider_snapshot_mismatch")
            tracked["done"] = True
            tracked["raw"] = part
            result = copy.deepcopy(event)
            result["part"][field] = tracked["buffer"].text
            return [result]
        if kind in {
            "response.output_text.delta",
            "response.output_text.done",
            "response.refusal.delta",
            "response.refusal.done",
        }:
            is_delta = kind.endswith("delta")
            is_refusal = kind.startswith("response.refusal.")
            field = "delta" if is_delta else "refusal" if is_refusal else "text"
            self.event(
                event,
                {"output_index", "item_id", "content_index", field, "logprobs"},
                {"output_index", "item_id", "content_index", field},
            )
            if event.get("logprobs", []) not in (None, []):
                raise StreamProtocolError()
            state = self.located(event)
            part = self.part_state(event, state)
            if part["raw"]["type"] != ("refusal" if is_refusal else "output_text") or part["done"]:
                raise StreamProtocolError()
            buffer = part["buffer"]
            value = _string(event[field])
            if buffer.closed:
                raise StreamProtocolError()
            if not is_delta and value != buffer.raw:
                raise StreamProtocolError("provider_snapshot_mismatch")
            if is_delta:
                self.count(value)
            text = buffer.feed(value if is_delta else "", final=not is_delta)
            self.count(text, restored=True)
            result = copy.deepcopy(event)
            if is_delta:
                if not text:
                    return []
                result[field] = text
                return [result]
            result[field] = buffer.text
            events = []
            if text:
                delta = copy.deepcopy(result)
                delta["type"] = kind.removesuffix("done") + "delta"
                delta.pop(field)
                delta["delta"] = text
                events.append(delta)
            events.append(result)
            return events
        if kind in {
            "response.function_call_arguments.delta",
            "response.function_call_arguments.done",
            "response.custom_tool_call_input.delta",
            "response.custom_tool_call_input.done",
        }:
            is_delta = kind.endswith("delta")
            custom = kind.startswith("response.custom_tool")
            field = "delta" if is_delta else "input" if custom else "arguments"
            self.event(
                event, {"output_index", "item_id", field}, {"output_index", "item_id", field}
            )
            state = self.located(event)
            if (
                state["raw"]["type"] != ("custom_tool_call" if custom else "function_call")
                or state["args_done"]
            ):
                raise StreamProtocolError()
            value = _string(event[field])
            if is_delta:
                self.count(value)
                state["argument_chunks"].append(value)
            else:
                state["arguments"] = "".join(state["argument_chunks"])
                state["argument_chunks"].clear()
                if value != state["arguments"]:
                    raise StreamProtocolError("provider_snapshot_mismatch")
                state["args_done"] = True
            self.hold(event)
            return []
        if kind == "response.output_item.done":
            self.event(event, {"output_index", "item"}, {"output_index", "item"})
            index = _index(event["output_index"], self.max_items)
            if index >= len(self.items) or self.items[index]["done"]:
                raise StreamProtocolError()
            state = self.items[index]
            if state["raw"]["type"] == "message":
                if not all(part["done"] for part in state["parts"]):
                    raise StreamProtocolError()
            elif state["raw"]["type"] in _TOOL_KINDS and not state["args_done"]:
                raise StreamProtocolError()
            self.compare_item(event["item"], state)
            state["final_raw"] = copy.deepcopy(event["item"])
            state["done"] = True
            if state["raw"]["type"] in _TOOL_KINDS:
                self.hold(event)
                return []
            result = copy.deepcopy(event)
            result["item"] = self.item_snapshot(state, restored=True)
            return [result]
        if kind == "response.completed":
            self.event(event, {"response"}, {"response"})
            response = _response(
                event["response"],
                completed=True,
                max_items=self.max_items,
                expected_request=self.expected_request,
            )
            if response["id"] != self.response_id or len(response["output"]) != len(self.items):
                raise StreamProtocolError()
            for item, state in zip(response["output"], self.items, strict=True):
                if not state["done"]:
                    raise StreamProtocolError("truncated_provider_stream")
                self.compare_item(item, state)
            released = self.release_tools()
            response["output"] = [self.item_snapshot(state, restored=True) for state in self.items]
            if _size(response) > self.max_output_bytes:
                raise StreamProtocolError("provider_output_too_large")
            self.terminal = True
            result = copy.deepcopy(event)
            result["response"] = response
            return released + [result]
        raise StreamProtocolError("unsupported_provider_event")


class _Messages(_Machine):
    def __init__(self, *args):
        super().__init__(*args)
        self.blocks: list[dict] = []
        self.calls: set[str] = set()
        self.message_done = False
        self.message_delta: dict | None = None

    def located(self, event: dict) -> dict:
        index = _index(event.get("index"), self.max_items)
        if index >= len(self.blocks) or self.blocks[index]["done"]:
            raise StreamProtocolError()
        return self.blocks[index]

    def release_tools(self) -> list[dict]:
        _validate_batch(
            self.tools,
            [
                (block["raw"]["name"], "".join(block["argument_chunks"]) or "{}", False)
                for block in self.blocks
                if block["raw"]["type"] == "tool_use"
            ],
        )
        for block in self.blocks:
            if block["raw"]["type"] != "tool_use":
                continue
            arguments = "".join(block["argument_chunks"]) or "{}"
            # Parsing here rejects duplicate keys before registry restoration.
            json_object(arguments)
            block["restored"], outcome = _restore_tool(
                self.tools,
                self.ctx,
                block["raw"]["name"],
                arguments,
                self.provenance,
                self.restorer,
            )
            json_object(block["restored"])
            self.count(block["restored"], restored=True)
            self.outcome.merge(outcome)
        result = []
        sent: set[int] = set()
        for event in self.pending:
            index = event["index"]
            block = self.blocks[index]
            if event["type"] == "content_block_delta":
                if index in sent:
                    continue
                event["delta"]["partial_json"] = block["restored"]
                sent.add(index)
            elif event["type"] == "content_block_stop" and index not in sent:
                result.append(
                    {
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": "input_json_delta", "partial_json": block["restored"]},
                    }
                )
                sent.add(index)
            result.append(event)
        return result

    def handle(self, event: dict) -> list[dict]:
        kind = event.get("type")
        if kind == "error":
            raise StreamProtocolError("upstream_response_failed")
        if kind == "ping":
            self.event(event, set())
            return [copy.deepcopy(event)]
        if kind == "message_start":
            self.event(event, {"message"}, {"message"})
            if self.started:
                raise StreamProtocolError()
            _message(
                event["message"],
                start=True,
                max_items=self.max_items,
                expected_request=self.expected_request,
            )
            self.started = True
            return [copy.deepcopy(event)]
        if not self.started or self.message_done:
            raise StreamProtocolError()
        if kind == "content_block_start":
            self.event(event, {"index", "content_block"}, {"index", "content_block"})
            index = _index(event["index"], self.max_items)
            block = _block(event["content_block"], start=True)
            if index != len(self.blocks):
                raise StreamProtocolError()
            state = {
                "raw": block,
                "done": False,
                "argument_chunks": [],
                "buffer": self.text_buffer(),
            }
            if block["type"] == "tool_use":
                if block["id"] in self.calls:
                    raise StreamProtocolError()
                self.calls.add(block["id"])
            self.blocks.append(state)
            self.add_item()
            if block["type"] == "tool_use":
                self.hold(event)
                return []
            return [copy.deepcopy(event)]
        if kind == "content_block_delta":
            self.event(event, {"index", "delta"}, {"index", "delta"})
            block = self.located(event)
            delta = event["delta"]
            if block["raw"]["type"] == "text":
                _keys(delta, {"type", "text"}, {"type", "text"})
                if delta["type"] != "text_delta":
                    raise StreamProtocolError()
                value = _string(delta["text"])
                self.count(value)
                restored = block["buffer"].feed(value)
                self.count(restored, restored=True)
                if not restored:
                    return []
                result = copy.deepcopy(event)
                result["delta"]["text"] = restored
                return [result]
            _keys(delta, {"type", "partial_json"}, {"type", "partial_json"})
            if delta["type"] != "input_json_delta":
                raise StreamProtocolError()
            value = _string(delta["partial_json"])
            self.count(value)
            block["argument_chunks"].append(value)
            self.hold(event)
            return []
        if kind == "content_block_stop":
            self.event(event, {"index"}, {"index"})
            block = self.located(event)
            block["done"] = True
            if block["raw"]["type"] == "tool_use":
                self.hold(event)
                return []
            restored = block["buffer"].feed("", final=True)
            self.count(restored, restored=True)
            result = []
            if restored:
                result.append(
                    {
                        "type": "content_block_delta",
                        "index": event["index"],
                        "delta": {"type": "text_delta", "text": restored},
                    }
                )
            return result + [copy.deepcopy(event)]
        if kind == "message_delta":
            self.event(event, {"delta", "usage"}, {"delta", "usage"})
            _keys(
                event["delta"],
                {"stop_reason", "stop_sequence", "container", "stop_details"},
                {"stop_reason"},
            )
            _stop(event["delta"], self.expected_request)
            reason = event["delta"]["stop_reason"]
            _usage(event["usage"], messages=True)
            if self.message_delta is not None or not all(block["done"] for block in self.blocks):
                raise StreamProtocolError()
            if self.calls and reason != "tool_use":
                raise StreamProtocolError("upstream_response_failed")
            self.message_delta = copy.deepcopy(event)
            details = self.message_delta["delta"].get("stop_details")
            if details is not None and details.get("explanation") is not None:
                restored = self.restorer.restore(
                    self.ctx,
                    details["explanation"],
                    self.provenance,
                    max_output_bytes=self.max_output_bytes - self.restored_bytes,
                )
                details["explanation"] = restored.text
                self.count(restored.text, restored=True)
                self.outcome.merge(restored)
            self.message_done = True
            return []
        if kind == "message_stop":
            # Handled below outside the message_done guard.
            raise StreamProtocolError()
        raise StreamProtocolError("unsupported_provider_event")

    def complete(self, event: dict) -> list[dict]:
        self.event(event, set())
        if not self.started or not self.message_done or self.message_delta is None:
            raise StreamProtocolError("truncated_provider_stream")
        released = self.release_tools()
        self.terminal = True
        return released + [self.message_delta, copy.deepcopy(event)]


async def restore_stream(
    protocol: str,
    chunks: AsyncIterable[bytes],
    ctx: RequestContext,
    provenance: TokenProvenance,
    restorer: RestorationEngine,
    tools: ToolRegistry,
    *,
    max_event_bytes: int = MAX_EVENT_BYTES,
    max_items: int = MAX_ITEMS,
    max_output_bytes: int = MAX_RESTORED_CONTENT_BYTES,
    outcome: RestorationOutcome | None = None,
    expected_request: dict | None = None,
) -> AsyncIterator[bytes]:
    """Pull-driven stream; upstream cancellation follows generator closure."""
    if max_items < 1 or max_output_bytes < 1:
        raise ValueError("output limits must be positive")
    if protocol not in {"responses", "messages"}:
        raise ValueError("unknown protocol")
    outcome = outcome if outcome is not None else RestorationOutcome(text="")
    machine_type = _Responses if protocol == "responses" else _Messages
    machine = machine_type(
        ctx, provenance, restorer, tools, outcome, max_items, max_output_bytes, expected_request
    )
    terminal_events: list[dict] = []
    try:
        async for frame in parse_sse(chunks, max_event_bytes=max_event_bytes):
            if frame.heartbeat:
                if machine.terminal:
                    raise StreamProtocolError()
                yield b": keep-alive\n\n"
                continue
            payload = json_object(frame.data)
            _string(payload.get("type"))
            if frame.event is not None and frame.event != payload.get("type"):
                raise StreamProtocolError()
            if protocol == "messages" and payload.get("type") == "message_stop":
                events = machine.complete(payload)
            else:
                events = machine.handle(payload)
            if machine.terminal:
                terminal_events = events
                continue
            for event in events:
                yield machine.encode(event, responses=protocol == "responses")
    except RestorationOutputTooLargeError as exc:
        raise StreamProtocolError("provider_output_too_large") from exc
    except StreamProtocolError as exc:
        original = getattr(exc, "outcome", None)
        if isinstance(original, RestorationOutcome):
            outcome.merge(original)
        exc.outcome = outcome
        raise
    except (TypeError, KeyError, ValueError, RecursionError) as exc:
        raise StreamProtocolError() from exc
    finally:
        close = getattr(chunks, "aclose", None)
        if close is not None:
            await close()
    if not machine.terminal:
        raise StreamProtocolError("truncated_provider_stream")
    for event in terminal_events:
        yield machine.encode(event, responses=protocol == "responses")
