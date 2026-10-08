"""Native request coverage, unambiguous JSON, and safe reconstruction boundaries."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from gateway.api.schema import RequestRejected
from gateway.inspection.agent import AgentPreparation
from gateway.inspection.preparation import DetectionError
from gateway.protocols import (
    ContentLocation,
    loads_json,
    parse_messages_request,
    parse_responses_request,
    replace_location,
)
from gateway.protocols.base import MAX_COLLECTION, MAX_DEPTH
from gateway.tools.patches import APPLY_PATCH_LARK_GRAMMAR

CANARY = "synthetic-private@example.invalid"
NUMERIC_CARD = 4111111111111111


def responses(**fields: Any) -> dict[str, Any]:
    return {"model": "test-model", "input": "hello", **fields}


def messages(**fields: Any) -> dict[str, Any]:
    return {
        "model": "test-model",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": "hello"}],
        **fields,
    }


def schema() -> dict[str, Any]:
    return {
        "type": "object",
        "description": CANARY,
        "properties": {
            CANARY: {
                "type": "string",
                "description": CANARY,
                "title": CANARY,
                "examples": [CANARY, {CANARY: CANARY}],
                "default": CANARY,
                "enum": [CANARY],
                "pattern": CANARY,
            }
        },
        "required": [CANARY],
        "additionalProperties": False,
    }


def _plain_strings(value: Any, path=()):
    """Reference traversal independent of the protocol location visitor."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _plain_strings(item, path + (key,))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _plain_strings(item, path + (index,))


def _assert_complete_locations(request) -> None:
    values = {(location.path, location.json_path, location.text) for location in request.locations}
    for path, text in _plain_strings(request.payload):
        if path[-1:] == ("arguments",) or path == ("client_metadata", "x-codex-turn-metadata"):
            for nested_path, nested_text in _plain_strings(loads_json(text)):
                assert (path, nested_path, nested_text) in values
        else:
            assert (path, None, text) in values


def test_responses_inspects_every_replay_and_schema_content_location():
    payload = responses(
        instructions=CANARY,
        stream=True,
        input=[
            {"role": "developer", "content": [{"type": "input_text", "text": CANARY}]},
            {"role": "system", "content": CANARY},
            {"role": "user", "content": CANARY},
            {
                "type": "message",
                "role": "assistant",
                "content": [
                    {"type": "output_text", "text": CANARY, "annotations": []},
                    {"type": "refusal", "refusal": CANARY},
                ],
            },
            {
                "type": "function_call",
                "name": "read_file",
                "call_id": "call_a",
                "arguments": json.dumps({CANARY: [CANARY, {"nested": CANARY}]}),
            },
            {"type": "function_call_output", "call_id": "call_a", "output": CANARY},
            {
                "type": "custom_tool_call",
                "name": "apply_patch",
                "call_id": "call_b",
                "input": CANARY,
            },
            {
                "type": "custom_tool_call_output",
                "call_id": "call_b",
                "output": [{"type": "input_text", "text": CANARY}],
            },
        ],
        tools=[
            {
                "type": "function",
                "name": "read_file",
                "description": CANARY,
                "parameters": schema(),
                "strict": True,
            },
            {
                "type": "custom",
                "name": "apply_patch",
                "description": CANARY,
                "format": {"type": "text"},
            },
        ],
        text={
            "format": {
                "type": "json_schema",
                "name": "answer",
                "schema": schema(),
                "description": CANARY,
            }
        },
    )
    request = parse_responses_request(payload)
    _assert_complete_locations(request)
    assert request.protocol == "responses" and request.stream
    assert request.model == "test-model"
    assert request.tool_definitions == request.tools
    assert request.payload["store"] is False
    assert [item.get("role") for item in request.payload["input"][:4]] == [
        "developer",
        "system",
        "user",
        "assistant",
    ]
    assert all(CANARY in location.text for location in request.locations if not location.structural)
    assert any(location.text == CANARY and location.structural for location in request.locations)


def test_messages_inspects_native_schema_arguments_results_stops_and_system():
    cache = {"type": "ephemeral", "ttl": "1h"}
    payload = messages(
        stream=True,
        system=[{"type": "text", "text": CANARY, "cache_control": cache}],
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": CANARY, "cache_control": {"type": "ephemeral"}}
                ],
            },
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": CANARY},
                    {
                        "type": "tool_use",
                        "id": "call_a",
                        "name": "read_file",
                        "input": {CANARY: [CANARY, {"nested": CANARY}]},
                    },
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "call_a",
                        "is_error": True,
                        "content": [
                            {"type": "text", "text": CANARY, "cache_control": cache},
                        ],
                    }
                ],
            },
        ],
        tools=[
            {
                "name": "read_file",
                "description": CANARY,
                "input_schema": schema(),
                "cache_control": cache,
            }
        ],
        tool_choice={"type": "tool", "name": "read_file", "disable_parallel_tool_use": True},
        stop_sequences=[CANARY],
    )
    original = copy.deepcopy(payload)
    request = parse_messages_request(payload)
    _assert_complete_locations(request)
    assert request.protocol == "messages" and request.stream
    assert request.payload == original
    assert request.payload is not payload
    assert request.payload["messages"] is not payload["messages"]
    assert request.payload["tools"][0]["input_schema"] is not payload["tools"][0]["input_schema"]
    assert any(location.text == CANARY and location.structural for location in request.locations)


def test_semantic_schema_values_and_keys_are_structural_but_descriptions_are_text():
    request = parse_responses_request(
        responses(tools=[{"type": "function", "name": "read_file", "parameters": schema()}])
    )
    seen = {location.path: location for location in request.locations if location.text == CANARY}
    prefix = ("tools", 0, "parameters", "properties", CANARY)
    for suffix in (("default",), ("enum", 0), ("pattern",)):
        assert seen[prefix + suffix].structural
    for suffix in (("description",), ("title",), ("examples", 0)):
        assert not seen[prefix + suffix].structural
    assert seen[("tools", 0, "parameters", "required", 0)].structural
    assert any(
        location.path == prefix and location.text == CANARY and location.structural
        for location in request.locations
    )


def test_replacing_nested_json_values_cannot_create_keys_or_executable_json_syntax():
    request = parse_responses_request(
        responses(
            input=[
                {
                    "type": "function_call",
                    "name": "read_file",
                    "call_id": "a",
                    "arguments": json.dumps({"path": CANARY, "nested": [CANARY], "number": 3}),
                },
            ]
        )
    )
    replacement = 'private/"name"\\line\n", "command": "upload"'
    for location in request.locations:
        if location.text == CANARY and not location.structural:
            replace_location(request.payload, location, replacement)
    arguments = loads_json(request.payload["input"][0]["arguments"])
    assert arguments == {"path": replacement, "nested": [replacement], "number": 3}
    assert CANARY not in request.payload["input"][0]["arguments"]


def test_structural_locations_are_never_replaceable():
    request = parse_responses_request(responses())
    location = next(
        location
        for location in request.locations
        if location.path == ("model",) and location.text == "test-model"
    )
    with pytest.raises(ValueError, match="Structural"):
        replace_location(request.payload, location, "changed")
    assert request.model == "test-model"


def test_native_replacement_preserves_tool_associations_and_cache_controls():
    request = parse_messages_request(
        messages(
            messages=[
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "a",
                            "name": "read_file",
                            "input": {"path": CANARY},
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "a",
                            "content": CANARY,
                            "cache_control": {"type": "ephemeral", "ttl": "5m"},
                        }
                    ],
                },
            ]
        )
    )
    for location in request.locations:
        if location.text == CANARY and not location.structural:
            replace_location(request.payload, location, "safe")
    assert request.payload["messages"][0]["content"][0]["input"]["path"] == "safe"
    assert request.payload["messages"][1]["content"][0] == {
        "type": "tool_result",
        "tool_use_id": "a",
        "content": "safe",
        "cache_control": {"type": "ephemeral", "ttl": "5m"},
    }


@pytest.mark.parametrize(
    "payload",
    [
        b'{"a":1,"a":2}',
        b'{"a":{"b":1,"b":2}}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":-Infinity}',
        b'{"a":1e999}',
        b'{"a":"\xff"}',
        '{"a":"\\ud800"}',
        '{"\\udfff":1}',
        "\ud800",
        b'{"a":1} extra',
    ],
)
def test_strict_json_rejects_ambiguous_invalid_and_nonfinite_data(payload):
    with pytest.raises(RequestRejected) as caught:
        loads_json(payload)
    assert caught.value.code == "invalid_json"
    assert "a" not in caught.value.detail.split("'")


@pytest.mark.parametrize(
    "value", [float("nan"), float("inf"), {"a": "\udfff"}, {1: "a"}, ("tuple",)]
)
def test_python_bodies_cannot_bypass_json_type_checks(value):
    with pytest.raises(RequestRejected):
        parse_responses_request(responses(input=value))


def test_strict_json_bounds_nesting_collections_and_bytes():
    nested = "[" * (MAX_DEPTH + 1) + "0" + "]" * (MAX_DEPTH + 1)
    for payload in (
        nested,
        json.dumps([0] * (MAX_COLLECTION + 1)),
        json.dumps({str(index): 0 for index in range(MAX_COLLECTION + 1)}),
        '"' + "x" * (4 * 1024 * 1024) + '"',
    ):
        with pytest.raises(RequestRejected) as caught:
            loads_json(payload)
        assert caught.value.code == "request_too_large"


@pytest.mark.parametrize(
    "parser, make_body",
    [
        (parse_responses_request, responses),
        (parse_messages_request, messages),
    ],
)
@pytest.mark.parametrize("field", ["temperature", "top_p"])
def test_huge_finite_json_integers_are_safe_contract_errors(parser, make_body, field):
    payload = json.dumps(make_body(**{field: 10**1000}))
    with pytest.raises(RequestRejected) as caught:
        parser(payload)
    assert caught.value.code == "invalid_request"


def test_schema_integer_bounds_are_not_coerced_to_floating_point():
    huge = 10**1000
    request = parse_responses_request(
        responses(
            text={
                "format": {
                    "type": "json_schema",
                    "name": "answer",
                    "schema": {
                        "type": "integer",
                        "minimum": huge,
                        "maximum": huge + 1,
                    },
                }
            },
        )
    )
    assert request.payload["text"]["format"]["schema"]["minimum"] == huge
    assert request.payload["text"]["format"]["schema"]["maximum"] == huge + 1


def test_numeric_arguments_are_inspected_without_coercing_native_types():
    arguments = {"count": NUMERIC_CARD, "values": [NUMERIC_CARD, float(NUMERIC_CARD), 1e20]}
    encoded = parse_responses_request(
        responses(
            input=[
                {
                    "type": "function_call",
                    "name": "read_file",
                    "call_id": "a",
                    "arguments": json.dumps(arguments),
                }
            ]
        )
    )
    native = parse_messages_request(
        messages(
            messages=[
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "a",
                            "name": "read_file",
                            "input": arguments,
                        }
                    ],
                }
            ]
        )
    )
    for request in (encoded, native):
        numeric = [
            location
            for location in request.locations
            if location.text.startswith(str(NUMERIC_CARD))
        ]
        assert len(numeric) == 3
        assert all(location.structural for location in numeric)
        assert any(location.text == "100000000000000000000" for location in request.locations)
    assert loads_json(encoded.payload["input"][0]["arguments"]) == arguments
    assert native.payload["messages"][0]["content"][0]["input"] == arguments


@pytest.mark.parametrize(
    "field, value",
    [
        ("default", NUMERIC_CARD),
        ("const", NUMERIC_CARD),
        ("enum", [NUMERIC_CARD]),
        ("examples", [{"nested": [NUMERIC_CARD]}]),
        ("minimum", NUMERIC_CARD),
        ("maximum", NUMERIC_CARD),
        ("exclusiveMinimum", NUMERIC_CARD),
        ("exclusiveMaximum", NUMERIC_CARD),
        ("multipleOf", NUMERIC_CARD),
    ],
)
async def test_sensitive_numeric_schema_content_fails_inspection(pipeline, ctx, field, value):
    request = parse_responses_request(
        responses(
            text={
                "format": {
                    "type": "json_schema",
                    "name": "answer",
                    "schema": {"type": "number", field: value},
                }
            }
        )
    )
    assert any(
        location.text == str(NUMERIC_CARD) and location.structural for location in request.locations
    )
    preparation = AgentPreparation(pipeline.preparation, max_input_chars=256000, detector_timeout=5)
    with pytest.raises(DetectionError, match="Sensitive structural"):
        await preparation.prepare(ctx, request)


@pytest.mark.parametrize("protocol", ["responses", "messages"])
async def test_sensitive_numeric_argument_content_fails_inspection(pipeline, ctx, protocol):
    if protocol == "responses":
        request = parse_responses_request(
            responses(
                input=[
                    {
                        "type": "function_call",
                        "name": "read_file",
                        "call_id": "a",
                        "arguments": json.dumps({"nested": {"number": NUMERIC_CARD}}),
                    }
                ]
            )
        )
    else:
        request = parse_messages_request(
            messages(
                messages=[
                    {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "a",
                                "name": "read_file",
                                "input": {"nested": {"number": NUMERIC_CARD}},
                            }
                        ],
                    }
                ]
            )
        )
    preparation = AgentPreparation(pipeline.preparation, max_input_chars=256000, detector_timeout=5)
    with pytest.raises(DetectionError, match="Sensitive structural"):
        await preparation.prepare(ctx, request)


def test_fixed_numeric_protocol_controls_are_not_customer_content():
    response_request = parse_responses_request(
        responses(temperature=1, top_p=0.5, max_output_tokens=100)
    )
    message_request = parse_messages_request(
        messages(temperature=1, top_p=0.5, max_tokens=100, top_k=10)
    )
    for request in (response_request, message_request):
        control_paths = {
            ("temperature",),
            ("top_p",),
            ("max_output_tokens",),
            ("max_tokens",),
            ("top_k",),
        }
        assert all(
            location.text == location.path[-1]
            for location in request.locations
            if location.path in control_paths
        )


def test_python_integer_exceeding_json_representation_is_rejected_safely():
    with pytest.raises(RequestRejected) as caught:
        parse_messages_request(
            messages(
                messages=[
                    {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "a",
                                "name": "read_file",
                                "input": {"number": 10**5000},
                            }
                        ],
                    }
                ]
            )
        )
    assert caught.value.code == "invalid_json"


def test_pinned_codex_request_controls_are_explicit_and_fully_classified():
    metadata = {
        "installation_id": "installation_a",
        "session_id": "session_a",
        "thread_id": "thread_a",
        "agent_name": "Codex",
        "turn_id": "turn_a",
        "window_id": "session_a:1",
        "window_number": 1,
        "model": "synthetic-agent-model",
        "reasoning_effort": "none",
        "request_kind": "turn",
        "thread_source": "user",
        "sandbox_mode": "workspace-write",
        "auto_review_enabled": False,
        "node_repl_disabled": True,
        "turn_started_at_unix_ms": 1791420000000,
        "workspaces": {
            "/workspace/synthetic": {
                "associated_remote_urls": {"origin": "https://example.invalid/project.git"},
                "has_changes": False,
            }
        },
        "tool_namespaces_info": {
            "functions": {
                "name": "functions",
                "functions": {
                    "read_file": {
                        "name": "read_file",
                        "direct": True,
                        "code_mode_name": None,
                        "deferred": False,
                        "source": {"kind": "harness"},
                    }
                },
            }
        },
    }
    request = parse_responses_request(
        responses(
            prompt_cache_key="session_a",
            include=["reasoning.encrypted_content"],
            reasoning={},
            client_metadata={
                "session_id": "session_a",
                "thread_id": "thread_a",
                "x-codex-installation-id": "installation_a",
                "x-codex-window-id": "session_a:1",
                "turn_id": "turn_a",
                "x-codex-turn-metadata": json.dumps(metadata),
            },
        )
    )
    _assert_complete_locations(request)
    assert request.payload["include"] == ["reasoning.encrypted_content"]
    assert request.payload["prompt_cache_key"] == "session_a"
    assert loads_json(request.payload["client_metadata"]["x-codex-turn-metadata"]) == metadata
    assert all(
        location.structural
        for location in request.locations
        if location.path[:1] == ("client_metadata",)
    )
    assert any(
        location.path == ("prompt_cache_key",)
        and location.text == "session_a"
        and location.structural
        for location in request.locations
    )
    assert not any(location.text == "1791420000000" for location in request.locations)


def test_codex_local_compaction_attribution_has_an_explicit_contract():
    metadata = {
        "request_kind": "compaction",
        "compaction": {
            "trigger": "auto",
            "reason": "context_limit",
            "implementation": "responses",
            "phase": "pre_turn",
            "strategy": "memento",
        },
    }
    request = parse_responses_request(
        responses(client_metadata={"x-codex-turn-metadata": json.dumps(metadata)})
    )
    assert loads_json(request.payload["client_metadata"]["x-codex-turn-metadata"]) == metadata
    metadata["compaction"]["implementation"] = "responses_compaction_v2"
    with pytest.raises(RequestRejected):
        parse_responses_request(
            responses(client_metadata={"x-codex-turn-metadata": json.dumps(metadata)})
        )


@pytest.mark.parametrize(
    "metadata",
    [
        {CANARY: CANARY},
        {"session_id": CANARY},
        {"x-codex-window-id": "session_a:2147483648"},
        {"x-codex-window-id": "session_a:1:2"},
        {"x-codex-turn-metadata": json.dumps({"window_id": "session_a:1:2"})},
        {"x-codex-turn-metadata": json.dumps({"model": CANARY})},
        {"x-codex-turn-metadata": json.dumps({"reasoning_effort": CANARY})},
        {"x-codex-turn-metadata": json.dumps({"reasoning_effort": None})},
        {"x-codex-turn-metadata": json.dumps({"reasoning_effort": {"effort": "none"}})},
        {"x-codex-turn-metadata": json.dumps({CANARY: CANARY})},
        {"x-codex-turn-metadata": json.dumps({"workspaces": {"safe": {CANARY: CANARY}}})},
        {"x-codex-turn-metadata": '{"agent_name":"first","agent_name":"second"}'},
        {"x-codex-turn-metadata": json.dumps({"auto_review_enabled": "true"})},
        {"x-codex-turn-metadata": json.dumps({"turn_started_at_unix_ms": 10**1000})},
    ],
)
def test_codex_unknown_or_invalid_metadata_is_refused_without_echo(metadata):
    with pytest.raises(RequestRejected) as caught:
        parse_responses_request(responses(client_metadata=metadata))
    assert CANARY not in caught.value.detail


async def test_sensitive_codex_metadata_strings_cannot_escape_inspection(pipeline, ctx):
    request = parse_responses_request(
        responses(
            client_metadata={
                "x-codex-turn-metadata": json.dumps({"agent_name": CANARY}),
            }
        )
    )
    assert (
        ContentLocation(("client_metadata", "x-codex-turn-metadata"), CANARY, True, ("agent_name",))
        in request.locations
    )
    preparation = AgentPreparation(pipeline.preparation, max_input_chars=256000, detector_timeout=5)
    with pytest.raises(DetectionError, match="Sensitive structural"):
        await preparation.prepare(ctx, request)


@pytest.mark.parametrize("phase", [None, "commentary", "final_answer"])
def test_codex_assistant_message_phase_survives_history_replay(phase):
    request = parse_responses_request(
        responses(
            input=[
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "done"}],
                    "phase": phase,
                }
            ]
        )
    )
    assert request.payload["input"][0]["phase"] == phase
    for role in ("user", "developer", "system"):
        with pytest.raises(RequestRejected):
            parse_responses_request(
                responses(input=[{"role": role, "content": "hello", "phase": phase}])
            )


def test_only_empty_inspectable_reasoning_placeholders_can_be_replayed():
    item = {
        "type": "reasoning",
        "id": "rs_a",
        "summary": [],
        "content": [],
        "encrypted_content": None,
        "status": None,
    }
    request = parse_responses_request(
        responses(input=[item, {"role": "user", "content": "follow up"}])
    )
    assert request.payload["input"][0] == item
    for fields in (
        {"encrypted_content": ""},
        {"encrypted_content": CANARY},
        {"content": [{"type": "reasoning_text", "text": CANARY}]},
        {"summary": [{"type": "summary_text", "text": CANARY}]},
    ):
        with pytest.raises(RequestRejected):
            parse_responses_request(responses(input=[{**item, **fields}]))


def test_deferred_tool_loading_is_not_implicitly_enabled():
    tool = {
        "type": "function",
        "name": "read_file",
        "parameters": {"type": "object"},
        "defer_loading": False,
    }
    request = parse_responses_request(responses(tools=[tool]))
    assert request.tools[0]["defer_loading"] is False
    for value in (True, "false", 0):
        with pytest.raises(RequestRejected):
            parse_responses_request(responses(tools=[{**tool, "defer_loading": value}]))


def test_only_exact_pinned_public_apply_patch_grammar_is_accepted():
    fmt = {"type": "grammar", "syntax": "lark", "definition": APPLY_PATCH_LARK_GRAMMAR}
    tool = {"type": "custom", "name": "apply_patch", "format": fmt}
    request = parse_responses_request(responses(tools=[tool]))
    assert request.tools[0]["format"] == fmt
    assert (
        ContentLocation(("tools", 0, "format", "definition"), APPLY_PATCH_LARK_GRAMMAR, True)
        in request.locations
    )
    for altered in (
        {**fmt, "definition": fmt["definition"] + CANARY},
        {**fmt, "syntax": "regex"},
        {**fmt, CANARY: CANARY},
    ):
        with pytest.raises(RequestRejected) as caught:
            parse_responses_request(responses(tools=[{**tool, "format": altered}]))
        assert CANARY not in caught.value.detail
    with pytest.raises(RequestRejected):
        parse_responses_request(responses(tools=[{**tool, "name": "arbitrary_patch"}]))


@pytest.mark.parametrize("tier", ["fast", "ultrafast"])
def test_documented_responses_bounded_controls_do_not_enable_opaque_content(tier):
    request = parse_responses_request(responses(service_tier=tier, reasoning={"effort": "max"}))
    _assert_complete_locations(request)
    assert request.payload["service_tier"] == tier
    assert request.payload["reasoning"] == {"effort": "max"}
    with pytest.raises(RequestRejected):
        parse_responses_request(
            responses(
                service_tier=tier,
                reasoning={"effort": "max"},
                input=[{"type": "reasoning", "encrypted_content": "opaque"}],
            )
        )


@pytest.mark.parametrize("effort", ["low", "medium", "high", "xhigh", "max"])
def test_messages_disabled_thinking_and_effort_controls_preserve_native_contract(effort):
    request = parse_messages_request(
        messages(thinking={"type": "disabled"}, output_config={"effort": effort})
    )
    _assert_complete_locations(request)
    assert request.payload["thinking"] == {"type": "disabled"}
    assert request.payload["output_config"] == {"effort": effort}


def test_messages_captured_identity_is_bounded_and_inspected_as_local_metadata():
    identity = {
        "device_id": "ab" * 32,
        "account_uuid": "",
        "session_id": "01234567-89ab-cdef-0123-456789abcdef",
    }
    request = parse_messages_request(messages(metadata={"user_id": json.dumps(identity)}))
    _assert_complete_locations(request)
    user_id = request.payload["metadata"]["user_id"]
    assert loads_json(user_id) == identity
    assert ContentLocation(("metadata", "user_id"), user_id, True) in request.locations
    for fields in (
        {"user_id": CANARY},
        {CANARY: CANARY},
        {"user_id": json.dumps({**identity, CANARY: CANARY})},
        {"user_id": json.dumps({**identity, "device_id": CANARY})},
        {"user_id": json.dumps({**identity, "session_id": "not-a-uuid"})},
        {"user_id": '{"device_id":"a","device_id":"b"}'},
    ):
        with pytest.raises(RequestRejected) as caught:
            parse_messages_request(messages(metadata=fields))
        assert CANARY not in caught.value.detail


def test_messages_top_level_cache_control_counts_toward_the_shared_breakpoint_limit():
    block = {"type": "text", "text": "instructions", "cache_control": {"type": "ephemeral"}}
    request = parse_messages_request(
        messages(system=[block] * 3, cache_control={"type": "ephemeral", "ttl": "1h"})
    )
    _assert_complete_locations(request)
    assert request.payload["cache_control"] == {"type": "ephemeral", "ttl": "1h"}
    with pytest.raises(RequestRejected) as caught:
        parse_messages_request(messages(system=[block] * 4, cache_control={"type": "ephemeral"}))
    assert caught.value.code == "invalid_cache_control"
    for fields in (
        {"cache_control": {"type": "ephemeral", CANARY: CANARY}},
        {"thinking": {"type": "disabled", CANARY: CANARY}},
        {"thinking": {"type": "adaptive"}},
        {"output_config": {"effort": CANARY}},
        {"output_config": {"effort": "max", CANARY: CANARY}},
    ):
        with pytest.raises(RequestRejected) as caught:
            parse_messages_request(messages(**fields))
        assert CANARY not in caught.value.detail


@pytest.mark.parametrize(
    "parser,make_body,fields",
    [
        (parse_responses_request, responses, {CANARY: CANARY}),
        (parse_responses_request, responses, {"metadata": {CANARY: CANARY}}),
        (parse_responses_request, responses, {"previous_response_id": CANARY}),
        (parse_responses_request, responses, {"store": True}),
        (parse_responses_request, responses, {"background": True}),
        (parse_responses_request, responses, {"prompt_cache_key": CANARY}),
        (parse_responses_request, responses, {"include": ["output_text.logprobs"]}),
        (
            parse_responses_request,
            responses,
            {"input": [{"type": "reasoning", "encrypted_content": CANARY}]},
        ),
        (
            parse_responses_request,
            responses,
            {"input": [{"type": "compaction", "encrypted_content": CANARY}]},
        ),
        (
            parse_responses_request,
            responses,
            {
                "input": [
                    {"role": "user", "content": [{"type": "input_image", "image_url": CANARY}]}
                ]
            },
        ),
        (
            parse_responses_request,
            responses,
            {
                "tools": [
                    {
                        "type": "custom",
                        "name": "patch",
                        "format": {"type": "grammar", "syntax": "lark", "definition": CANARY},
                    }
                ]
            },
        ),
        (parse_messages_request, messages, {CANARY: CANARY}),
        (parse_messages_request, messages, {"metadata": {"user_id": CANARY}}),
        (parse_messages_request, messages, {"thinking": {"type": "enabled", "budget_tokens": 128}}),
        (
            parse_messages_request,
            messages,
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [{"type": "image", "source": {"type": "url", "url": CANARY}}],
                    }
                ]
            },
        ),
        (
            parse_messages_request,
            messages,
            {
                "messages": [
                    {
                        "role": "assistant",
                        "content": [{"type": "thinking", "thinking": CANARY, "signature": CANARY}],
                    }
                ]
            },
        ),
        (
            parse_messages_request,
            messages,
            {
                "system": [
                    {
                        "type": "text",
                        "text": "hello",
                        "cache_control": {"type": "ephemeral", CANARY: CANARY},
                    }
                ]
            },
        ),
    ],
)
def test_uninspectable_unknown_and_opaque_fields_fail_without_echo(parser, make_body, fields):
    with pytest.raises(RequestRejected) as caught:
        parser(make_body(**fields))
    assert CANARY not in str(caught.value)
    assert CANARY not in caught.value.detail


@pytest.mark.parametrize(
    "parser,make_body,fields",
    [
        (parse_responses_request, responses, {"model": CANARY}),
        (parse_responses_request, responses, {"stream": "true"}),
        (parse_responses_request, responses, {"temperature": True}),
        (parse_responses_request, responses, {"max_output_tokens": "123"}),
        (parse_responses_request, responses, {"input": [{"role": "alien", "content": CANARY}]}),
        (
            parse_responses_request,
            responses,
            {
                "input": [
                    {"type": "function_call", "name": CANARY, "call_id": "a", "arguments": "{}"}
                ]
            },
        ),
        (parse_messages_request, messages, {"max_tokens": True}),
        (parse_messages_request, messages, {"stream": 1}),
        (parse_messages_request, messages, {"messages": [{"role": "system", "content": CANARY}]}),
        (
            parse_messages_request,
            messages,
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "tool_use", "id": "a", "name": "read_file", "input": {}}
                        ],
                    }
                ]
            },
        ),
    ],
)
def test_strict_controls_and_roles_refuse_coercion(parser, make_body, fields):
    with pytest.raises(RequestRejected) as caught:
        parser(make_body(**fields))
    assert CANARY not in caught.value.detail


@pytest.mark.parametrize(
    "arguments", ['{"a":1,"a":2}', "[]", '"text"', '{"a":NaN}', '{"a":"\\ud800"}']
)
def test_function_arguments_must_be_unambiguous_json_objects(arguments):
    with pytest.raises(RequestRejected):
        parse_responses_request(
            responses(
                input=[
                    {
                        "type": "function_call",
                        "name": "read_file",
                        "call_id": "a",
                        "arguments": arguments,
                    }
                ]
            )
        )


@pytest.mark.parametrize(
    "parser,payload",
    [
        (
            parse_responses_request,
            responses(
                input=[{"type": "function_call_output", "call_id": "unknown", "output": "hello"}]
            ),
        ),
        (
            parse_responses_request,
            responses(
                input=[
                    {
                        "type": "function_call",
                        "name": "read_file",
                        "call_id": "a",
                        "arguments": "{}",
                    },
                    {"type": "custom_tool_call_output", "call_id": "a", "output": "hello"},
                ]
            ),
        ),
        (
            parse_responses_request,
            responses(
                input=[
                    {
                        "type": "function_call",
                        "name": "read_file",
                        "call_id": "a",
                        "arguments": "{}",
                    }
                ]
                * 2
            ),
        ),
        (
            parse_messages_request,
            messages(
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {"type": "tool_result", "tool_use_id": "unknown", "content": "hello"}
                        ],
                    }
                ]
            ),
        ),
    ],
)
def test_dangling_mismatched_and_duplicate_history_is_rejected(parser, payload):
    with pytest.raises(RequestRejected) as caught:
        parser(payload)
    assert caught.value.code == "invalid_history"


@pytest.mark.parametrize(
    "parser,payload",
    [
        (
            parse_responses_request,
            responses(
                tools=[
                    {
                        "type": "function",
                        "name": "read_file",
                        "parameters": {"$ref": "https://example.invalid/private.json"},
                    }
                ]
            ),
        ),
        (
            parse_messages_request,
            messages(
                tools=[
                    {
                        "name": "read_file",
                        "input_schema": {"$ref": "https://example.invalid/private.json"},
                    }
                ]
            ),
        ),
    ],
)
def test_remote_schema_references_cannot_introduce_uninspected_input(parser, payload):
    with pytest.raises(RequestRejected) as caught:
        parser(payload)
    assert caught.value.code == "uninspectable_field"
    assert "example.invalid" not in caught.value.detail


def test_cache_controls_are_explicit_and_bounded_without_dropping_semantics():
    for control in ({"type": "ephemeral", "ttl": "forever"}, {"type": "persistent"}):
        with pytest.raises(RequestRejected):
            parse_messages_request(
                messages(system=[{"type": "text", "text": "hello", "cache_control": control}])
            )
    with pytest.raises(RequestRejected) as caught:
        parse_messages_request(
            messages(
                system=[{"type": "text", "text": "hello", "cache_control": {"type": "ephemeral"}}]
                * 5
            )
        )
    assert caught.value.code == "invalid_cache_control"


JSON_VALUES = st.recursive(
    st.none() | st.booleans() | st.integers(min_value=-1000, max_value=1000) | st.text(max_size=30),
    lambda child: (
        st.lists(child, max_size=4) | st.dictionaries(st.text(max_size=20), child, max_size=4)
    ),
    max_leaves=15,
)


@given(value=JSON_VALUES)
@settings(max_examples=80)
def test_malformed_native_requests_always_fail_with_safe_contract_errors(value):
    payloads = [
        (
            parse_responses_request,
            responses(input=[{"type": value, "role": "user", "content": "hello"}]),
        ),
        (
            parse_responses_request,
            responses(input=[{"role": "user", "content": [{"type": value, "text": "hello"}]}]),
        ),
        (
            parse_responses_request,
            responses(tools=[{"type": value, "name": "read_file", "parameters": {}}]),
        ),
        (parse_responses_request, responses(text={"format": {"type": value}})),
        (
            parse_messages_request,
            messages(messages=[{"role": "user", "content": [{"type": value, "text": "hello"}]}]),
        ),
    ]
    for parser, payload in payloads:
        try:
            request = parser(payload)
        except RequestRejected:
            pass
        else:
            _assert_complete_locations(request)


@given(value=JSON_VALUES)
@settings(max_examples=100)
def test_every_arbitrary_native_json_string_has_a_classified_location(value):
    payload = messages(
        messages=[
            {
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "a", "name": "read_file", "input": {"value": value}}
                ],
            }
        ]
    )
    request = parse_messages_request(payload)
    _assert_complete_locations(request)
    for path, text in _plain_strings(value, ("messages", 0, "content", 0, "input", "value")):
        assert any(
            location.path == path and location.text == text and not location.structural
            for location in request.locations
        )


@given(value=JSON_VALUES)
@settings(max_examples=100)
def test_every_encoded_json_argument_string_has_a_classified_location(value):
    payload = responses(
        input=[
            {
                "type": "function_call",
                "call_id": "a",
                "name": "read_file",
                "arguments": json.dumps({"value": value}),
            }
        ]
    )
    request = parse_responses_request(payload)
    _assert_complete_locations(request)
    for path, text in _plain_strings(value, ("value",)):
        assert ContentLocation(("input", 0, "arguments"), text, False, path) in request.locations
