"""Synthetic native SSE, token boundaries, and atomic executable delivery.

Public-schema defaults use openai-python 9301e319ea33ef28fba380f39a289dedc14652c1
and anthropic-sdk-python 50b78d17a8a73bef97c3884102310344ac00f056. Message phase and
empty reasoning replay also match Codex rust-v0.161.0 protocol models at commit
979011409de0a60b52f179721948e65531d26144. Fixtures contain invented content only.
"""

from __future__ import annotations

import copy
import json

import pytest

from gateway.restoration.engine import RestorationEngine, RestorationOutcome
from gateway.streaming.protocols import restore_response, restore_stream
from gateway.streaming.sse import StreamProtocolError, encode_event, json_object, parse_sse
from gateway.streaming.tokens import MAX_TOKEN_LENGTH, IncrementalRestorer
from gateway.tools.registry import ToolRegistry
from gateway.transformations.tokens import TokenProvenance


async def _chunks(frames, *, bytewise=False):
    for frame in frames:
        raw = frame if isinstance(frame, bytes) else encode_event(frame, frame["type"])
        if bytewise:
            for byte in raw:
                yield bytes([byte])
        else:
            yield raw


async def _decode(chunks):
    return [json_object(frame.data) async for frame in parse_sse(chunks) if not frame.heartbeat]


def _response(items, *, completed=True):
    return {
        "id": "resp_test",
        "object": "response",
        "model": "mock-model",
        "status": "completed" if completed else "in_progress",
        "output": items,
        "usage": {"input_tokens": 10, "output_tokens": 3, "total_tokens": 13},
    }


def _text_events(deltas, *, refusal=False):
    raw = "".join(deltas)
    part = (
        {"type": "refusal", "refusal": raw}
        if refusal
        else {
            "type": "output_text",
            "text": raw,
            "annotations": [],
        }
    )
    field = "refusal" if refusal else "text"
    prefix = "response.refusal" if refusal else "response.output_text"
    item = {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "status": "completed",
        "content": [part],
    }
    locator = {"item_id": "msg_test", "output_index": 0, "content_index": 0}
    result = [
        {"type": "response.created", "response": _response([], completed=False)},
        {
            "type": "response.output_item.added",
            "output_index": 0,
            "item": {**item, "status": "in_progress", "content": []},
        },
        {"type": "response.content_part.added", **locator, "part": {**part, field: ""}},
    ]
    result.extend({"type": prefix + ".delta", **locator, "delta": delta} for delta in deltas)
    result.extend(
        [
            {"type": prefix + ".done", **locator, field: raw},
            {"type": "response.content_part.done", **locator, "part": part},
            {"type": "response.output_item.done", "output_index": 0, "item": item},
            {"type": "response.completed", "response": _response([item])},
        ]
    )
    return result


def _tool_events(calls):
    items = []
    result = [{"type": "response.created", "response": _response([], completed=False)}]
    for index, (name, arguments) in enumerate(calls):
        item = {
            "id": f"fc_{index}",
            "type": "function_call",
            "call_id": f"call_{index}",
            "name": name,
            "arguments": arguments,
            "status": "completed",
        }
        items.append(item)
        locator = {"item_id": item["id"], "output_index": index}
        result.extend(
            [
                {
                    "type": "response.output_item.added",
                    "output_index": index,
                    "item": {**item, "status": "in_progress", "arguments": ""},
                },
                {
                    "type": "response.function_call_arguments.delta",
                    **locator,
                    "delta": arguments[: len(arguments) // 2],
                },
                {
                    "type": "response.function_call_arguments.delta",
                    **locator,
                    "delta": arguments[len(arguments) // 2 :],
                },
                {
                    "type": "response.function_call_arguments.done",
                    **locator,
                    "arguments": arguments,
                },
                {"type": "response.output_item.done", "output_index": index, "item": item},
            ]
        )
    result.append({"type": "response.completed", "response": _response(items)})
    return result


def _messages(deltas, *, tool=False):
    start = {
        "type": "message_start",
        "message": {
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "model": "mock-model",
            "content": [],
            "stop_reason": None,
            "stop_sequence": None,
            "usage": {"input_tokens": 10, "output_tokens": 0},
        },
    }
    block = (
        {"type": "tool_use", "id": "call_test", "name": "read_file", "input": {}}
        if tool
        else {
            "type": "text",
            "text": "",
        }
    )
    result = [start, {"type": "content_block_start", "index": 0, "content_block": block}]
    for delta in deltas:
        result.append(
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": delta}
                if tool
                else {
                    "type": "text_delta",
                    "text": delta,
                },
            }
        )
    return result + [
        {"type": "content_block_stop", "index": 0},
        {
            "type": "message_delta",
            "delta": {
                "stop_reason": "tool_use" if tool else "end_turn",
                "stop_sequence": None,
            },
            "usage": {"output_tokens": 3},
        },
        {"type": "message_stop"},
    ]


@pytest.fixture
def restoration(ctx, minter, vault, tmp_path):
    provenance = TokenProvenance()
    token = minter.mint(ctx, "PERSON", "Ilze Bērziņa", provenance).token
    vault.put(ctx, token, "Ilze Bērziņa", "v1")
    return token, provenance, RestorationEngine(vault), ToolRegistry(tmp_path)


@pytest.mark.parametrize("protocol", ["responses", "messages"])
async def test_every_token_split_and_split_multibyte_utf8(ctx, restoration, protocol):
    token, provenance, restorer, tools = restoration
    for split in range(len(token) + 1):
        deltas = ["🙂 " + token[:split], token[split:] + " — done"]
        frames = _text_events(deltas) if protocol == "responses" else _messages(deltas)
        outcome = RestorationOutcome(text="")
        result = await _decode(
            restore_stream(
                protocol,
                _chunks(frames, bytewise=True),
                ctx,
                provenance,
                restorer,
                tools,
                outcome=outcome,
            )
        )
        if protocol == "responses":
            text = "".join(
                event["delta"] for event in result if event["type"] == "response.output_text.delta"
            )
            assert result[-1]["response"]["output"][0]["content"][0]["text"] == text
            assert result[-1]["response"]["usage"]["output_tokens"] == 3
        else:
            text = "".join(
                event["delta"]["text"] for event in result if event["type"] == "content_block_delta"
            )
            assert result[-2]["usage"]["output_tokens"] == 3
        assert text == "🙂 Ilze Bērziņa — done"
        assert outcome.restored == 1


def test_token_suffix_bound_comes_from_grammar(ctx, restoration):
    _, provenance, restorer, _ = restoration
    buffer = IncrementalRestorer(ctx, provenance, restorer, RestorationOutcome(""), 2048)
    for character in "<" + "A" * 64 + ":v1:" + "a" * 32:
        buffer.feed(character)
        assert len(buffer.suffix) < MAX_TOKEN_LENGTH
    buffer.feed(">")
    assert buffer.suffix == ""


async def test_forged_tokens_remain_verbatim_in_refusal_prose(ctx, restoration):
    _, _, restorer, tools = restoration
    forged = "<PERSON:v1:" + "a" * 32 + ">"
    outcome = RestorationOutcome("")
    result = await _decode(
        restore_stream(
            "responses",
            _chunks(_text_events(["Refused " + forged], refusal=True)),
            ctx,
            TokenProvenance(),
            restorer,
            tools,
            outcome=outcome,
        )
    )
    assert result[-1]["response"]["output"][0]["content"][0]["refusal"] == "Refused " + forged
    assert outcome.refused_not_minted == 1


@pytest.mark.parametrize("protocol", ["responses", "messages"])
async def test_tools_wait_for_terminal_and_validated_eof(ctx, restoration, protocol):
    _, provenance, restorer, tools = restoration
    arguments = json.dumps({"path": "src/demo.py"})
    events = (
        _tool_events([("read_file", arguments)])
        if protocol == "responses"
        else _messages([arguments], tool=True)
    )
    read = 0

    async def source():
        nonlocal read
        for event in events:
            read += 1
            yield encode_event(event, event["type"])
        read += 1

    stream = restore_stream(protocol, source(), ctx, provenance, restorer, tools)
    start = await anext(stream)
    assert b"created" in start or b"message_start" in start
    assert read == 1
    first_tool = await anext(stream)
    assert b"function_call" in first_tool or b"tool_use" in first_tool
    assert read == len(events) + 1
    result = await _decode(_chunks([first_tool] + [chunk async for chunk in stream]))
    assert result[-1]["type"] == (
        "response.completed" if protocol == "responses" else "message_stop"
    )


async def test_tool_batch_refuses_all_if_second_call_fails(ctx, restoration):
    _, provenance, restorer, tools = restoration
    events = _tool_events(
        [
            ("read_file", json.dumps({"path": "src/demo.py"})),
            ("read_file", json.dumps({"path": "<PERSON:v1:" + "f" * 32 + ">"})),
        ]
    )
    delivered = []
    with pytest.raises(StreamProtocolError, match="tool_restoration_failed"):
        async for chunk in restore_stream(
            "responses", _chunks(events), ctx, provenance, restorer, tools
        ):
            delivered.append(chunk)
    assert len(delivered) == 1
    assert b"function_call" not in b"".join(delivered)
    assert b"response.completed" not in b"".join(delivered)


@pytest.mark.parametrize("protocol", ["responses", "messages"])
async def test_trailing_malformed_frame_never_releases_tools(ctx, restoration, protocol):
    _, provenance, restorer, tools = restoration
    arguments = json.dumps({"path": "src/demo.py"})
    frames = (
        _tool_events([("read_file", arguments)])
        if protocol == "responses"
        else _messages([arguments], tool=True)
    )
    frames.append(b"data: {invalid}\n\n")
    delivered = []
    with pytest.raises(StreamProtocolError):
        async for chunk in restore_stream(
            protocol, _chunks(frames), ctx, provenance, restorer, tools
        ):
            delivered.append(chunk)
    assert len(delivered) == 1


@pytest.mark.parametrize(
    "mutation", ["identity", "duplicate", "snapshot", "unknown", "truncated", "reorder"]
)
async def test_invalid_response_transitions_fail_safely(ctx, restoration, mutation):
    _, provenance, restorer, tools = restoration
    frames = _text_events(["hello"])
    if mutation == "identity":
        frames[3]["item_id"] = "msg_other"
    elif mutation == "duplicate":
        frames.insert(2, copy.deepcopy(frames[1]))
    elif mutation == "snapshot":
        frames[4]["text"] = "different"
    elif mutation == "unknown":
        frames[3]["raw_private_field"] = "private canary"
    elif mutation == "truncated":
        frames.pop()
    else:
        frames[2], frames[3] = frames[3], frames[2]
    delivered = []
    with pytest.raises(StreamProtocolError) as failure:
        async for chunk in restore_stream(
            "responses", _chunks(frames), ctx, provenance, restorer, tools
        ):
            delivered.append(chunk)
    assert "canary" not in str(failure.value)
    assert b"response.completed" not in b"".join(delivered)


@pytest.mark.parametrize(
    "frames",
    [
        [b"data: {}\n\n"],
        [b'data: {"type":"ping","type":"message_stop"}\n\n'],
        [b'data: {"type":"ping","bad":NaN}\n\n'],
        [b'data: {"type":"ping","bad":"\\ud800"}\n\n'],
        [b"data: \xff\n\n"],
        [b'data: {"type":"ping"}'],
        [b'event: message_stop\ndata: {"type":"ping"}\n\n'],
    ],
)
async def test_malformed_sse_and_json_fail(ctx, restoration, frames):
    _, provenance, restorer, tools = restoration
    with pytest.raises(StreamProtocolError):
        await _decode(restore_stream("messages", _chunks(frames), ctx, provenance, restorer, tools))


async def test_event_limit_applies_to_split_frames(ctx, restoration):
    _, provenance, restorer, tools = restoration
    with pytest.raises(StreamProtocolError, match="provider_event_too_large"):
        await _decode(
            restore_stream(
                "responses",
                _chunks(_text_events(["x" * 1000]), bytewise=True),
                ctx,
                provenance,
                restorer,
                tools,
                max_event_bytes=700,
            )
        )


async def test_item_and_output_limits(ctx, restoration):
    _, provenance, restorer, tools = restoration
    with pytest.raises(StreamProtocolError):
        await _decode(
            restore_stream(
                "responses",
                _chunks(
                    _tool_events([("read_file", '{"path":"a"}'), ("read_file", '{"path":"b"}')])
                ),
                ctx,
                provenance,
                restorer,
                tools,
                max_items=1,
            )
        )
    with pytest.raises(StreamProtocolError, match="provider_output_too_large"):
        await _decode(
            restore_stream(
                "responses",
                _chunks(_text_events(["x" * 500])),
                ctx,
                provenance,
                restorer,
                tools,
                max_output_bytes=100,
            )
        )


async def test_cancellation_closes_source_without_prefetch(ctx, restoration):
    _, provenance, restorer, tools = restoration
    reads = 0
    closed = False

    async def source():
        nonlocal reads, closed
        try:
            for event in _text_events(["hello"]):
                reads += 1
                yield encode_event(event)
        finally:
            closed = True

    stream = restore_stream("responses", source(), ctx, provenance, restorer, tools)
    await anext(stream)
    assert reads == 1
    await stream.aclose()
    assert closed


def test_buffered_output_validates_all_shapes_and_atomic_batch(ctx, restoration):
    token, provenance, restorer, tools = restoration
    response = _text_events([token])[-1]["response"]
    restored, outcome = restore_response("responses", response, ctx, provenance, restorer, tools)
    assert restored["output"][0]["content"][0]["text"] == "Ilze Bērziņa"
    assert outcome.restored == 1
    assert response["output"][0]["content"][0]["text"] == token
    response["output"][0]["content"] = [{"type": "image", "url": "https://private.invalid"}]
    with pytest.raises(StreamProtocolError):
        restore_response("responses", response, ctx, provenance, restorer, tools)
    unsafe = _tool_events([("read_file", '{"path":"a"}'), ("unknown_tool", "{}")])[-1]["response"]
    with pytest.raises(StreamProtocolError):
        restore_response("responses", unsafe, ctx, provenance, restorer, tools)


def test_sanitized_request_echoes_must_match_current_request(ctx, restoration):
    token, provenance, restorer, tools = restoration
    response = _text_events(["hello"])[-1]["response"]
    expected = {
        "model": "mock-model",
        "input": "hello",
        "instructions": "Contact " + token,
        "tools": [
            {
                "type": "function",
                "name": "read_file",
                "description": "Read local source",
                "parameters": {"type": "object", "properties": {"path": {"type": "string"}}},
            }
        ],
    }
    response["instructions"] = expected["instructions"]
    response["tools"] = expected["tools"]
    restored, _ = restore_response(
        "responses", response, ctx, provenance, restorer, tools, expected_request=expected
    )
    assert restored["instructions"] == expected["instructions"]
    response["instructions"] = "private changed canary"
    with pytest.raises(StreamProtocolError, match="provider_snapshot_mismatch"):
        restore_response(
            "responses", response, ctx, provenance, restorer, tools, expected_request=expected
        )


async def test_sse_crlf_cr_comments_and_multiline():
    frames = [b": ping\r\n\r\n", b'event: ping\rdata: {\rdata: "type":"ping"}\r\r']
    result = [frame async for frame in parse_sse(_chunks(frames, bytewise=True))]
    assert result[0].heartbeat
    assert json_object(result[1].data) == {"type": "ping"}


async def test_custom_patch_input_is_restored_once_after_completion(ctx, restoration):
    token, provenance, restorer, tools = restoration
    patch = "*** Begin Patch\n*** Add File: src/demo.py\n+name = '" + token + "'\n*** End Patch\n"
    events = _tool_events([("apply_patch", patch)])
    for event in events:
        event["type"] = event["type"].replace("function_call_arguments", "custom_tool_call_input")
        if "arguments" in event:
            event["input"] = event.pop("arguments")
        items = [event["item"]] if "item" in event else event.get("response", {}).get("output", [])
        for item in items:
            item["type"] = "custom_tool_call"
            if "arguments" in item:
                item["input"] = item.pop("arguments")
    outcome = RestorationOutcome("")
    result = await _decode(
        restore_stream(
            "responses", _chunks(events), ctx, provenance, restorer, tools, outcome=outcome
        )
    )
    deltas = [
        event["delta"]
        for event in result
        if event["type"] == "response.custom_tool_call_input.delta"
    ]
    assert len(deltas) == 1
    assert "Ilze Bērziņa" in deltas[0]
    assert result[-1]["response"]["output"][0]["input"] == deltas[0]
    assert outcome.restored == 1


@pytest.mark.parametrize("protocol", ["responses", "messages"])
async def test_batch_and_restoration_run_once_per_unique_call(ctx, restoration, protocol):
    _, provenance, restorer, registry = restoration
    arguments = json.dumps({"path": "src/demo.py"})

    class CountRegistry:
        restores = 0
        batches = []

        def validate_batch(self, calls):
            self.batches.append(calls)

        def restore(self, *args, **kwargs):
            self.restores += 1
            return registry.restore(*args, **kwargs)

    bound = CountRegistry()
    frames = (
        _tool_events([("read_file", arguments)])
        if protocol == "responses"
        else _messages([arguments], tool=True)
    )
    await _decode(restore_stream(protocol, _chunks(frames), ctx, provenance, restorer, bound))
    assert bound.restores == 1
    assert bound.batches == [[("read_file", arguments, False)]]


async def test_independent_text_streams_while_tools_wait_and_sequences_stay_ordered(
    ctx, restoration
):
    _, provenance, restorer, tools = restoration
    tool = _tool_events([("read_file", '{"path":"src/demo.py"}')])
    prose = _text_events(["still working"])
    for event in prose[1:-1]:
        if "output_index" in event:
            event["output_index"] = 1
    final = copy.deepcopy(tool[-1])
    final["response"]["output"].append(prose[-1]["response"]["output"][0])
    frames = tool[:-1] + prose[1:-1] + [final]
    for sequence, event in enumerate(frames):
        event["sequence_number"] = sequence
    result = await _decode(
        restore_stream("responses", _chunks(frames), ctx, provenance, restorer, tools)
    )
    text_index = next(
        index for index, event in enumerate(result) if event["type"] == "response.output_text.delta"
    )
    tool_index = next(
        index
        for index, event in enumerate(result)
        if event["type"] == "response.function_call_arguments.delta"
    )
    assert text_index < tool_index
    assert result[text_index]["output_index"] == 1
    assert result[tool_index]["output_index"] == 0
    assert [event["sequence_number"] for event in result] == list(range(len(result)))


async def test_native_stop_sequence_matches_only_sanitized_request(ctx, restoration):
    _, provenance, restorer, tools = restoration
    frames = _messages(["hello"])
    frames[-2]["delta"] = {"stop_reason": "stop_sequence", "stop_sequence": "END"}
    result = await _decode(
        restore_stream(
            "messages",
            _chunks(frames),
            ctx,
            provenance,
            restorer,
            tools,
            expected_request={"stop_sequences": ["END"]},
        )
    )
    assert result[-2]["delta"]["stop_sequence"] == "END"
    with pytest.raises(StreamProtocolError, match="provider_snapshot_mismatch"):
        await _decode(
            restore_stream(
                "messages",
                _chunks(frames),
                ctx,
                provenance,
                restorer,
                tools,
                expected_request={"stop_sequences": ["OTHER"]},
            )
        )


async def test_tool_refusal_outcome_carries_safe_counters(ctx, restoration):
    _, provenance, restorer, tools = restoration
    arguments = json.dumps({"path": "<PERSON:v1:" + "f" * 32 + ">"})
    outcome = RestorationOutcome("")
    with pytest.raises(StreamProtocolError) as failure:
        await _decode(
            restore_stream(
                "responses",
                _chunks(_tool_events([("read_file", arguments)])),
                ctx,
                provenance,
                restorer,
                tools,
                outcome=outcome,
            )
        )
    assert failure.value.outcome is outcome
    assert outcome.refused_not_minted == 1
    assert outcome.text == ""
    with pytest.raises(StreamProtocolError) as buffered:
        restore_response(
            "responses",
            _tool_events([("read_file", arguments)])[-1]["response"],
            ctx,
            provenance,
            restorer,
            tools,
        )
    assert buffered.value.outcome.refused_not_minted == 1
    assert buffered.value.outcome.text == ""


@pytest.mark.parametrize(
    "corruption", ["sequence_duplicate", "sequence_missing", "sequence_reverse"]
)
async def test_response_sequence_contract_is_strict(ctx, restoration, corruption):
    _, provenance, restorer, tools = restoration
    frames = _text_events(["hello"])
    for index, event in enumerate(frames):
        event["sequence_number"] = index
    if corruption == "sequence_missing":
        frames[2].pop("sequence_number")
    else:
        frames[2]["sequence_number"] = 1 if corruption == "sequence_duplicate" else 0
    with pytest.raises(StreamProtocolError):
        await _decode(
            restore_stream("responses", _chunks(frames), ctx, provenance, restorer, tools)
        )


async def test_crlf_is_included_in_event_size_limit():
    frame = b"data: {}\r\n\r\n"
    assert len(frame) == 12
    with pytest.raises(StreamProtocolError, match="provider_event_too_large"):
        [event async for event in parse_sse(_chunks([frame]), max_event_bytes=11)]


@pytest.mark.parametrize("bad_type", [[], {}, False, None, 12])
def test_malformed_buffered_control_types_fail_safely(ctx, restoration, bad_type):
    _, provenance, restorer, tools = restoration
    response = _text_events(["hello"])[-1]["response"]
    response["output"][0]["type"] = bad_type
    with pytest.raises(StreamProtocolError):
        restore_response("responses", response, ctx, provenance, restorer, tools)


@pytest.mark.parametrize(
    "data",
    [
        '{"usage":1e999}',
        '{"\\ud800":"value"}',
        json.dumps({"array": [0] * 513}),
        json.dumps({str(index): 0 for index in range(513)}),
        '{"nested":' + "[" * 33 + "0" + "]" * 33 + "}",
    ],
)
def test_decoder_rejects_nonfinite_keys_collections_and_depth(data):
    with pytest.raises(StreamProtocolError):
        json_object(data)


@pytest.mark.parametrize("tier", ["standard", "priority", "batch"])
@pytest.mark.parametrize("geo", ["us", "global", "not_available"])
async def test_native_cache_usage_start_and_delta_preserved(ctx, restoration, tier, geo):
    _, provenance, restorer, tools = restoration
    frames = _messages(["cached source response"])
    initial = {
        "input_tokens": 7,
        "output_tokens": 0,
        "cache_creation_input_tokens": 1400,
        "cache_read_input_tokens": 2200,
        "cache_creation": {"ephemeral_5m_input_tokens": 900, "ephemeral_1h_input_tokens": 500},
        "server_tool_use": {"web_search_requests": 0, "web_fetch_requests": 0},
        "service_tier": tier,
        "inference_geo": geo,
        "output_tokens_details": {"thinking_tokens": 0},
    }
    final = {
        **initial,
        "output_tokens": 17,
        "output_tokens_details": {"thinking_tokens": 4},
    }
    frames[0]["message"]["model"] = "claude-sonnet-4-5"
    frames[0]["message"]["usage"] = initial
    frames[-2]["usage"] = final
    result = await _decode(
        restore_stream(
            "messages",
            _chunks(frames),
            ctx,
            provenance,
            restorer,
            tools,
        )
    )
    assert result[0]["message"]["usage"] == initial
    assert result[-2]["usage"] == final
    buffered = {
        **frames[0]["message"],
        "content": [{"type": "text", "text": "cached source response"}],
        "stop_reason": "end_turn",
        "usage": final,
    }
    restored, _ = restore_response("messages", buffered, ctx, provenance, restorer, tools)
    assert restored["usage"] == final


async def test_native_optional_usage_null_fields_preserved(ctx, restoration):
    _, provenance, restorer, tools = restoration
    frames = _messages(["hello"])
    optional = {
        "cache_creation_input_tokens": None,
        "cache_read_input_tokens": None,
        "cache_creation": None,
        "server_tool_use": None,
        "output_tokens_details": None,
        "service_tier": None,
        "inference_geo": None,
    }
    frames[0]["message"]["usage"].update(optional)
    frames[-2]["usage"].update(optional)
    result = await _decode(
        restore_stream("messages", _chunks(frames), ctx, provenance, restorer, tools)
    )
    assert all(result[0]["message"]["usage"][key] is None for key in optional)
    assert all(result[-2]["usage"][key] is None for key in optional)


@pytest.mark.parametrize(
    "bad_usage",
    [
        {"service_tier": "private canary"},
        {"inference_geo": "private canary"},
        {"service_tier": {}},
        {"inference_geo": False},
        {"cache_creation": {"ephemeral_5m_input_tokens": -1}},
        {"cache_creation": {"ephemeral_1h_input_tokens": True}},
        {"cache_creation": {"unknown_private_field": 4}},
        {"cache_read_input_tokens": "40"},
        {"output_tokens_details": {"thinking_tokens": 1.2}},
        {"output_tokens_details": {"encrypted_content": "opaque"}},
        {"unknown_private_field": 4},
    ],
)
@pytest.mark.parametrize("location", ["start", "delta"])
async def test_native_usage_contract_rejects_unknown_or_untyped_fields(
    ctx,
    restoration,
    bad_usage,
    location,
):
    _, provenance, restorer, tools = restoration
    frames = _messages(["hello"])
    usage = frames[0]["message"]["usage"] if location == "start" else frames[-2]["usage"]
    usage.update(bad_usage)
    with pytest.raises(StreamProtocolError) as failure:
        await _decode(restore_stream("messages", _chunks(frames), ctx, provenance, restorer, tools))
    assert "canary" not in str(failure.value)


@pytest.mark.parametrize(
    "model", ["gpt-5.1", "claude-sonnet-4-5", "provider/claude-sonnet-4-5", "provider:gpt-5.1"]
)
async def test_named_models_with_dots_and_hyphens_are_accepted(ctx, restoration, model):
    _, provenance, restorer, tools = restoration
    frames = _text_events(["hello"])
    frames[0]["response"]["model"] = model
    frames[-1]["response"]["model"] = model
    result = await _decode(
        restore_stream("responses", _chunks(frames), ctx, provenance, restorer, tools)
    )
    assert result[-1]["response"]["model"] == model


@pytest.mark.parametrize("identifier", ["msg.private", "msg:private", "msg/private"])
def test_output_control_ids_use_id_grammar_instead_of_model_grammar(ctx, restoration, identifier):
    _, provenance, restorer, tools = restoration
    response = _text_events(["hello"])[-1]["response"]
    response["output"][0]["id"] = identifier
    with pytest.raises(StreamProtocolError):
        restore_response("responses", response, ctx, provenance, restorer, tools)


def _public_response_defaults():
    # OpenAI's public Response schema defines these metadata/control properties
    # as optional nullable fields, while id/output/status remain our validated
    # terminal and snapshot contract. No opaque capability is enabled by null.
    return {
        "created_at": 1770323456.125,
        "completed_at": None,
        "background": None,
        "temperature": None,
        "top_p": None,
        "truncation": None,
        "metadata": None,
        "reasoning": None,
        "text": None,
        "instructions": None,
        "error": None,
        "incomplete_details": None,
        "max_output_tokens": None,
        "max_tool_calls": None,
        "previous_response_id": None,
        "service_tier": None,
        "prompt_cache_key": None,
        "prompt_cache_retention": None,
        "safety_identifier": None,
        "user": None,
        "top_logprobs": None,
        "conversation": None,
        "prompt": None,
        "moderation": None,
        "access_programs": None,
        "prompt_cache_options": None,
        "prompt_cache_diagnostics": None,
        "end_turn": None,
        "usage_metadata": None,
        "tools": [],
        "tool_choice": "auto",
        "parallel_tool_calls": True,
        "store": False,
    }


@pytest.mark.parametrize("phase", [None, "commentary", "final_answer"])
async def test_public_responses_nullable_defaults_and_message_phase(ctx, restoration, phase):
    token, provenance, restorer, tools = restoration
    frames = _text_events(["Hello " + token])
    for event in frames:
        if "response" in event:
            event["response"].update(_public_response_defaults())
        if "item" in event:
            event["item"]["phase"] = phase
            event["item"]["internal_chat_message_metadata_passthrough"] = None
        if "part" in event:
            event["part"]["logprobs"] = None
    frames[-1]["response"]["completed_at"] = 1770323457.875
    frames[-1]["response"]["end_turn"] = True
    frames[-1]["response"]["usage"]["input_tokens_details"] = {
        "cached_tokens": 7,
        "cache_write_tokens": 3,
    }
    frames[-1]["response"]["usage"]["output_tokens_details"] = {"reasoning_tokens": 0}
    frames[-1]["response"]["usage"]["codex_rollout_budget_units"] = 1.25
    result = await _decode(
        restore_stream("responses", _chunks(frames), ctx, provenance, restorer, tools)
    )
    final = result[-1]["response"]
    assert final["output"][0]["phase"] == phase
    assert final["output"][0]["content"][0]["logprobs"] is None
    assert final["output"][0]["content"][0]["text"] == "Hello Ilze Bērziņa"
    assert final["metadata"] is None and final["reasoning"] is None
    assert final["created_at"] == 1770323456.125
    assert final["completed_at"] == 1770323457.875
    assert final["usage"] == frames[-1]["response"]["usage"]
    buffered, _ = restore_response(
        "responses", frames[-1]["response"], ctx, provenance, restorer, tools
    )
    assert buffered == final


async def test_phase_can_first_arrive_at_item_completion_and_stays_stable(ctx, restoration):
    _, provenance, restorer, tools = restoration
    frames = _text_events(["final answer"])
    frames[1]["item"]["phase"] = None
    frames[-2]["item"]["phase"] = "final_answer"
    result = await _decode(
        restore_stream("responses", _chunks(frames), ctx, provenance, restorer, tools)
    )
    assert result[-2]["item"]["phase"] == "final_answer"
    assert result[-1]["response"]["output"][0]["phase"] == "final_answer"
    frames[-1] = copy.deepcopy(frames[-1])
    frames[-1]["response"]["output"][0]["phase"] = "commentary"
    with pytest.raises(StreamProtocolError, match="provider_snapshot_mismatch"):
        await _decode(
            restore_stream("responses", _chunks(frames), ctx, provenance, restorer, tools)
        )


def _empty_reasoning_events(*, terminal=True):
    initial = {
        "id": "rs_test",
        "type": "reasoning",
        "summary": [],
        "content": None,
        "encrypted_content": None,
        "status": "in_progress",
    }
    final = {**initial, "status": "completed"}
    events = [
        {"type": "response.created", "response": _response([], completed=False)},
        {"type": "response.output_item.added", "output_index": 0, "item": initial},
        {"type": "response.output_item.done", "output_index": 0, "item": final},
    ]
    if terminal:
        events.append({"type": "response.completed", "response": _response([final])})
    return events


async def test_empty_inspectable_reasoning_item_round_trip(ctx, restoration):
    _, provenance, restorer, tools = restoration
    frames = _empty_reasoning_events()
    result = await _decode(
        restore_stream("responses", _chunks(frames), ctx, provenance, restorer, tools)
    )
    assert result[-1]["response"] == frames[-1]["response"]
    buffered, outcome = restore_response(
        "responses", frames[-1]["response"], ctx, provenance, restorer, tools
    )
    assert buffered == frames[-1]["response"]
    assert outcome.restored == 0


async def test_empty_reasoning_never_becomes_a_tool_or_breaks_batch_atomicity(ctx, restoration):
    _, provenance, restorer, tools = restoration
    reasoning = _empty_reasoning_events(terminal=False)
    tool = _tool_events([("read_file", '{"path":"src/demo.py"}')])
    for event in tool[1:-1]:
        event["output_index"] = 1
    final = copy.deepcopy(tool[-1])
    final["response"]["output"].insert(0, reasoning[-1]["item"])
    frames = reasoning + tool[1:-1] + [final]
    result = await _decode(
        restore_stream("responses", _chunks(frames), ctx, provenance, restorer, tools)
    )
    assert result[-1]["response"]["output"][0] == reasoning[-1]["item"]
    assert result[-1]["response"]["output"][1]["name"] == "read_file"
    assert [
        event["item"]["type"] for event in result if event["type"] == "response.output_item.done"
    ] == ["reasoning", "function_call"]


@pytest.mark.parametrize(
    "change",
    [
        {"encrypted_content": ""},
        {"encrypted_content": "opaque signed payload"},
        {"content": [{"type": "reasoning_text", "text": "unsupported"}]},
        {"summary": [{"type": "summary_text", "text": "unsupported"}]},
        {"internal_chat_message_metadata_passthrough": {"opaque": "signed"}},
    ],
)
async def test_nonempty_or_opaque_reasoning_still_refused_before_tools_release(
    ctx, restoration, change
):
    _, provenance, restorer, tools = restoration
    tool = _tool_events([("read_file", '{"path":"src/demo.py"}')])
    reasoning = _empty_reasoning_events(terminal=False)[1:]
    for event in reasoning:
        event["output_index"] = 1
    reasoning[-1]["item"].update(change)
    frames = tool[:-1] + reasoning
    delivered = []
    with pytest.raises(StreamProtocolError):
        async for event in restore_stream(
            "responses", _chunks(frames), ctx, provenance, restorer, tools
        ):
            delivered.append(event)
    assert b"function_call" not in b"".join(delivered)
    assert b"response.completed" not in b"".join(delivered)


@pytest.mark.parametrize("caller", [None, {"type": "direct"}])
async def test_public_tool_nullable_metadata_remains_direct_and_atomic(ctx, restoration, caller):
    _, provenance, restorer, tools = restoration
    frames = _tool_events([("read_file", '{"path":"src/demo.py"}')])
    for event in frames:
        if "item" in event:
            event["item"].update(
                {
                    "namespace": None,
                    "caller": caller,
                    "async": None,
                    "status": None,
                    "encrypted_function_args": None,
                    "internal_chat_message_metadata_passthrough": None,
                }
            )
    result = await _decode(
        restore_stream("responses", _chunks(frames), ctx, provenance, restorer, tools)
    )
    final_item = result[-1]["response"]["output"][0]
    assert final_item["caller"] == caller
    assert final_item["namespace"] is None and final_item["status"] is None
    assert json.loads(final_item["arguments"]) == {"path": "src/demo.py"}


@pytest.mark.parametrize(
    "field",
    [
        "conversation",
        "prompt",
        "moderation",
        "prompt_cache_options",
        "prompt_cache_diagnostics",
        "usage_metadata",
    ],
)
def test_nullable_unimplemented_provider_state_cannot_carry_nonnull_data(ctx, restoration, field):
    _, provenance, restorer, tools = restoration
    response = _text_events(["hello"])[-1]["response"]
    response[field] = {"opaque": "private canary"}
    with pytest.raises(StreamProtocolError) as failure:
        restore_response("responses", response, ctx, provenance, restorer, tools)
    assert "canary" not in str(failure.value)


def test_bound_metadata_and_cache_echoes_cannot_cross_requests(ctx, restoration):
    _, provenance, restorer, tools = restoration
    response = _text_events(["hello"])[-1]["response"]
    expected = {
        "prompt_cache_key": "cloakspan_scoped_digest",
        "metadata": {"application": "coding"},
    }
    response.update(expected)
    response["prompt_cache_retention"] = "in_memory"
    restored, _ = restore_response(
        "responses", response, ctx, provenance, restorer, tools, expected_request=expected
    )
    assert restored["prompt_cache_key"] == "cloakspan_scoped_digest"
    assert restored["metadata"] == expected["metadata"]
    with pytest.raises(StreamProtocolError):
        restore_response(
            "responses",
            response,
            ctx,
            provenance,
            restorer,
            tools,
            expected_request={"prompt_cache_key": "other_request"},
        )


async def test_native_nullable_public_message_and_delta_metadata(ctx, restoration):
    _, provenance, restorer, tools = restoration
    frames = _messages(["hello"])
    frames[0]["message"].update({"container": None, "diagnostics": None, "stop_details": None})
    frames[1]["content_block"]["citations"] = None
    frames[-2]["delta"].update({"container": None, "stop_details": None})
    result = await _decode(
        restore_stream("messages", _chunks(frames), ctx, provenance, restorer, tools)
    )
    assert result[0]["message"]["container"] is None
    assert result[1]["content_block"]["citations"] is None
    assert result[-2]["delta"]["stop_details"] is None
    buffered = {
        **frames[0]["message"],
        "content": [{"type": "text", "text": "hello", "citations": None}],
        "stop_reason": "end_turn",
    }
    restored, _ = restore_response("messages", buffered, ctx, provenance, restorer, tools)
    assert restored == buffered


async def test_native_refusal_explanation_is_typed_bounded_prose(ctx, restoration):
    token, provenance, restorer, tools = restoration
    frames = _messages(["Cannot perform that request."])
    details = {
        "type": "refusal",
        "category": "general_harms",
        "explanation": "Refused for " + token,
    }
    frames[-2]["delta"].update({"stop_reason": "refusal", "stop_details": details})
    outcome = RestorationOutcome("")
    result = await _decode(
        restore_stream(
            "messages", _chunks(frames), ctx, provenance, restorer, tools, outcome=outcome
        )
    )
    assert result[-2]["delta"]["stop_details"]["explanation"] == "Refused for Ilze Bērziņa"
    assert outcome.restored == 1
    buffered = {
        **frames[0]["message"],
        "content": [{"type": "text", "text": "Cannot perform that request."}],
        "stop_reason": "refusal",
        "stop_details": details,
    }
    restored, buffered_outcome = restore_response(
        "messages", buffered, ctx, provenance, restorer, tools
    )
    assert restored["stop_details"]["explanation"] == "Refused for Ilze Bērziņa"
    assert buffered_outcome.restored == 1


@pytest.mark.parametrize(
    "block",
    [
        {"type": "thinking", "thinking": "", "signature": ""},
        {"type": "redacted_thinking", "data": ""},
    ],
)
async def test_native_signed_or_redacted_reasoning_remains_refused(ctx, restoration, block):
    _, provenance, restorer, tools = restoration
    frames = _messages(["hello"])
    frames[1]["content_block"] = block
    with pytest.raises(StreamProtocolError):
        await _decode(restore_stream("messages", _chunks(frames), ctx, provenance, restorer, tools))


@pytest.mark.parametrize("tier", ["fast", "ultrafast"])
def test_public_response_service_tier_enum(ctx, restoration, tier):
    _, provenance, restorer, tools = restoration
    response = _text_events(["hello"])[-1]["response"]
    response["service_tier"] = tier
    restored, _ = restore_response("responses", response, ctx, provenance, restorer, tools)
    assert restored["service_tier"] == tier
