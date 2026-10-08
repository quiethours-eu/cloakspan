"""Current-request tool declarations constrain every executable output call."""

from __future__ import annotations

import hashlib
import json

import pytest

from gateway.restoration.engine import RestorationEngine
from gateway.tools import BoundToolRegistry, ToolRegistry, ToolRestorationError
from gateway.tools.patches import APPLY_PATCH_LARK_GRAMMAR
from gateway.transformations.tokens import TokenProvenance


def _schema(**path_constraints):
    return {
        "type": "object",
        "properties": {"path": {"type": "string", **path_constraints}},
        "required": ["path"],
        "additionalProperties": False,
    }


def _tool(name="read_file", schema=None, protocol="responses", custom=False):
    if protocol == "messages":
        return {"name": name, "input_schema": _schema() if schema is None else schema}
    if custom:
        return {"type": "custom", "name": name, "format": {"type": "text"}}
    return {"type": "function", "name": name, "parameters": _schema() if schema is None else schema}


def _bound(tmp_path, payload=None, protocol="responses"):
    return BoundToolRegistry(
        ToolRegistry(tmp_path),
        {"tools": [_tool(protocol=protocol)]} if payload is None else payload,
        protocol,
    )


def _call(bound, ctx, vault, path="source.py", name="read_file", custom=False, provenance=None):
    return bound.restore(
        ctx,
        name,
        json.dumps({"path": path}),
        TokenProvenance() if provenance is None else provenance,
        RestorationEngine(vault),
        custom=custom,
    )


def test_no_declared_tools_does_not_authorize_registered_tool(tmp_path, ctx, vault):
    with pytest.raises(ToolRestorationError, match="could not be restored safely") as caught:
        _call(_bound(tmp_path, {}), ctx, vault)
    assert caught.value.code == "undeclared_tool_call"


def test_only_this_requests_name_and_type_are_authorized(tmp_path, ctx, vault):
    bound = _bound(tmp_path)
    assert json.loads(_call(bound, ctx, vault)[0]) == {"path": "source.py"}
    for name, custom in [("Read", False), ("read_file", True)]:
        with pytest.raises(ToolRestorationError):
            _call(bound, ctx, vault, name=name, custom=custom)


def test_custom_and_function_apply_patch_are_distinct_contracts(tmp_path, ctx, vault):
    bound = _bound(tmp_path, {"tools": [_tool("apply_patch", custom=True)]})
    patch = "*** Begin Patch\n*** Add File: source.py\n+# synthetic\n*** End Patch"
    result, _ = bound.restore(
        ctx, "apply_patch", patch, TokenProvenance(), RestorationEngine(vault), custom=True
    )
    assert result == patch
    with pytest.raises(ToolRestorationError):
        bound.restore(
            ctx,
            "apply_patch",
            json.dumps({"patch": patch}),
            TokenProvenance(),
            RestorationEngine(vault),
        )


@pytest.mark.parametrize(
    "protocol,choice",
    [
        ("responses", "none"),
        ("messages", {"type": "none"}),
    ],
)
def test_none_choice_forbids_calls_but_accepts_empty_completion(
    tmp_path, ctx, vault, protocol, choice
):
    bound = _bound(tmp_path, {"tools": [_tool(protocol=protocol)], "tool_choice": choice}, protocol)
    bound.validate_batch([])
    with pytest.raises(ToolRestorationError):
        _call(bound, ctx, vault)


@pytest.mark.parametrize(
    "protocol,choice",
    [
        ("responses", "required"),
        ("messages", {"type": "any"}),
        ("responses", {"type": "function", "name": "read_file"}),
        ("messages", {"type": "tool", "name": "read_file"}),
    ],
)
def test_required_choice_needs_at_least_one_completed_call(tmp_path, protocol, choice):
    bound = _bound(tmp_path, {"tools": [_tool(protocol=protocol)], "tool_choice": choice}, protocol)
    with pytest.raises(ToolRestorationError) as caught:
        bound.validate_batch([])
    assert caught.value.code == "tool_choice_violation"
    bound.validate_batch([("read_file", '{"path":"source.py"}', False)])


@pytest.mark.parametrize(
    "protocol,choice",
    [
        ("responses", {"type": "function", "name": "read_file"}),
        ("messages", {"type": "tool", "name": "read_file"}),
    ],
)
def test_selected_tool_excludes_other_declared_tools(tmp_path, ctx, vault, protocol, choice):
    bound = _bound(
        tmp_path,
        {
            "tools": [_tool(protocol=protocol), _tool("read", protocol=protocol)],
            "tool_choice": choice,
        },
        protocol,
    )
    with pytest.raises(ToolRestorationError) as caught:
        _call(bound, ctx, vault, name="read")
    assert caught.value.code == "tool_choice_violation"


@pytest.mark.parametrize(
    "protocol,options",
    [
        ("responses", {"max_tool_calls": 1}),
        ("responses", {"parallel_tool_calls": False}),
        ("messages", {"tool_choice": {"type": "auto", "disable_parallel_tool_use": True}}),
    ],
)
def test_complete_batch_obeys_count_and_parallel_limits(tmp_path, protocol, options):
    bound = _bound(tmp_path, {"tools": [_tool(protocol=protocol)], **options}, protocol)
    call = ("read_file", '{"path":"source.py"}', False)
    bound.validate_batch([call])
    with pytest.raises(ToolRestorationError):
        bound.validate_batch([call, call])


def test_restoring_snapshots_does_not_double_count_calls(tmp_path, ctx, vault):
    bound = _bound(tmp_path, {"tools": [_tool()], "max_tool_calls": 1})
    first = _call(bound, ctx, vault)[0]
    assert _call(bound, ctx, vault)[0] == first
    bound.validate_batch([("read_file", first, False)])


@pytest.mark.parametrize(
    "assertion",
    [
        {"pattern": "^safe$"},
        {"$ref": "#/properties/path"},
        {"format": "uri"},
        {"if": True, "then": False},
        {"not": False},
        {"multipleOf": 2},
        {"unevaluatedProperties": False},
        {"dependentSchemas": {}},
        {"unknownPrivateKey": "secret"},
    ],
)
def test_unsupported_executable_assertions_fail_at_bind_before_egress(tmp_path, assertion):
    schema = _schema()
    schema["properties"]["path"].update(assertion)
    with pytest.raises(ToolRestorationError) as caught:
        _bound(tmp_path, {"tools": [_tool(schema=schema)]})
    assert caught.value.code == "unsupported_tool_schema"
    assert "unknownPrivateKey" not in str(caught.value)
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "array", "items": {"type": "string"}},
        {"type": "object", "properties": {"destination": {"type": "string"}}},
        {"type": "object", "required": ["networkPayload"]},
        _schema(type="array", items={"type": "string"}, maxItems=3),
        _schema(type="integer"),
        _schema(type=["string", "null"]),
    ],
)
def test_unknown_or_nonflat_executable_formats_fail_at_bind(tmp_path, schema):
    with pytest.raises(ToolRestorationError):
        _bound(tmp_path, {"tools": [_tool(schema=schema)]})


@pytest.mark.parametrize(
    "constraints",
    [
        {"enum": ["allowed.py"]},
        {"const": "allowed.py"},
        {"maxLength": 5},
        {"minLength": 30},
        {"allOf": [{"minLength": 1}, {"const": "allowed.py"}]},
        {"anyOf": [{"const": "first.py"}, {"const": "second.py"}]},
        {"oneOf": [{"type": "string"}, {"minLength": 0}]},
    ],
)
def test_final_restored_values_must_meet_declared_schema(tmp_path, ctx, minter, vault, constraints):
    bound = _bound(tmp_path, {"tools": [_tool(schema=_schema(**constraints))]})
    provenance = TokenProvenance()
    value = "private-source.py"
    surrogate = minter.mint(ctx, "PERSON", value, provenance)
    vault.put(ctx, surrogate.token, value, surrogate.version)
    with pytest.raises(ToolRestorationError) as caught:
        _call(bound, ctx, vault, path=surrogate.token, provenance=provenance)
    assert caught.value.code == "tool_schema_violation"
    assert caught.value.outcome.restored == 1
    assert caught.value.outcome.text == ""
    assert value not in str(caught.value)


def test_schema_lengths_apply_after_restoration_not_surrogate_encoding(
    tmp_path, ctx, minter, vault
):
    bound = _bound(tmp_path, {"tools": [_tool(schema=_schema(maxLength=5))]})
    provenance = TokenProvenance()
    surrogate = minter.mint(ctx, "PERSON", "x.py", provenance)
    vault.put(ctx, surrogate.token, "x.py", surrogate.version)
    assert json.loads(_call(bound, ctx, vault, path=surrogate.token, provenance=provenance)[0]) == {
        "path": "x.py"
    }


def test_declared_numeric_and_object_limits_are_enforced(tmp_path, ctx, vault):
    schema = _schema()
    schema["properties"]["limit"] = {"type": "integer", "minimum": 1, "exclusiveMaximum": 5}
    schema["minProperties"] = 2
    schema["maxProperties"] = 2
    bound = _bound(
        tmp_path,
        {
            "tools": [
                _tool(
                    "Read",
                    schema={
                        **schema,
                        "properties": {
                            "file_path": schema["properties"]["path"],
                            "limit": schema["properties"]["limit"],
                        },
                        "required": ["file_path"],
                    },
                )
            ]
        },
    )
    for limit in [5, 10]:
        with pytest.raises(ToolRestorationError) as caught:
            bound.restore(
                ctx,
                "Read",
                json.dumps({"file_path": "x", "limit": limit}),
                TokenProvenance(),
                RestorationEngine(vault),
            )
        assert caught.value.code == "tool_schema_violation"
    result, _ = bound.restore(
        ctx,
        "Read",
        json.dumps({"file_path": "x", "limit": 3}),
        TokenProvenance(),
        RestorationEngine(vault),
    )
    assert json.loads(result)["limit"] == 3


def test_annotations_do_not_impose_unreviewed_executable_assertions(tmp_path, ctx, vault):
    schema = _schema()
    schema.update(
        {"title": "local read", "description": "annotation", "examples": [{"path": "example"}]}
    )
    schema["properties"]["path"].update({"default": "default.py", "deprecated": True})
    bound = _bound(tmp_path, {"tools": [_tool(schema=schema)]})
    assert json.loads(_call(bound, ctx, vault)[0])["path"] == "source.py"


def test_bound_schema_is_copied_from_mutable_request(tmp_path, ctx, vault):
    schema = _schema(const="safe.py")
    payload = {"tools": [_tool(schema=schema)]}
    bound = _bound(tmp_path, payload)
    schema["properties"]["path"]["const"] = "unsafe.py"
    assert json.loads(_call(bound, ctx, vault, path="safe.py")[0])["path"] == "safe.py"
    with pytest.raises(ToolRestorationError):
        _call(bound, ctx, vault, path="unsafe.py")


def test_executable_schema_depth_is_bounded(tmp_path):
    schema = _schema()
    for _ in range(20):
        schema = {"allOf": [schema]}
    with pytest.raises(ToolRestorationError):
        _bound(tmp_path, {"tools": [_tool(schema=schema)]})


def test_pinned_public_codex_apply_patch_lark_contract(tmp_path, ctx, vault):
    # Digest of codex-rs/core/assets/tools/apply_patch.lark at rust-v0.161.0
    # (979011409de0a60b52f179721948e65531d26144), independent of this gateway.
    assert hashlib.sha256(APPLY_PATCH_LARK_GRAMMAR.encode()).hexdigest() == (
        "d6367f4826ed608c424b0a308f3d6163527df63c22513d089b91863552f8bfeb"
    )
    tool = {
        "type": "custom",
        "name": "apply_patch",
        "format": {
            "type": "grammar",
            "syntax": "lark",
            "definition": APPLY_PATCH_LARK_GRAMMAR,
        },
    }
    bound = _bound(tmp_path, {"tools": [tool]})
    patch = "*** Begin Patch\n*** Update File: old.py\n*** Move to: renamed.py\n*** End Patch\n"
    result, _ = bound.restore(
        ctx, "apply_patch", patch, TokenProvenance(), RestorationEngine(vault), custom=True
    )
    assert result == patch
    tool["format"]["definition"] += "\nmalicious: /.+/\n"
    with pytest.raises(ToolRestorationError):
        _bound(tmp_path, {"tools": [tool]})


def test_official_claude_schema_dialect_and_pdf_declaration(tmp_path, ctx, vault):
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "file_path": {"type": "string"},
            "offset": {"type": "integer", "minimum": 0},
            "pages": {"type": "string"},
        },
        "required": ["file_path"],
        "additionalProperties": False,
    }
    bound = _bound(
        tmp_path, {"tools": [_tool("Read", schema=schema, protocol="messages")]}, "messages"
    )
    result, _ = bound.restore(
        ctx,
        "Read",
        json.dumps({"file_path": "source.py", "offset": 0}),
        TokenProvenance(),
        RestorationEngine(vault),
    )
    assert json.loads(result)["offset"] == 0
    # Accepting this declared optional field does not authorize PDF egress.
    with pytest.raises(ToolRestorationError):
        bound.restore(
            ctx,
            "Read",
            json.dumps({"file_path": "paper.pdf", "pages": "1"}),
            TokenProvenance(),
            RestorationEngine(vault),
        )
    schema["$schema"] = "https://json-schema.org/draft-07/schema"
    with pytest.raises(ToolRestorationError):
        _bound(tmp_path, {"tools": [_tool("Read", schema=schema, protocol="messages")]}, "messages")


def test_public_codex_exec_nested_permission_declaration(tmp_path, ctx, vault):
    schema = {
        "type": "object",
        "properties": {
            "cmd": {"type": "string"},
            "sandbox_permissions": {
                "type": "string",
                "enum": ["use_default", "require_escalated", "with_additional_permissions"],
            },
            "justification": {"type": "string"},
            "prefix_rule": {"type": "array", "items": {"type": "string"}},
            "additional_permissions": {
                "type": "object",
                "properties": {
                    "network": {
                        "type": "object",
                        "properties": {"enabled": {"type": "boolean"}},
                        "additionalProperties": False,
                    },
                    "file_system": {
                        "type": "object",
                        "properties": {
                            "read": {"type": "array", "items": {"type": "string"}},
                            "write": {"type": "array", "items": {"type": "string"}},
                        },
                        "additionalProperties": False,
                    },
                },
                "additionalProperties": False,
            },
            "environment_id": {"type": "string"},
        },
        "required": ["cmd"],
        "additionalProperties": False,
    }
    bound = _bound(tmp_path, {"tools": [_tool("exec_command", schema=schema)]})
    values = {
        "cmd": "python -m pytest -q",
        "sandbox_permissions": "require_escalated",
        "justification": "Allow running local tests?",
        "prefix_rule": ["python", "-m", "pytest"],
    }
    result, _ = bound.restore(
        ctx, "exec_command", json.dumps(values), TokenProvenance(), RestorationEngine(vault)
    )
    assert json.loads(result) == values


def test_nested_todo_schema_checks_restored_prose_and_array_bounds(tmp_path, ctx, minter, vault):
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "todos": {
                "type": "array",
                "maxItems": 1,
                "items": {
                    "type": "object",
                    "properties": {
                        "content": {"type": "string", "maxLength": 5},
                        "activeForm": {"type": "string"},
                        "status": {
                            "type": "string",
                            "enum": ["pending", "in_progress", "completed"],
                        },
                    },
                    "required": ["content", "activeForm", "status"],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["todos"],
        "additionalProperties": False,
    }
    bound = _bound(
        tmp_path, {"tools": [_tool("TodoWrite", schema=schema, protocol="messages")]}, "messages"
    )
    provenance = TokenProvenance()
    surrogate = minter.mint(ctx, "PERSON", "Alex", provenance)
    vault.put(ctx, surrogate.token, "Alex", surrogate.version)
    todo = {"content": surrogate.token, "activeForm": "Updating", "status": "pending"}
    result, _ = bound.restore(
        ctx, "TodoWrite", json.dumps({"todos": [todo]}), provenance, RestorationEngine(vault)
    )
    assert json.loads(result)["todos"][0]["content"] == "Alex"
    with pytest.raises(ToolRestorationError) as caught:
        bound.restore(
            ctx,
            "TodoWrite",
            json.dumps({"todos": [todo, todo]}),
            provenance,
            RestorationEngine(vault),
        )
    assert caught.value.code == "tool_schema_violation"
    assert caught.value.outcome.text == ""


def test_unknown_nested_permission_schema_cannot_broaden_registered_sink(tmp_path):
    schema = {
        "type": "object",
        "properties": {
            "cmd": {"type": "string"},
            "additional_permissions": {
                "type": "object",
                "properties": {
                    "network": {
                        "type": "object",
                        "properties": {"upload_destination": {"type": "string"}},
                    },
                },
            },
        },
    }
    with pytest.raises(ToolRestorationError):
        _bound(tmp_path, {"tools": [_tool("exec_command", schema=schema)]})
