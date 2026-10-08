"""Executable restoration grants access only to explicitly registered sinks."""

from __future__ import annotations

import json
import re
import shlex
import subprocess

import pytest

from gateway.domain import RequestContext
from gateway.restoration.engine import RestorationEngine
from gateway.tools import ToolRegistry, ToolRestorationError
from gateway.transformations.tokens import TokenProvenance


@pytest.fixture
def registry(tmp_path):
    return ToolRegistry(tmp_path)


def _mint(ctx, minter, vault, value, provenance, entity="PERSON"):
    surrogate = minter.mint(ctx, entity, value, provenance)
    vault.put(ctx, surrogate.token, value, surrogate.version)
    return surrogate.token


def _restore(registry, ctx, vault, name, values, provenance=None):
    return registry.restore(
        ctx,
        name,
        json.dumps(values),
        provenance if provenance is not None else TokenProvenance(),
        RestorationEngine(vault),
    )


@pytest.mark.parametrize(
    ("name", "values", "field"),
    [
        ("read_file", {"path": "VALUE/report.py"}, "path"),
        ("Read", {"file_path": "VALUE/report.py", "limit": 10}, "file_path"),
        ("write_file", {"path": "result.py", "content": "# VALUE\n"}, "content"),
        ("Write", {"file_path": "result.py", "content": 'name = "VALUE"\n'}, "content"),
        (
            "edit_file",
            {"path": "result.py", "old_string": 'name = "VALUE"', "new_string": "name = None"},
            "old_string",
        ),
        (
            "Edit",
            {"file_path": "result.py", "old_string": "# VALUE", "new_string": "# redacted"},
            "old_string",
        ),
    ],
)
def test_registered_fields_restore_exact_values(registry, ctx, minter, vault, name, values, field):
    provenance = TokenProvenance()
    value = "Ilze Bērziņa"
    token = _mint(ctx, minter, vault, value, provenance)
    original = dict(values)
    values[field] = values[field].replace("VALUE", token)
    arguments, outcome = _restore(registry, ctx, vault, name, values, provenance)
    expected = {
        key: text.replace("VALUE", value) if isinstance(text, str) else text
        for key, text in original.items()
    }
    assert json.loads(arguments) == expected
    assert outcome.restored == 1


def test_json_escaping_and_edit_matching_are_preserved(registry, ctx, minter, vault):
    provenance = TokenProvenance()
    value = 'Ilze "Bērziņa"\\folder\nnext line'
    token = _mint(ctx, minter, vault, value, provenance)
    arguments, outcome = _restore(
        registry,
        ctx,
        vault,
        "edit_file",
        {"path": "source.py", "old_text": f"# {token}", "new_text": f'person = "{token}"'},
        provenance,
    )
    assert json.loads(arguments) == {
        "path": "source.py",
        "old_text": f"# {value}",
        "new_text": f'person = "{value}"',
    }
    assert outcome.restored == 2


@pytest.mark.parametrize(
    "value",
    [
        "<PERSON:v1:" + "f" * 32 + ">",
        "<PERSON:v1:abc>",
        "<PERSON:v2:" + "a" * 32 + ">",
        "<PERSON:v1:abc",
        "<person:v1:" + "a" * 32 + ">",
        "<PERSON_1>",
        "<PERSON",
        "＜PERSON:v1:abc＞",
        "PERSON:v1:" + "a" * 32 + ">",
    ],
)
def test_unknown_and_malformed_tokens_fail_entire_call(registry, ctx, vault, value):
    with pytest.raises(ToolRestorationError) as caught:
        _restore(registry, ctx, vault, "write_file", {"path": "x.py", "content": value})
    assert value not in str(caught.value)
    assert caught.value.outcome.text == ""


def test_valid_then_forged_token_returns_no_half_restored_call(registry, ctx, minter, vault):
    provenance = TokenProvenance()
    token = _mint(ctx, minter, vault, "private@example.test", provenance, "EMAIL_ADDRESS")
    forged = "<PERSON:v1:" + "f" * 32 + ">"
    with pytest.raises(ToolRestorationError) as caught:
        _restore(
            registry,
            ctx,
            vault,
            "write_file",
            {"path": "x.py", "content": f"{token} {forged}"},
            provenance,
        )
    assert caught.value.outcome.restored == 1
    assert caught.value.outcome.total_refused == 1
    assert caught.value.outcome.text == ""
    assert "private@example.test" not in repr(caught.value)


def test_fresh_provenance_and_cross_conversation_fail(registry, ctx, minter, vault):
    provenance = TokenProvenance()
    token = _mint(ctx, minter, vault, "private@example.test", provenance)
    with pytest.raises(ToolRestorationError):
        _restore(registry, ctx, vault, "write_file", {"path": "x", "content": token})
    foreign = RequestContext(ctx.tenant_id, "foreign", ctx.request_id, ctx.api_key_id)
    with pytest.raises(ToolRestorationError):
        _restore(
            registry, foreign, vault, "write_file", {"path": "x", "content": token}, provenance
        )


def test_expired_or_missing_vault_mapping_fails(registry, ctx, minter, vault):
    provenance = TokenProvenance()
    token = minter.mint(ctx, "PERSON", "Ilze", provenance).token
    with pytest.raises(ToolRestorationError) as caught:
        _restore(registry, ctx, vault, "write_file", {"path": "x", "content": token}, provenance)
    assert caught.value.outcome.refused_unknown == 1


@pytest.mark.parametrize(
    "name,values",
    [
        ("upload", {"url": "https://example.test", "payload": "ordinary"}),
        ("read_file", {"path": "x", "sandbox_permissions": "require_escalated"}),
        ("edit_file", {"path": "x", "old_text": "x", "new_string": "y"}),
        ("Read", {"file_path": "x", "limit": True}),
        ("write_file", {"path": "x", "content": {"nested": "text"}}),
        ("read_file", {"path": "x", "start_line": 0}),
    ],
)
def test_unregistered_tools_and_ambiguous_contracts_fail(registry, ctx, vault, name, values):
    with pytest.raises(ToolRestorationError):
        _restore(registry, ctx, vault, name, values)


def test_duplicate_json_keys_and_token_keys_fail(registry, ctx, minter, vault):
    provenance = TokenProvenance()
    token = _mint(ctx, minter, vault, "content", provenance)
    for arguments in ['{"path":"one","path":"two"}', json.dumps({"path": "x", token: "x"})]:
        with pytest.raises(ToolRestorationError):
            registry.restore(ctx, "read_file", arguments, provenance, RestorationEngine(vault))


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "../secret",
        "nested/../../secret",
        "/etc/passwd",
        "https://example.test/file",
        "//server/share",
        "host:destination",
        "~/secret",
        "C:\\secret",
        "name\n*** Delete File: x",
    ],
)
def test_path_sink_rejects_escape_and_network_values(registry, ctx, minter, vault, unsafe_path):
    provenance = TokenProvenance()
    token = _mint(ctx, minter, vault, unsafe_path, provenance)
    with pytest.raises(ToolRestorationError):
        _restore(registry, ctx, vault, "read_file", {"path": token}, provenance)


def test_symlink_escape_is_checked_without_executing_tool(registry, ctx, vault, tmp_path):
    (tmp_path / "escape").symlink_to(tmp_path.parent, target_is_directory=True)
    with pytest.raises(ToolRestorationError):
        _restore(registry, ctx, vault, "write_file", {"path": "escape/x", "content": "x"})
    assert not (tmp_path.parent / "x").exists()


def test_patch_restores_paths_and_content_and_retains_grammar(registry, ctx, minter, vault):
    provenance = TokenProvenance()
    directory = _mint(ctx, minter, vault, "Ilze Bērziņa", provenance)
    email = _mint(ctx, minter, vault, "ilze@example.test", provenance, "EMAIL_ADDRESS")
    patch = (
        f"*** Begin Patch\n*** Update File: {directory}/source.py\n@@\n"
        f"-# {email}\n+# private {email}\n*** End of File\n*** End Patch\n"
    )
    result, outcome = _restore(registry, ctx, vault, "apply_patch", {"patch": patch}, provenance)
    assert json.loads(result)["patch"] == patch.replace(directory, "Ilze Bērziņa").replace(
        email, "ilze@example.test"
    )
    assert outcome.restored == 3
    custom_result, _ = registry.restore(
        ctx, "apply_patch", patch, provenance, RestorationEngine(vault), custom=True
    )
    assert custom_result == json.loads(result)["patch"]


@pytest.mark.parametrize(
    "patch",
    [
        "--- old\n+++ new\n@@\n-x\n+y\n",
        "*** Begin Patch\n*** Update File: x\n@@\n*** End Patch",
        "*** Begin Patch\n*** Add File: x\nraw content\n*** End Patch",
        "*** Begin Patch\n*** Delete File: x\nextra\n*** End Patch",
        "*** Begin Patch\n*** Add File: x\n+x\n*** Add File: ./x\n+y\n*** End Patch",
    ],
)
def test_patch_ambiguous_or_malformed_grammar_fails(registry, ctx, vault, patch):
    with pytest.raises(ToolRestorationError):
        _restore(registry, ctx, vault, "apply_patch", {"patch": patch})


def test_patch_cannot_inject_actions_via_restored_content(registry, ctx, minter, vault):
    provenance = TokenProvenance()
    token = _mint(ctx, minter, vault, "text\n*** Delete File: source.py", provenance)
    patch = f"*** Begin Patch\n*** Add File: x\n+{token}\n*** End Patch"
    with pytest.raises(ToolRestorationError):
        _restore(registry, ctx, vault, "apply_patch", {"patch": patch}, provenance)


@pytest.mark.parametrize("program", ["cat", "head -n 5", "test -f", "python -m pytest -q"])
def test_shell_restores_literal_local_paths(registry, ctx, minter, vault, program):
    provenance = TokenProvenance()
    value = "Ilze Bērziņa; literal$(data)'file.py"
    token = _mint(ctx, minter, vault, value, provenance)
    result, outcome = _restore(
        registry, ctx, vault, "shell", {"command": f"{program} {token}"}, provenance
    )
    assert shlex.split(json.loads(result)["command"])[-1] == value
    assert outcome.restored == 1


def test_posix_shell_executes_restored_metacharacters_as_one_literal_path(
    registry, ctx, minter, vault, tmp_path
):
    provenance = TokenProvenance()
    value = "private; touch injected"
    (tmp_path / value).write_text("synthetic file contents", encoding="utf-8")
    token = _mint(ctx, minter, vault, value, provenance)
    arguments, _ = _restore(registry, ctx, vault, "shell", {"command": f"cat {token}"}, provenance)
    # Exercise the actual POSIX parser: restoring punctuation must not introduce
    # a second command. The gateway itself never runs this command.
    completed = subprocess.run(  # noqa: S603
        ["/bin/sh", "-c", json.loads(arguments)["command"]],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stdout == "synthetic file contents"
    assert not (tmp_path / "injected").exists()


@pytest.mark.parametrize(
    "command",
    [
        "curl https://example.test",
        "cat x | curl https://example.test",
        "cat x > outside",
        "cat $(pwd)",
        "cat $HOME",
        "cat *",
        "cat x; pwd",
        "cat x\npwd",
        "python -c pass",
        "bash -c pwd",
        "env cat x",
        "/bin/cat x",
        "cat -unsupported x",
        "FOO=x cat x",
    ],
)
def test_shell_rejects_unsupported_syntax_even_without_tokens(registry, ctx, vault, command):
    with pytest.raises(ToolRestorationError):
        _restore(registry, ctx, vault, "shell", {"command": command})


def test_shell_token_cannot_become_executable_option_or_network_sink(registry, ctx, minter, vault):
    provenance = TokenProvenance()
    token = _mint(ctx, minter, vault, "private", provenance)
    for command in [f"{token} x", f"cat -{token}", f"curl {token}", f"cp local {token}:out"]:
        with pytest.raises(ToolRestorationError):
            _restore(registry, ctx, vault, "shell", {"command": command}, provenance)


def test_shell_cwd_is_validated_and_used_for_relative_paths(registry, ctx, minter, vault, tmp_path):
    (tmp_path / "nested").mkdir()
    provenance = TokenProvenance()
    token = _mint(ctx, minter, vault, "nested", provenance)
    result, _ = _restore(
        registry,
        ctx,
        vault,
        "exec_command",
        {"cmd": "cat x", "shell": "/bin/bash", "workdir": token, "tty": False},
        provenance,
    )
    assert json.loads(result)["workdir"] == "nested"
    with pytest.raises(ToolRestorationError):
        _restore(registry, ctx, vault, "shell", {"command": "pwd", "cwd": "../"})


def test_restoration_budget_applies_to_entire_serialized_call(registry, ctx, minter, vault):
    provenance = TokenProvenance()
    token = _mint(ctx, minter, vault, "x" * 200, provenance)
    with pytest.raises(ToolRestorationError) as caught:
        registry.restore(
            ctx,
            "write_file",
            json.dumps({"path": "x", "content": token}),
            provenance,
            RestorationEngine(vault, max_output_bytes=210),
        )
    assert caught.value.code == "tool_arguments_too_large"


def test_tokens_are_never_restored_in_control_fields(registry, ctx, minter, vault):
    provenance = TokenProvenance()
    token = _mint(ctx, minter, vault, "bash", provenance)
    with pytest.raises(ToolRestorationError):
        _restore(registry, ctx, vault, "shell", {"command": "pwd", "shell": token}, provenance)
    with pytest.raises(ToolRestorationError):
        _restore(registry, ctx, vault, token, {"path": "x"}, provenance)


def test_public_exec_permission_hints_preserve_client_approval(registry, ctx, vault):
    values = {
        "cmd": "cat source.py",
        "sandbox_permissions": "require_escalated",
        "justification": "Allow reading this local file?",
        "prefix_rule": ["cat"],
    }
    result, outcome = _restore(registry, ctx, vault, "exec_command", values)
    assert json.loads(result) == values
    assert outcome.restored == 0


def test_scoped_additional_permissions_are_preserved_without_network(
    registry, ctx, vault, tmp_path
):
    permissions = {
        "network": {"enabled": False},
        "file_system": {"read": [str(tmp_path / "source.py")]},
    }
    result, _ = _restore(
        registry,
        ctx,
        vault,
        "exec_command",
        {
            "cmd": "cat source.py",
            "sandbox_permissions": "with_additional_permissions",
            "additional_permissions": permissions,
        },
    )
    assert json.loads(result)["additional_permissions"] == permissions


@pytest.mark.parametrize(
    "controls",
    [
        {
            "sandbox_permissions": "with_additional_permissions",
            "additional_permissions": {"network": {"enabled": True}},
        },
        {
            "sandbox_permissions": "with_additional_permissions",
            "additional_permissions": {"file_system": {"read": ["/etc/passwd"]}},
        },
        {"sandbox_permissions": "require_escalated", "prefix_rule": ["curl"]},
        {"sandbox_permissions": "use_default", "prefix_rule": ["cat"]},
        {"sandbox_permissions": "with_additional_permissions"},
        {"environment_id": "unbound-client-environment"},
    ],
)
def test_exec_control_hints_cannot_grant_unreviewed_access(registry, ctx, vault, controls):
    with pytest.raises(ToolRestorationError):
        _restore(registry, ctx, vault, "exec_command", {"cmd": "cat source.py", **controls})


def test_exec_control_values_never_restore_sensitive_tokens(registry, ctx, minter, vault):
    provenance = TokenProvenance()
    token = _mint(ctx, minter, vault, "cat", provenance)
    for controls in [
        {"sandbox_permissions": token},
        {"sandbox_permissions": "require_escalated", "prefix_rule": [token]},
        {"sandbox_permissions": "require_escalated", "justification": token},
    ]:
        with pytest.raises(ToolRestorationError) as caught:
            _restore(
                registry,
                ctx,
                vault,
                "exec_command",
                {"cmd": "cat source.py", **controls},
                provenance,
            )
        assert caught.value.outcome.restored == 0


def test_public_bash_background_flag_stays_client_local(registry, ctx, vault):
    values = {
        "command": "python -m pytest -q",
        "run_in_background": True,
        "dangerouslyDisableSandbox": False,
    }
    result, _ = _restore(registry, ctx, vault, "Bash", values)
    assert json.loads(result) == values
    with pytest.raises(ToolRestorationError):
        _restore(registry, ctx, vault, "Bash", {**values, "dangerouslyDisableSandbox": True})


@pytest.mark.parametrize("chars", ["", "\x03"])
def test_write_stdin_allows_only_polling_or_interrupt(registry, ctx, vault, chars):
    values = {"session_id": 123, "chars": chars, "yield_time_ms": 0, "max_output_tokens": 0}
    result, outcome = _restore(registry, ctx, vault, "write_stdin", values)
    assert json.loads(result) == values
    assert outcome.restored == 0


@pytest.mark.parametrize(
    "chars", ["print('execute')\n", "secret\n", "\n", "\x04", "<PERSON:v1:abc"]
)
def test_write_stdin_does_not_restore_or_forward_interactive_commands(registry, ctx, vault, chars):
    with pytest.raises(ToolRestorationError):
        _restore(registry, ctx, vault, "write_stdin", {"session_id": 123, "chars": chars})


def test_write_stdin_refuses_even_minted_surrogates(registry, ctx, minter, vault):
    provenance = TokenProvenance()
    token = _mint(ctx, minter, vault, "private", provenance)
    with pytest.raises(ToolRestorationError) as caught:
        _restore(
            registry, ctx, vault, "write_stdin", {"session_id": 123, "chars": token}, provenance
        )
    assert caught.value.outcome.restored == 0


def test_grep_restores_sensitive_values_as_literal_regex(registry, ctx, minter, vault):
    provenance = TokenProvenance()
    value = "private.name+(x)@example.test"
    token = _mint(ctx, minter, vault, value, provenance, "EMAIL_ADDRESS")
    controls = {
        "output_mode": "content",
        "-n": True,
        "-i": False,
        "-o": True,
        "-A": 2,
        "context": 3,
        "offset": 0,
        "head_limit": 10,
        "multiline": False,
        "type": "py",
    }
    result, outcome = _restore(
        registry, ctx, vault, "Grep", {"pattern": f"^{token}$", "path": ".", **controls}, provenance
    )
    restored = json.loads(result)
    assert re.fullmatch(restored["pattern"], value)
    assert not re.fullmatch(restored["pattern"], "privateXname+(x)@example.test")
    assert {key: restored[key] for key in controls} == controls
    assert outcome.restored == 1


def test_glob_restores_private_local_directory(registry, ctx, minter, vault):
    provenance = TokenProvenance()
    token = _mint(ctx, minter, vault, "Ilze Bērziņa", provenance)
    result, outcome = _restore(
        registry,
        ctx,
        vault,
        "Glob",
        {"pattern": f"{token}/**/*.{{py,txt}}", "path": "."},
        provenance,
    )
    assert json.loads(result)["pattern"] == "Ilze Bērziņa/**/*.{{py,txt}}".replace(
        "{{", "{"
    ).replace("}}", "}")
    assert outcome.restored == 1


@pytest.mark.parametrize(
    "pattern",
    [
        "../*",
        "/etc/*",
        "{../,inside}/*",
        "~/private/*",
        "!excluded/*",
        "{one}/file",
        "unclosed{pattern",
    ],
)
def test_glob_pattern_cannot_change_search_root(registry, ctx, vault, pattern):
    with pytest.raises(ToolRestorationError):
        _restore(registry, ctx, vault, "Glob", {"pattern": pattern})


def test_restored_values_cannot_inject_glob_wildcards(registry, ctx, minter, vault):
    provenance = TokenProvenance()
    token = _mint(ctx, minter, vault, "private*", provenance)
    with pytest.raises(ToolRestorationError):
        _restore(registry, ctx, vault, "Glob", {"pattern": f"{token}/**"}, provenance)


@pytest.mark.parametrize(
    "command",
    [
        "rg -n 'TODO.*fix' .",
        "rg --files -g '*.py' .",
        "grep -n 'TODO' source.py",
        "find . -maxdepth 3 -type f -name '*.py' -print",
    ],
)
def test_public_local_shell_search_subset(registry, ctx, vault, command):
    result, _ = _restore(registry, ctx, vault, "exec_command", {"cmd": command})
    assert shlex.split(json.loads(result)["cmd"]) == shlex.split(command)


def test_shell_rg_restoration_cannot_inject_regex_or_shell_syntax(registry, ctx, minter, vault):
    provenance = TokenProvenance()
    value = "private.*; touch injected"
    token = _mint(ctx, minter, vault, value, provenance)
    result, _ = _restore(
        registry, ctx, vault, "exec_command", {"cmd": f"rg -n '^{token}$' ."}, provenance
    )
    argv = shlex.split(json.loads(result)["cmd"])
    assert argv == ["rg", "-n", "^" + re.escape(value) + "$", "."]
    assert re.fullmatch(argv[2], value)


def test_shell_fixed_string_search_restores_exact_literal(registry, ctx, minter, vault):
    provenance = TokenProvenance()
    value = "private.*"
    token = _mint(ctx, minter, vault, value, provenance)
    result, _ = _restore(
        registry, ctx, vault, "exec_command", {"cmd": f"rg -F -e '{token}' ."}, provenance
    )
    assert shlex.split(json.loads(result)["cmd"])[3] == value


@pytest.mark.parametrize(
    "command",
    [
        "find . -exec curl example.test",
        "find . -delete",
        "find . -fprint output",
        "rg --pre curl secret .",
        "rg --type-add custom secret .",
        "rg --follow secret .",
        "rg -n 'TODO' /etc",
        "rg --files --glob '{../,inside}/*' .",
        'cat "a\\"" ; touch injected ""',
    ],
)
def test_shell_search_forbids_external_programs_and_path_escape(registry, ctx, vault, command):
    with pytest.raises(ToolRestorationError):
        _restore(registry, ctx, vault, "exec_command", {"cmd": command})


def test_todo_content_restores_without_changing_status(registry, ctx, minter, vault):
    provenance = TokenProvenance()
    token = _mint(ctx, minter, vault, "Ilze Bērziņa", provenance)
    values = {
        "todos": [
            {
                "content": f"Update {token} source",
                "activeForm": f"Updating {token} source",
                "status": "in_progress",
            }
        ]
    }
    result, outcome = _restore(registry, ctx, vault, "TodoWrite", values, provenance)
    assert json.loads(result) == {
        "todos": [
            {
                "content": "Update Ilze Bērziņa source",
                "activeForm": "Updating Ilze Bērziņa source",
                "status": "in_progress",
            }
        ]
    }
    assert outcome.restored == 2


@pytest.mark.parametrize(
    "todo",
    [
        {"content": "step", "status": "pending"},
        {"content": "step", "activeForm": "Doing", "status": "unknown"},
        {
            "content": "step",
            "activeForm": "Doing",
            "status": "pending",
            "destination": "https://example.test",
        },
    ],
)
def test_todos_are_an_exact_registered_nested_contract(registry, ctx, vault, todo):
    with pytest.raises(ToolRestorationError):
        _restore(registry, ctx, vault, "TodoWrite", {"todos": [todo]})
