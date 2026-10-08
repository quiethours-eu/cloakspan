"""Prevent local public-client evidence from qualifying an unverified client."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from gateway.audit.events import AuditEvent
from scripts import public_client_check as harness

SURROGATE = "<EMAIL_ADDRESS:v1:0123456789abcdef0123456789abcdef>"


def _codex_test_event():
    return {
        "type": "item.completed",
        "item": {
            "id": "item_test",
            "type": "command_execution",
            "command": "/bin/bash -c 'python -m pytest -q'",
            "aggregated_output": ". [100%]\n1 passed in 0.02s\n",
            "exit_code": 0,
            "status": "completed",
        },
    }


def _claude_test_events():
    return [
        {
            "type": "assistant",
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "bash_test",
                        "name": "Bash",
                        "input": {"command": "python -m pytest -q"},
                    }
                ],
            },
        },
        {
            "type": "user",
            "message": {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "bash_test",
                        "content": ". [100%]\n1 passed in 0.02s\n",
                        "is_error": False,
                    }
                ],
            },
        },
    ]


@pytest.mark.parametrize(
    ("client", "stdout", "expected"),
    [
        ("codex", "codex-cli 0.161.0\n", "0.161.0"),
        ("claude", "2.1.293 (Claude Code)\n", "2.1.293"),
    ],
)
def test_version_requires_the_pinned_public_product(client, stdout, expected):
    assert harness._validate_version(client, stdout) == expected


@pytest.mark.parametrize(
    ("client", "stdout"),
    [
        ("codex", "codex-cli 0.161.00"),
        ("codex", "codex-cli 0.161.0-dev"),
        ("codex", "codex-cli 0.161.0+build"),
        ("codex", "another-cli 0.161.0"),
        ("codex", "codex-cli 0.162.0\ncompatible with 0.161.0"),
        ("claude", "2.1.2930 (Claude Code)"),
        ("claude", "2.1.293-dev (Claude Code)"),
        ("claude", "2.1.293 (Another Product)"),
        ("claude", "2.1.293"),
        ("claude", "2.1.294 (Claude Code)\npreviously 2.1.293 (Claude Code)"),
    ],
)
def test_version_substring_or_compatibility_claim_cannot_qualify(client, stdout):
    with pytest.raises(ValueError, match="pinned public version"):
        harness._validate_version(client, stdout)


@pytest.mark.parametrize("client", ["codex", "claude"])
def test_completion_requires_own_native_success_event(client):
    codex = [{"type": "turn.completed", "usage": {"input_tokens": 1}}]
    claude = [{"type": "result", "subtype": "success", "is_error": False}]
    own, foreign = (codex, claude) if client == "codex" else (claude, codex)
    assert harness._client_completion(client, own)
    assert not harness._client_completion(client, foreign)
    assert not harness._client_completion(client, [])
    assert not harness._client_completion(
        client, [{"type": "assistant", "message": {"content": "completed successfully"}}]
    )


@pytest.mark.parametrize("failure", [{"type": "turn.failed"}, {"type": "error"}])
def test_codex_success_event_cannot_mask_a_failed_turn(failure):
    assert not harness._client_completion("codex", [{"type": "turn.completed"}, failure])


@pytest.mark.parametrize(
    "failure",
    [
        {"type": "result", "subtype": "error_during_execution", "is_error": True},
        {"type": "result", "subtype": "success", "is_error": True},
    ],
)
def test_claude_success_event_cannot_mask_a_failed_result(failure):
    success = {"type": "result", "subtype": "success", "is_error": False}
    assert not harness._client_completion("claude", [success, failure])


def test_test_execution_requires_native_completed_command_and_matching_result():
    codex, claude = [_codex_test_event()], _claude_test_events()
    assert harness._test_execution_seen("codex", codex)
    assert harness._test_execution_seen("claude", claude)
    assert not harness._test_execution_seen("codex", claude)
    assert not harness._test_execution_seen("claude", codex)
    claimed = [{"type": "assistant", "message": "python -m pytest -q: 1 passed"}]
    assert not harness._test_execution_seen("codex", claimed)
    assert not harness._test_execution_seen("claude", claimed)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("command", "echo 'python -m pytest -q'; echo '1 passed'"),
        ("command", "cat pytest-output.txt"),
        ("exit_code", 1),
        ("exit_code", None),
        ("exit_code", False),
        ("aggregated_output", "1 failed in 0.02s"),
    ],
)
def test_codex_unexecuted_or_failed_test_cannot_qualify(field, value):
    event = _codex_test_event()
    event["item"][field] = value
    assert not harness._test_execution_seen("codex", [event])


def test_codex_started_command_with_pass_text_cannot_qualify():
    event = _codex_test_event()
    event["type"] = "item.started"
    assert not harness._test_execution_seen("codex", [event])


@pytest.mark.parametrize(
    ("block_index", "field", "value"),
    [
        (0, "name", "Read"),
        (0, "id", ""),
        (0, "input", {"command": "echo 'python -m pytest -q'; echo '1 passed'"}),
        (1, "tool_use_id", "unrelated_test"),
        (1, "tool_use_id", None),
        (1, "is_error", True),
        (1, "content", "1 failed in 0.02s"),
    ],
)
def test_claude_unmatched_or_failed_tool_result_cannot_qualify(block_index, field, value):
    events = _claude_test_events()
    events[block_index]["message"]["content"][0][field] = value
    assert not harness._test_execution_seen("claude", events)


def test_claude_tool_result_must_follow_the_actual_test_call():
    call, result = _claude_test_events()
    assert not harness._test_execution_seen("claude", [result, call])
    assert not harness._test_execution_seen("claude", [result])
    assert not harness._test_execution_seen("claude", [call])


@pytest.mark.parametrize("nested_index", [0, 1])
def test_nested_claude_execution_cannot_qualify_the_selected_client(nested_index):
    events = _claude_test_events()
    events[nested_index]["parent_tool_use_id"] = "foreign_subagent_parent"
    assert not harness._test_execution_seen("claude", events)


def test_nested_claude_terminal_result_and_boundary_do_not_mask_parent_evidence():
    parent = {"type": "result", "subtype": "success", "is_error": False}
    nested = {**parent, "parent_tool_use_id": "foreign_subagent_parent"}
    assert not harness._client_completion("claude", [nested])
    nested_failure = {**nested, "subtype": "error_during_execution", "is_error": True}
    assert harness._client_completion("claude", [parent, nested_failure])
    boundary = {
        "type": "system",
        "subtype": "compact_boundary",
        "parent_tool_use_id": "foreign_subagent_parent",
    }
    assert not harness._native_compaction_seen("claude", [boundary])


def test_compaction_requires_the_clients_native_completed_boundary():
    codex = [{"type": "item.completed", "item": {"type": "context_compaction"}}]
    claude = [{"type": "system", "subtype": "compact_boundary"}]
    assert harness._native_compaction_seen("codex", codex)
    assert harness._native_compaction_seen("claude", claude)
    assert not harness._native_compaction_seen("codex", claude)
    assert not harness._native_compaction_seen("claude", codex)
    assert not harness._native_compaction_seen(
        "codex", [{"type": "item.started", "item": {"type": "context_compaction"}}]
    )
    claimed = [{"type": "assistant", "message": "Automatic context compaction completed"}]
    assert not harness._native_compaction_seen("codex", claimed)
    assert not harness._native_compaction_seen("claude", claimed)


def test_json_stdout_scopes_native_events_without_prose_claims():
    stdout = "compaction complete, 1 passed\n" + json.dumps(_codex_test_event()) + "\n"
    events = harness._read_events(stdout)
    assert harness._test_execution_seen("codex", events)
    assert not harness._native_compaction_seen("codex", events)
    assert not harness._client_completion("codex", events)


def _completion_events(client):
    if client == "codex":
        return [
            {"type": "item.completed", "item": {"type": "agent_message", "text": harness.CANARY}},
            {"type": "turn.completed"},
        ]
    return [{"type": "result", "subtype": "success", "is_error": False, "result": harness.CANARY}]


def _long_session_events(client):
    if client == "codex":
        read = _codex_test_event()
        read["item"].update(
            command="/bin/bash -c 'cat synthetic_notes.txt'",
            aggregated_output=harness.NOTES,
        )
        boundary = {"type": "item.completed", "item": {"type": "context_compaction"}}
        return [read, boundary, *_completion_events(client)]
    read, result = _claude_test_events()
    read["message"]["content"][0].update(
        name="Read", input={"file_path": "/workspace/synthetic_notes.txt"}
    )
    result["message"]["content"][0]["content"] = harness.NOTES
    boundary = {"type": "system", "subtype": "compact_boundary"}
    return [read, result, boundary, *_completion_events(client)]


def _write_events(root, filename, events):
    (root / filename).write_text("".join(json.dumps(event) + "\n" for event in events))


def _native_payload(client, text):
    if client == "codex":
        return {
            "model": "gpt-5.1",
            "input": [{"role": "user", "content": [{"type": "input_text", "text": text}]}],
            "prompt_cache_key": "cache_" + "1" * 64,
        }
    return {
        "model": "claude-sonnet-4-6",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": [{"type": "text", "text": text}]}],
    }


def _set_payload_text(payload, text):
    history = payload["input" if "input" in payload else "messages"]
    history[0]["content"][0]["text"] = text


def _summary_text(client, *, notes=True):
    directive = (
        "CONTEXT CHECKPOINT COMPACTION"
        if client == "codex"
        else "Your task is to create a detailed summary"
    )
    history = harness.NOTES.replace(harness.CANARY, SURROGATE) if notes else "Owner " + SURROGATE
    return directive + ":\n" + history


def _evidence(root: Path, *, compact=False, clients=("codex", "claude")):
    """Independent per-client native transcripts and inspected egress records."""
    evidence = {
        "root": root,
        "clients": list(clients),
        "mode": "gateway",
        "workflow": True,
        "compact": compact,
        "runs": [],
        "requests": [],
        "provider_requests": {"responses": [], "messages": []},
        "audit": [],
    }
    phases = ["initial", "resume"]
    if compact:
        phases += ["long-session", "post-compaction-resume"]
    for client in clients:
        workspace = root / "repos" / client
        workspace.mkdir(parents=True)
        (workspace / "sample_math.py").write_text(
            harness.SOURCE.replace("return a - b", "return a + b")
        )
        protocol = "responses" if client == "codex" else "messages"
        for phase in phases:
            request_id = "req_" + client + "_" + phase
            request_start = len(evidence["requests"])
            provider_start = len(evidence["provider_requests"][protocol])
            filename = client + "-" + phase + "-stdout.jsonl"
            if phase == "initial":
                test = [_codex_test_event()] if client == "codex" else _claude_test_events()
                events = test + _completion_events(client)
            elif phase == "long-session":
                events = _long_session_events(client)
            else:
                events = _completion_events(client)
            _write_events(root, filename, events)
            text = "Follow up for " + SURROGATE
            if phase == "long-session":
                text = _summary_text(client)
            elif phase == "post-compaction-resume":
                text = harness.SUMMARY_MARKER + ": Owner " + SURROGATE
            body = _native_payload(client, text)
            evidence["provider_requests"][protocol].append(body)
            incoming = _native_payload(client, harness.CANARY)
            incoming.update(
                metadata={"user_id": "synthetic-private-user-" + client},
                client_metadata={"session_id": "synthetic-private-session-" + client},
                prompt_cache_key="synthetic-private-cache-" + client,
            )
            evidence["requests"].append(
                {
                    "method": "POST",
                    "path": "/v1/" + protocol,
                    "headers": {
                        "session-id"
                        if client == "codex"
                        else "x-claude-code-session-id": "synthetic-session-" + client
                    },
                    "body": incoming,
                    "status": 200,
                    "request_id": request_id,
                }
            )
            evidence["audit"].append(
                AuditEvent(
                    schema_version=3,
                    request_id=request_id,
                    tenant_id="public-synthetic-tenant",
                    conversation_id="agent_" + client,
                    api_key_id="public-client-key",
                    application="default",
                    timestamp=0.0,
                    model_requested="client-model",
                    destination="external",
                    provider="mock",
                    decision="transform",
                    rule_name="pseudonymise-personal-data",
                    policy_version="community-default-v1",
                    entity_counts={"EMAIL_ADDRESS": 1},
                    entities_transformed=1,
                ).to_dict()
            )
            evidence["runs"].append(
                {
                    "client": client,
                    "phase": phase,
                    "returncode": 0,
                    "timed_out": False,
                    "stdout_file": filename,
                    "resume": phase != "initial",
                    "request_start": request_start,
                    "request_end": request_start + 1,
                    "provider_start": provider_start,
                    "provider_end": provider_start + 1,
                }
            )
    return evidence


def _run(evidence, client, phase):
    return next(
        run for run in evidence["runs"] if run["client"] == client and run["phase"] == phase
    )


def _replace_phase_events(evidence, client, phase, events):
    _write_events(evidence["root"], _run(evidence, client, phase)["stdout_file"], events)


def test_report_qualifies_independent_initial_and_resumed_workflows(tmp_path):
    evidence = _evidence(tmp_path)
    report = harness._build_report(**evidence)
    assert report["success"]
    assert report["privacy_checked"]
    assert not report["automatic_compaction_qualified"]
    assert set(report["outcomes"]) == {"codex", "claude"}
    assert all(run["successful"] and run["provider_request_count"] == 1 for run in report["runs"])
    # Raw private recordings and restored client output intentionally contain the synthetic canary.
    assert harness.CANARY in json.dumps(evidence["requests"])
    assert harness.CANARY in (tmp_path / "claude-resume-stdout.jsonl").read_text()


@pytest.mark.parametrize("client", ["codex", "claude"])
def test_one_clients_test_pass_cannot_qualify_the_other(tmp_path, client):
    evidence = _evidence(tmp_path)
    _replace_phase_events(evidence, client, "initial", _completion_events(client))
    # A request log or another phase containing the marker is not execution evidence.
    evidence["requests"][0]["body"]["claim"] = "python -m pytest -q: 1 passed"
    test = [_codex_test_event()] if client == "codex" else _claude_test_events()
    _replace_phase_events(evidence, client, "resume", test + _completion_events(client))
    report = harness._build_report(**evidence)
    other = "claude" if client == "codex" else "codex"
    assert report["outcomes"][other]["test_execution_seen"]
    assert not report["outcomes"][client]["test_execution_seen"]
    assert not report["success"]


@pytest.mark.parametrize("client", ["codex", "claude"])
@pytest.mark.parametrize("phase", ["initial", "resume"])
@pytest.mark.parametrize("failure", ["missing", "exit", "timeout", "native_result", "upstream"])
def test_each_client_phase_needs_successful_native_result_and_own_egress(
    tmp_path, client, phase, failure
):
    evidence = _evidence(tmp_path)
    run = _run(evidence, client, phase)
    if failure == "missing":
        evidence["runs"].remove(run)
    elif failure == "exit":
        run["returncode"] = 1
    elif failure == "timeout":
        run["timed_out"] = True
    elif failure == "native_result":
        run["completed"] = (
            True  # The report must re-read native evidence, not trust a claimed flag.
        )
        _replace_phase_events(evidence, client, phase, [{"type": "assistant", "text": "success"}])
    else:
        run["provider_end"] = run["provider_start"]
    report = harness._build_report(**evidence)
    assert not report["outcomes"][client]["runs_successful"]
    assert not report["success"]


def test_provider_request_for_other_client_cannot_mask_absent_own_request(tmp_path):
    evidence = _evidence(tmp_path)
    evidence["provider_requests"]["messages"] = []
    report = harness._build_report(**evidence)
    assert report["outcomes"]["codex"]["runs_successful"]
    assert not report["outcomes"]["claude"]["runs_successful"]
    assert not report["privacy_checked"]
    assert not report["success"]


def test_failed_native_response_cannot_be_hidden_by_upstream_success(tmp_path):
    evidence = _evidence(tmp_path)
    evidence["requests"][-1]["status"] = 400
    report = harness._build_report(**evidence)
    assert not report["outcomes"]["claude"]["runs_successful"]
    assert not report["success"]


def test_session_scope_change_cannot_qualify_resumed_workflow(tmp_path):
    evidence = _evidence(tmp_path)
    evidence["requests"][-1]["headers"]["x-claude-code-session-id"] = "different-session"
    report = harness._build_report(**evidence)
    assert not report["outcomes"]["claude"]["stable_session_scope"]
    assert not report["success"]


@pytest.mark.parametrize(
    "failure",
    ["upstream_canary", "audit_canary", "raw_audit", "audit_error", "empty_audit", "no_tokens"],
)
def test_report_privacy_requires_inspected_egress_and_metadata_only_product_audit(
    tmp_path, failure
):
    evidence = _evidence(tmp_path)
    if failure == "upstream_canary":
        _set_payload_text(evidence["provider_requests"]["messages"][0], harness.CANARY)
    elif failure == "audit_canary":
        evidence["audit"][0]["prompt"] = harness.CANARY
    elif failure == "raw_audit":
        evidence["audit"][0]["raw_content_logged"] = True
    elif failure == "audit_error":
        evidence["audit"][0]["error"] = "request_rejected"
    elif failure == "empty_audit":
        evidence["audit"] = []
    else:
        for payload in evidence["provider_requests"]["messages"]:
            _set_payload_text(payload, "No transformed canary")
    report = harness._build_report(**evidence)
    assert not report["privacy_checked"]
    assert not report["success"]


def test_other_clients_audit_events_cannot_mask_missing_product_audit(tmp_path):
    evidence = _evidence(tmp_path)
    evidence["audit"] = [event for event in evidence["audit"] if "codex" in event["request_id"]]
    report = harness._build_report(**evidence)
    assert not report["privacy_checked"]
    assert not report["success"]


@pytest.mark.parametrize("field", ["metadata", "client_metadata", "prompt_cache_key"])
def test_raw_client_metadata_identifiers_cannot_qualify_egress_privacy(tmp_path, field):
    evidence = _evidence(tmp_path)
    raw_identifier = deepcopy(evidence["requests"][0]["body"][field])
    evidence["provider_requests"]["responses"][0][field] = raw_identifier
    report = harness._build_report(**evidence)
    assert not report["privacy_checked"]
    assert not report["success"]


@pytest.mark.parametrize("identity", ["user_id", "session_id", "json_user_id"])
def test_original_client_identifiers_cannot_escape_under_other_structural_fields(
    tmp_path, identity
):
    evidence = _evidence(tmp_path)
    record = evidence["requests"][-1]
    if identity == "user_id":
        raw = record["body"]["metadata"]["user_id"]
    elif identity == "session_id":
        raw = record["headers"]["x-claude-code-session-id"]
    else:
        raw = "synthetic-private-account"
        record["body"]["metadata"]["user_id"] = json.dumps(
            {"account_uuid": raw, "session_id": "synthetic-private-json-session"}
        )
    evidence["provider_requests"]["messages"][0]["user"] = raw
    report = harness._build_report(**evidence)
    assert not report["privacy_checked"]
    assert not report["success"]


def test_visible_transcript_reference_remains_inspectable_after_metadata_consumption(tmp_path):
    evidence = _evidence(tmp_path)
    raw_session = evidence["requests"][-1]["headers"]["x-claude-code-session-id"]
    text = "Owner " + SURROGATE + "; visible transcript /tmp/sessions/" + raw_session + ".jsonl"
    _set_payload_text(evidence["provider_requests"]["messages"][-1], text)
    report = harness._build_report(**evidence)
    assert report["privacy_checked"]
    assert report["success"]
    assert evidence["provider_requests"]["responses"][0]["prompt_cache_key"].startswith("cache_")


def test_empty_execution_evidence_cannot_make_absence_only_privacy_claim(tmp_path):
    evidence = _evidence(tmp_path)
    evidence["runs"] = []
    evidence["requests"] = []
    evidence["provider_requests"] = {}
    evidence["audit"] = []
    report = harness._build_report(**evidence)
    assert not report["privacy_checked"]
    assert not report["success"]


def test_record_mode_never_claims_gateway_privacy(tmp_path):
    evidence = _evidence(tmp_path)
    evidence["mode"] = "record"
    report = harness._build_report(**evidence)
    assert not report["privacy_checked"]
    assert not report["automatic_compaction_qualified"]


def test_compaction_report_requires_all_clients_summary_and_resumed_replay(tmp_path):
    report = harness._build_report(**_evidence(tmp_path, compact=True))
    assert report["success"]
    assert report["automatic_compaction_qualified"]
    assert all(outcome["automatic_compaction_qualified"] for outcome in report["outcomes"].values())
    assert all(outcome["long_history_summarized"] for outcome in report["outcomes"].values())


@pytest.mark.parametrize("client", ["codex", "claude"])
def test_compaction_before_notes_read_cannot_qualify_the_long_session(tmp_path, client):
    evidence = _evidence(tmp_path, compact=True)
    protocol = "responses" if client == "codex" else "messages"
    received = evidence["provider_requests"][protocol]
    _set_payload_text(received[0], _summary_text(client, notes=False))
    _set_payload_text(
        received[2], "Ordinary replay:\n" + harness.NOTES.replace(harness.CANARY, SURROGATE)
    )
    report = harness._build_report(**evidence)
    outcome = report["outcomes"][client]
    sibling = "claude" if client == "codex" else "codex"
    assert outcome["compactions"] == 1
    assert outcome["long_history_read"]
    assert outcome["native_compaction_event"]
    assert outcome["summary_replay_inspected"]
    assert report["privacy_checked"]
    assert not outcome["long_history_summarized"]
    assert report["outcomes"][sibling]["long_history_summarized"]
    assert report["outcomes"][sibling]["automatic_compaction_qualified"]
    assert not report["automatic_compaction_qualified"]
    assert not report["success"]


@pytest.mark.parametrize("client", ["codex", "claude"])
@pytest.mark.parametrize(
    "failure",
    ["last_note_missing", "owner_untransformed", "no_surrogate", "last_owner_untransformed"],
)
def test_long_summary_must_include_final_inspected_note_and_transformed_owner(
    tmp_path, client, failure
):
    evidence = _evidence(tmp_path, compact=True)
    protocol = "responses" if client == "codex" else "messages"
    text = _summary_text(client)
    if failure == "last_note_missing":
        text = text.rsplit("Synthetic note 0999:", 1)[0]
    elif failure == "owner_untransformed":
        text = text.replace(SURROGATE, harness.CANARY)
    elif failure == "no_surrogate":
        text = text.replace(SURROGATE, "ordinary-public-owner")
    else:
        text = text.replace(
            "Synthetic note 0999: owner " + SURROGATE,
            "Synthetic note 0999: owner ordinary-public-owner",
        )
    _set_payload_text(evidence["provider_requests"][protocol][2], text)
    report = harness._build_report(**evidence)
    assert not report["outcomes"][client]["long_history_summarized"]
    assert not report["outcomes"][client]["automatic_compaction_qualified"]
    assert not report["automatic_compaction_qualified"]
    assert not report["success"]


@pytest.mark.parametrize("client", ["codex", "claude"])
def test_final_notes_summary_may_occur_during_post_compaction_resume(tmp_path, client):
    evidence = _evidence(tmp_path, compact=True)
    protocol = "responses" if client == "codex" else "messages"
    received = evidence["provider_requests"][protocol]
    _set_payload_text(received[0], _summary_text(client, notes=False))
    _set_payload_text(
        received[2], "Ordinary replay:\n" + harness.NOTES.replace(harness.CANARY, SURROGATE)
    )
    _set_payload_text(
        received[3], _summary_text(client) + "\n" + harness.SUMMARY_MARKER + ": Owner " + SURROGATE
    )
    report = harness._build_report(**evidence)
    assert report["outcomes"][client]["compactions"] == 2
    assert report["outcomes"][client]["long_history_summarized"]
    assert report["automatic_compaction_qualified"]
    assert report["success"]


@pytest.mark.parametrize("client", ["codex", "claude"])
@pytest.mark.parametrize("owner", ["ordinary-public-owner", harness.CANARY])
def test_fresh_user_surrogate_cannot_mask_uninspected_compaction_summary_owner(
    tmp_path, client, owner
):
    evidence = _evidence(tmp_path, compact=True)
    protocol = "responses" if client == "codex" else "messages"
    text = harness.SUMMARY_MARKER + ": Owner " + owner + ".\nFresh follow-up for " + SURROGATE
    _set_payload_text(evidence["provider_requests"][protocol][3], text)
    report = harness._build_report(**evidence)
    assert report["outcomes"][client]["long_history_summarized"]
    assert not report["outcomes"][client]["summary_replay_inspected"]
    assert not report["outcomes"][client]["automatic_compaction_qualified"]
    assert not report["automatic_compaction_qualified"]
    assert not report["success"]


@pytest.mark.parametrize("client", ["codex", "claude"])
@pytest.mark.parametrize(
    "missing", ["summary_request", "boundary", "history_read", "summary_replay", "restored_reply"]
)
def test_one_clients_compaction_cannot_qualify_another_without_native_replay(
    tmp_path, client, missing
):
    evidence = _evidence(tmp_path, compact=True)
    protocol = "responses" if client == "codex" else "messages"
    if missing == "summary_request":
        _set_payload_text(
            evidence["provider_requests"][protocol][2], "ordinary follow-up " + SURROGATE
        )
    elif missing in {"boundary", "history_read"}:
        events = _long_session_events(client)
        if missing == "boundary":
            events = [
                event for event in events if not harness._native_compaction_seen(client, [event])
            ]
        else:
            events = [
                event
                for event in events
                if harness._native_compaction_seen(client, [event])
                or event in _completion_events(client)
            ]
        _replace_phase_events(evidence, client, "long-session", events)
    elif missing == "summary_replay":
        _set_payload_text(
            evidence["provider_requests"][protocol][3], "ordinary replay " + SURROGATE
        )
    else:
        events = _completion_events(client)
        for event in events:
            if "result" in event:
                event["result"] = "No restored owner"
            elif event.get("item", {}).get("type") == "agent_message":
                event["item"]["text"] = "No restored owner"
        _replace_phase_events(evidence, client, "post-compaction-resume", events)
    report = harness._build_report(**evidence)
    other = "claude" if client == "codex" else "codex"
    assert report["outcomes"][other]["automatic_compaction_qualified"]
    assert not report["outcomes"][client]["automatic_compaction_qualified"]
    assert not report["automatic_compaction_qualified"]
    assert not report["success"]


def test_compaction_requires_post_boundary_followup_to_resume_native_session(tmp_path):
    evidence = _evidence(tmp_path, compact=True)
    _run(evidence, "claude", "post-compaction-resume")["resume"] = False
    report = harness._build_report(**evidence)
    assert not report["automatic_compaction_qualified"]
    assert not report["success"]


def test_codex_persisted_native_compaction_can_qualify_when_exec_omits_boundary(tmp_path):
    evidence = _evidence(tmp_path, compact=True, clients=("codex",))
    events = _long_session_events("codex")
    events = [event for event in events if not harness._native_compaction_seen("codex", [event])]
    _replace_phase_events(evidence, "codex", "long-session", events)
    session = tmp_path / "codex-home" / "codex" / "sessions"
    session.mkdir(parents=True)
    _write_events(
        session,
        "rollout-synthetic.jsonl",
        [
            {
                "type": "compacted",
                "payload": {
                    "message": harness.SUMMARY_MARKER + ": Owner " + harness.CANARY,
                    "window_number": 1,
                    "compaction_response_id": "resp_synthetic_summary",
                },
            }
        ],
    )
    report = harness._build_report(**evidence)
    assert not report["outcomes"]["codex"]["native_compaction_event"]
    assert report["outcomes"]["codex"]["persisted_compaction_record"]
    assert report["automatic_compaction_qualified"]
    assert report["success"]
