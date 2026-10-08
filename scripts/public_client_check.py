"""Run pinned public coding CLIs in disposable repositories against local mocks.

The harness never installs CLIs or constructs an external provider. Its clients
receive an isolated HOME and a small explicit environment containing only a
synthetic gateway key. Record mode helps classify real native requests; gateway
mode runs the same clients through the real inspection and restoration path.
All recording artifacts contain only the disposable synthetic task.
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from gateway.api.app import create_app
from gateway.audit.events import MemorySink
from gateway.auth.keys import ApiKey, ApiKeyStore, hash_key
from gateway.config import DEFAULT_POLICY_PATH, Settings
from gateway.detectors.deterministic import default_detectors
from gateway.inspection.pipeline import SecurityPipeline
from gateway.policy.engine import PolicyEngine
from gateway.restoration.engine import RestorationEngine
from gateway.routing.base import MockProvider
from gateway.routing.responses import MockAgentProvider
from gateway.transformations.engine import TransformationEngine
from gateway.transformations.tokens import TOKEN_PATTERN, TokenMinter
from gateway.vault.store import KeyRing, SurrogateVault

PINNED = {"codex": "0.161.0", "claude": "2.1.293"}
SYNTHETIC_KEY = "sgw_live_public_client_synthetic_key"  # noqa: S105 - public fixture only
CANARY = "agent-owner@example.test"
SOURCE = (
    "# Owner: " + CANARY + '\nCONTACT = "' + CANARY + '"\n\n\ndef add(a, b):\n    return a - b\n'
)
TEST_SOURCE = (
    "from sample_math import CONTACT, add\n\n\n"
    "def test_addition_and_owner():\n"
    "    assert add(2, 3) == 5\n"
    f'    assert CONTACT == "{CANARY}"\n'
)
LONG_SESSION_MARKER = "CLOAKSPAN_LONG_SESSION"
SUMMARY_MARKER = "CLOAKSPAN_INSPECTABLE_SUMMARY"
LAST_NOTE_OWNER_PREFIX = "Synthetic note 0999: owner "
NOTE_SUFFIX = "; addition uses a plus b; tests passed."
NOTES = "".join(
    f"Synthetic note {line:04d}: owner {CANARY}; addition uses a plus b; tests passed.\n"
    for line in range(1000)
)


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def _event(kind: str, sequence: int, **fields: Any) -> bytes:
    data = {"type": kind, "sequence_number": sequence, **fields}
    return (f"event: {kind}\ndata: " + json.dumps(data, ensure_ascii=False) + "\n\n").encode()


class ScriptedProvider(MockAgentProvider):
    """Only deterministic local file operations; never executes client tools."""

    def __init__(self, protocol: str, workspace: Path, workflow: bool) -> None:
        super().__init__(protocol=protocol)
        self.workspace = workspace
        self.workflow = workflow
        self.steps = 0
        self.compactions = 0
        self.long_read_started = False
        self.compaction_requests: list[dict[str, Any]] = []

    def _completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        serialized = json.dumps(payload, ensure_ascii=False)
        token = TOKEN_PATTERN.search(serialized)
        owner = token.group(0) if token else CANARY
        step = self.steps
        self.steps += 1
        call: tuple[str, Any] | None = None
        summary_request = (
            self.protocol == "responses"
            and not payload.get("tools")
            and "CONTEXT CHECKPOINT COMPACTION" in serialized
        ) or (
            self.protocol == "messages"
            and any(
                marker in serialized
                for marker in (
                    "Your task is to create a detailed summary",
                    "You are a helpful AI assistant tasked with summarizing conversations.",
                )
            )
        )
        if summary_request:
            self.compactions += 1
            self.compaction_requests.append(payload)
        elif self.workflow and step == 0:
            call = (
                (
                    "exec_command",
                    {"cmd": "cat sample_math.py", "workdir": str(self.workspace), "login": False},
                )
                if self.protocol == "responses"
                else ("Read", {"file_path": str(self.workspace / "sample_math.py")})
            )
        elif self.workflow and step == 1:
            if self.protocol == "responses":
                patch = (
                    "*** Begin Patch\n*** Update File: "
                    + str(self.workspace / "sample_math.py")
                    + f'\n@@\n CONTACT = "{owner}"\n \n \n def add(a, b):\n'
                    "-    return a - b\n+    return a + b\n*** End Patch\n"
                )
                call = ("apply_patch", patch)
            else:
                old = SOURCE.replace(CANARY, owner)
                call = (
                    "Edit",
                    {
                        "file_path": str(self.workspace / "sample_math.py"),
                        "old_string": old,
                        "new_string": old.replace("return a - b", "return a + b"),
                    },
                )
        elif self.workflow and step == 2:
            call = (
                (
                    "exec_command",
                    {"cmd": "python -m pytest -q", "workdir": str(self.workspace), "login": False},
                )
                if self.protocol == "responses"
                else (
                    "Bash",
                    {
                        "command": "python -m pytest -q",
                        "description": "Run the synthetic addition test",
                    },
                )
            )
        elif LONG_SESSION_MARKER in serialized and not self.long_read_started:
            self.long_read_started = True
            call = (
                (
                    "exec_command",
                    {
                        "cmd": "cat synthetic_notes.txt",
                        "workdir": str(self.workspace),
                        "login": False,
                        "max_output_tokens": 16000,
                    },
                )
                if self.protocol == "responses"
                else ("Read", {"file_path": str(self.workspace / "synthetic_notes.txt")})
            )
        text = f"Synthetic workflow completed for {owner}; inspected replay is available."
        if summary_request:
            text = (
                f"{SUMMARY_MARKER}: Owner {owner}. sample_math.py now adds a and b. "
                "The client ran python -m pytest -q and one test passed. "
                "Synthetic notes contain no outstanding tasks. Continue with the user's follow-up."
            )
            if self.protocol == "messages":
                text = "<summary>" + text + "</summary>"
        usage = {"input_tokens": max(1, len(serialized) // 4), "output_tokens": 30}
        identity = f"public_{self.protocol}_{self.steps}"
        if self.protocol == "messages":
            content = (
                [{"type": "tool_use", "id": "call_" + identity, "name": call[0], "input": call[1]}]
                if call
                else [{"type": "text", "text": text}]
            )
            return {
                "id": "msg_" + identity,
                "type": "message",
                "role": "assistant",
                "model": payload["model"],
                "content": content,
                "stop_reason": "tool_use" if call else "end_turn",
                "stop_sequence": None,
                "usage": usage,
            }
        if call:
            custom = call[0] == "apply_patch"
            output = [
                {
                    "type": "custom_tool_call" if custom else "function_call",
                    "id": "fc_" + identity,
                    "call_id": "call_" + identity,
                    "name": call[0],
                    "input" if custom else "arguments": call[1] if custom else json.dumps(call[1]),
                    "status": "completed",
                }
            ]
        else:
            output = [
                {
                    "type": "message",
                    "id": "msg_" + identity,
                    "status": "completed",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": text, "annotations": []}],
                }
            ]
        return {
            "id": "resp_" + identity,
            "object": "response",
            "created_at": 1,
            "status": "completed",
            "model": payload["model"],
            "output": output,
            "usage": {**usage, "total_tokens": sum(usage.values())},
        }

    async def stream(self, payload: dict[str, Any], **kwargs: Any):
        # The shared fixture emits native Messages and standard Responses
        # items. Add the native freeform-patch event grammar for public Codex.
        if self.protocol != "responses" or not (self.workflow and self.steps == 1):
            async for chunk in super().stream(payload, **kwargs):
                yield chunk
            return
        self._record(payload)
        response = self._completion(payload)
        item = response["output"][0]
        yield _event(
            "response.created", 0, response={**response, "status": "in_progress", "output": []}
        )
        yield _event(
            "response.output_item.added",
            1,
            output_index=0,
            item={**item, "status": "in_progress", "input": ""},
        )
        yield _event(
            "response.custom_tool_call_input.delta",
            2,
            output_index=0,
            item_id=item["id"],
            delta=item["input"],
        )
        yield _event(
            "response.custom_tool_call_input.done",
            3,
            output_index=0,
            item_id=item["id"],
            input=item["input"],
        )
        yield _event("response.output_item.done", 4, output_index=0, item=item)
        yield _event("response.completed", 5, response=response)


class Recorder:
    def __init__(self, app: Any, output: Path) -> None:
        self.app = app
        self.output = output
        self.requests: list[dict[str, Any]] = []

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        raw = bytearray()
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return
            raw.extend(message.get("body", b""))
            if len(raw) > 1_048_576:
                await JSONResponse({"error": {"code": "fixture_request_too_large"}}, 413)(
                    scope, receive, send
                )
                return
            if not message.get("more_body"):
                break
        body = json.loads(raw) if raw else None
        record = {
            "method": scope["method"],
            "path": scope["path"],
            "query": scope.get("query_string", b"").decode(),
            "headers": {k.decode(): v.decode() for k, v in scope["headers"]},
            "body": body,
        }
        self.requests.append(record)
        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(raw), "more_body": False}
            return await receive()

        async def recorded_send(message):
            if message["type"] == "http.response.start":
                record["status"] = message["status"]
                response_headers = {k.decode(): v.decode() for k, v in message.get("headers", [])}
                record["request_id"] = response_headers.get("x-request-id")
                _write_json(self.output / "requests.json", self.requests)
            await send(message)

        await self.app(scope, replay, recorded_send)


def _app(mode: str, providers: dict[str, ScriptedProvider], root: Path, audit: MemorySink) -> Any:
    if mode == "record":
        app = FastAPI()

        @app.post("/v1/{endpoint:path}")
        async def recorded(request: Request, endpoint: str):
            payload = await request.json()
            protocol = "messages" if endpoint.startswith("messages") else "responses"
            provider = providers[protocol]
            if endpoint.endswith("count_tokens"):
                return JSONResponse(await provider.count_tokens(payload))
            if payload.get("stream"):
                return StreamingResponse(provider.stream(payload), media_type="text/event-stream")
            return JSONResponse(await provider.complete(payload))

        return app
    vault = SurrogateVault(key_ring=KeyRing(keys={1: b"\x31" * 32}, active_version=1))
    mock = MockProvider()
    pipeline = SecurityPipeline(
        detectors=default_detectors(),
        policy=PolicyEngine.from_yaml(DEFAULT_POLICY_PATH),
        transformer=TransformationEngine(TokenMinter(secret_key=b"\x42" * 32), vault),
        restorer=RestorationEngine(vault),
        providers={"mock": mock, "external": mock, "local": mock},
        audit_sink=audit,
        max_input_chars=262_144,
    )
    return create_app(
        pipeline=pipeline,
        key_store=ApiKeyStore(
            [ApiKey("public-client-key", hash_key(SYNTHETIC_KEY), "public-synthetic-tenant")]
        ),
        settings=Settings(
            enable_responses=True,
            enable_messages=True,
            agent_workspace_root=str(root / "repos"),
            max_input_chars=262_144,
        ),
        agent_providers={
            protocol: {"mock": provider, "external": provider, "local": provider}
            for protocol, provider in providers.items()
        },
    )


def _environment(home: Path) -> dict[str, str]:
    # No inherited cloud credentials, user settings, proxies, or plugin state.
    directories = [str(Path(sys.executable).parent)]
    node = shutil.which("node")
    if node:
        directories.append(str(Path(node).parent))
    directories.extend(["/usr/local/bin", "/usr/bin", "/bin"])
    return {
        "PATH": ":".join(directories),
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "TERM": "dumb",
        "NO_PROXY": "127.0.0.1,localhost",
        "XDG_CONFIG_HOME": str(home / "config"),
        "XDG_CACHE_HOME": str(home / "cache"),
        "XDG_STATE_HOME": str(home / "state"),
    }


def _validate_version(client: str, stdout: str) -> str:
    expected = (
        "codex-cli " + PINNED[client] if client == "codex" else PINNED[client] + " (Claude Code)"
    )
    if stdout.strip() != expected:
        raise ValueError("Client binary does not match the pinned public version")
    return PINNED[client]


def _read_events(stdout: str) -> list[dict[str, Any]]:
    events = []
    for line in stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            events.append(value)
    return events


def _client_completion(client: str, events: list[dict[str, Any]]) -> bool:
    if client == "codex":
        return any(event.get("type") == "turn.completed" for event in events) and not any(
            event.get("type") in {"turn.failed", "error"} for event in events
        )
    results = [
        event
        for event in events
        if event.get("type") == "result" and event.get("parent_tool_use_id") is None
    ]
    return bool(results) and all(
        event.get("type") == "result"
        and event.get("subtype") == "success"
        and event.get("is_error") is False
        for event in results
    )


def _test_execution_seen(client: str, events: list[dict[str, Any]]) -> bool:
    if client == "codex":
        return any(
            event.get("type") == "item.completed"
            and isinstance(item := event.get("item"), dict)
            and item.get("type") == "command_execution"
            and item.get("command")
            in {
                "python -m pytest -q",
                "/bin/bash -c 'python -m pytest -q'",
                "/bin/sh -c 'python -m pytest -q'",
            }
            and type(item.get("exit_code")) is int
            and item.get("exit_code") == 0
            and "1 passed" in item.get("aggregated_output", "")
            for event in events
        )
    test_calls = set()
    for event in events:
        if event.get("parent_tool_use_id") is not None:
            continue
        message = event.get("message")
        if event.get("type") == "assistant" and isinstance(message, dict):
            for block in message.get("content", []):
                if (
                    isinstance(block, dict)
                    and block.get("type") == "tool_use"
                    and block.get("name") == "Bash"
                    and isinstance(block.get("id"), str)
                    and block["id"]
                    and block.get("input", {}).get("command") == "python -m pytest -q"
                ):
                    test_calls.add(block.get("id"))
        elif event.get("type") == "user" and isinstance(message, dict):
            for block in message.get("content", []):
                if (
                    isinstance(block, dict)
                    and block.get("type") == "tool_result"
                    and block.get("tool_use_id") in test_calls
                    and block.get("is_error", False) is False
                    and "1 passed" in str(block.get("content", ""))
                ):
                    return True
    return False


def _native_compaction_seen(client: str, events: list[dict[str, Any]]) -> bool:
    if client == "codex":
        return any(
            event.get("type") == "item.completed"
            and isinstance(event.get("item"), dict)
            and event["item"].get("type") == "context_compaction"
            for event in events
        )
    return any(
        event.get("type") == "system"
        and event.get("subtype") == "compact_boundary"
        and event.get("parent_tool_use_id") is None
        for event in events
    )


def _persisted_compaction_seen(client: str, root: Path) -> bool:
    if client != "codex":
        return False
    sessions = root / "codex-home" / "codex" / "sessions"
    for path in sessions.rglob("rollout-*.jsonl"):
        for event in _read_events(path.read_text()):
            payload = event.get("payload", {})
            if (
                event.get("type") == "compacted"
                and isinstance(payload, dict)
                and SUMMARY_MARKER in payload.get("message", "")
                and CANARY in payload.get("message", "")
                and type(payload.get("window_number")) is int
                and payload["window_number"] > 0
                and isinstance(payload.get("compaction_response_id"), str)
            ):
                return True
    return False


def _notes_execution_seen(client: str, events: list[dict[str, Any]]) -> bool:
    if client == "codex":
        return any(
            event.get("type") == "item.completed"
            and isinstance(item := event.get("item"), dict)
            and item.get("type") == "command_execution"
            and item.get("command")
            in {
                "cat synthetic_notes.txt",
                "/bin/bash -c 'cat synthetic_notes.txt'",
                "/bin/sh -c 'cat synthetic_notes.txt'",
            }
            and type(item.get("exit_code")) is int
            and item.get("exit_code") == 0
            and "Synthetic note 0000:" in item.get("aggregated_output", "")
            for event in events
        )
    read_calls = set()
    for event in events:
        if event.get("parent_tool_use_id") is not None:
            continue
        message = event.get("message")
        if event.get("type") == "assistant" and isinstance(message, dict):
            for block in message.get("content", []):
                if (
                    isinstance(block, dict)
                    and block.get("type") == "tool_use"
                    and block.get("name") == "Read"
                    and isinstance(block.get("id"), str)
                    and block["id"]
                    and block.get("input", {}).get("file_path", "").endswith("/synthetic_notes.txt")
                ):
                    read_calls.add(block["id"])
        elif event.get("type") == "user" and isinstance(message, dict):
            for block in message.get("content", []):
                if (
                    isinstance(block, dict)
                    and block.get("type") == "tool_result"
                    and block.get("tool_use_id") in read_calls
                    and block.get("is_error", False) is False
                    and "Synthetic note 0000:" in str(block.get("content", ""))
                ):
                    return True
    return False


def _summary_request(payload: dict[str, Any], client: str) -> bool:
    serialized = json.dumps(payload)
    if client == "codex":
        return not payload.get("tools") and "CONTEXT CHECKPOINT COMPACTION" in serialized
    return any(
        marker in serialized
        for marker in (
            "Your task is to create a detailed summary",
            "You are a helpful AI assistant tasked with summarizing conversations.",
        )
    )


def _inspected_owner_segment(payload: dict[str, Any], prefix: str, *, suffix: str = "") -> bool:
    serialized = json.dumps(payload)
    offset = 0
    while (position := serialized.find(prefix, offset)) >= 0:
        owner_start = position + len(prefix)
        token = TOKEN_PATTERN.match(serialized, owner_start)
        if (
            token
            and token.group(1) == "EMAIL_ADDRESS"
            and serialized.startswith(suffix, token.end())
        ):
            return True
        offset = owner_start
    return False


def _build_report(
    *,
    root: Path,
    clients: list[str],
    mode: str,
    workflow: bool,
    compact: bool,
    runs: list[dict[str, Any]],
    requests: list[dict[str, Any]],
    provider_requests: dict[str, list[dict[str, Any]]],
    audit: list[dict[str, Any]],
) -> dict[str, Any]:
    """Qualify each real client from independent execution and replay evidence."""
    outcomes = {}
    required = {"initial"}
    if workflow:
        required.add("resume")
    if compact:
        required.update({"long-session", "post-compaction-resume"})
    checked_runs = []
    for client in clients:
        protocol = "responses" if client == "codex" else "messages"
        received = provider_requests.get(protocol, [])
        native = [r for r in requests if r["path"].startswith("/v1/" + protocol)]
        request_ids = {r.get("request_id") for r in native if r.get("request_id")}
        client_audit = [event for event in audit if event.get("request_id") in request_ids]
        client_runs = [run for run in runs if run["client"] == client]
        events = []
        phase_events = {}
        run_success = bool(client_runs) and {run["phase"] for run in client_runs} == required
        for run in client_runs:
            stdout_path = root / run["stdout_file"]
            stdout = stdout_path.read_text() if stdout_path.exists() else ""
            current_events = _read_events(stdout)
            phase_events[run["phase"]] = current_events
            events.extend(current_events)
            selected = requests[run["request_start"] : run["request_end"]]
            selected = [r for r in selected if r["path"] == "/v1/" + protocol]
            upstream = received[run["provider_start"] : run["provider_end"]]
            completed = _client_completion(client, current_events)
            passed = (
                type(run["returncode"]) is int
                and run["returncode"] == 0
                and run.get("timed_out") is False
                and completed
                and bool(selected)
                and all(record.get("status") == 200 for record in selected)
                and bool(upstream)
            )
            run_success = run_success and passed
            checked_runs.append(
                {
                    **run,
                    "completed": completed,
                    "request_count": len(selected),
                    "provider_request_count": len(upstream),
                    "successful": passed,
                }
            )
        sessions = {
            r.get("headers", {}).get(
                "session-id" if client == "codex" else "x-claude-code-session-id"
            )
            for r in native
        }
        stable_scope = len(sessions) == 1 and None not in sessions and "" not in sessions
        source = (root / "repos" / client / "sample_math.py").read_text()
        summary_count = sum(_summary_request(payload, client) for payload in received)
        long_history_summarized = any(
            _summary_request(payload, client)
            and _inspected_owner_segment(payload, LAST_NOTE_OWNER_PREFIX, suffix=NOTE_SUFFIX)
            for payload in received
        )
        native_compaction = _native_compaction_seen(client, events)
        persisted_compaction = _persisted_compaction_seen(client, root)
        post_runs = [run for run in client_runs if run["phase"] == "post-compaction-resume"]
        post_received = [
            payload
            for run in post_runs
            for payload in received[run["provider_start"] : run["provider_end"]]
        ]
        post_stdout = "".join(
            (root / run["stdout_file"]).read_text()
            for run in post_runs
            if (root / run["stdout_file"]).exists()
        )
        restored_followup = CANARY in post_stdout
        replay_inspected = any(
            _inspected_owner_segment(payload, SUMMARY_MARKER + ": Owner ")
            and CANARY not in json.dumps(payload)
            for payload in post_received
        )
        transformed = bool(received) and any(
            TOKEN_PATTERN.search(json.dumps(payload)) for payload in received
        )
        outcome = {
            "runs_successful": run_success,
            "stable_session_scope": stable_scope,
            "edited_source": source == SOURCE.replace("return a - b", "return a + b"),
            "test_execution_seen": _test_execution_seen(client, phase_events.get("initial", [])),
            "provider_requests": len(received),
            "canary_transformed": transformed,
            "audited_transformation": bool(client_audit)
            and any(event.get("entities_transformed", 0) > 0 for event in client_audit),
            "compactions": summary_count,
            "native_compaction_event": native_compaction,
            "persisted_compaction_record": persisted_compaction,
            "long_history_read": _notes_execution_seen(
                client, phase_events.get("long-session", [])
            ),
            "long_history_summarized": long_history_summarized,
            "summary_replay_inspected": replay_inspected,
            "restored_post_compaction_followup": restored_followup,
        }
        outcome["automatic_compaction_qualified"] = (
            compact
            and run_success
            and stable_scope
            and summary_count > 0
            and (native_compaction or persisted_compaction)
            and outcome["long_history_read"]
            and long_history_summarized
            and replay_inspected
            and restored_followup
            and all(run.get("resume") is True for run in post_runs)
            and bool(post_runs)
        )
        outcomes[client] = outcome
    all_upstream = json.dumps(provider_requests)
    # Native compactors can mention a transcript filename containing a session
    # UUID in visible text, which remains subject to content inspection. Check
    # that locally consumed identities are absent from forwarded structural
    # fields, including the remapped provider cache key.
    upstream_structural = json.dumps(
        [
            {
                key: value
                for key, value in payload.items()
                if key not in {"input", "instructions", "messages", "system", "tools", "text"}
            }
            for received in provider_requests.values()
            for payload in received
        ]
    )
    client_identifiers = set()
    for record in requests:
        payload = record.get("body") or {}
        if isinstance(payload.get("prompt_cache_key"), str) and payload["prompt_cache_key"]:
            client_identifiers.add(payload["prompt_cache_key"])
        user_id = payload.get("metadata", {}).get("user_id")
        if isinstance(user_id, str) and user_id:
            client_identifiers.add(user_id)
            try:
                identity = json.loads(user_id)
            except json.JSONDecodeError:
                identity = {}
            if isinstance(identity, dict):
                client_identifiers.update(
                    value for value in identity.values() if isinstance(value, str) and value
                )
        for key, value in record.get("headers", {}).items():
            if (
                key
                in {
                    "session-id",
                    "thread-id",
                    "x-session-id",
                    "x-codex-installation-id",
                    "x-codex-window-id",
                    "x-claude-code-session-id",
                }
                and value
            ):
                client_identifiers.add(value)
    privacy_checks = {
        "upstream_canary_absent": CANARY not in all_upstream,
        "audit_canary_absent": CANARY not in json.dumps(audit),
        "audit_present": bool(audit),
        "audit_metadata_only": bool(audit)
        and all(
            event.get("raw_content_logged") is False and not event.get("error") for event in audit
        ),
        "client_metadata_consumed": all(
            "metadata" not in payload and "client_metadata" not in payload
            for received in provider_requests.values()
            for payload in received
        ),
        "each_canary_transformed": bool(outcomes)
        and all(outcome["canary_transformed"] for outcome in outcomes.values()),
        "each_transformation_audited": bool(outcomes)
        and all(outcome["audited_transformation"] for outcome in outcomes.values()),
        "client_identifiers_consumed": all(
            value not in upstream_structural for value in client_identifiers
        ),
    }
    privacy = mode == "gateway" and all(privacy_checks.values())
    success = bool(outcomes) and all(
        outcome["runs_successful"] and outcome["stable_session_scope"]
        for outcome in outcomes.values()
    )
    if mode == "gateway":
        success = success and privacy
    if workflow:
        success = success and all(
            outcome["edited_source"] and outcome["test_execution_seen"]
            for outcome in outcomes.values()
        )
    qualified = (
        compact
        and privacy
        and bool(outcomes)
        and all(outcome["automatic_compaction_qualified"] for outcome in outcomes.values())
    )
    if compact:
        success = success and qualified
    return {
        "versions": {client: PINNED[client] for client in clients},
        "mode": mode,
        "workflow": workflow,
        "compact_requested": compact,
        "runs": checked_runs,
        "outcomes": outcomes,
        "privacy_checked": privacy,
        "privacy_checks": privacy_checks,
        "requests": len(requests),
        "success": success,
        "automatic_compaction_qualified": qualified,
        "compaction_controls": {
            "codex_auto_compact_token_limit": 6000,
            "codex_tool_truncation_bytes": 30000,
            "claude_window": 100000,
            "claude_percentage": 5,
            "claude_max_output_tokens": 1024,
            "notes_lines": 1000,
            "usage_estimate": "input_tokens = serialized inspected request characters // 4",
        }
        if compact
        else None,
        "output_dir": str(root),
    }


def _codex_config(home: Path, url: str, repository: Path, *, compact: bool = False) -> None:
    config_dir = home / "codex"
    config_dir.mkdir()
    catalog = json.loads((repository / "deployment/clients/codex-models.example.json").read_text())
    if compact:
        # Public catalog controls lower the real client's threshold. Token usage
        # remains proportional to the actual inspected request, and history is
        # grown by a client-executed read of a bounded synthetic notes file.
        catalog["models"][0]["auto_compact_token_limit"] = 6000
        catalog["models"][0]["truncation_policy"]["limit"] = 30000
    _write_json(config_dir / "models.json", catalog)
    config = (repository / "deployment/clients/codex-config.example.toml").read_text()
    config = config.replace(
        "REPLACE_WITH_ABSOLUTE_PATH/codex-models.example.json", str(config_dir / "models.json")
    )
    config = config.replace("http://127.0.0.1:8080/v1", url + "/v1")
    config = 'approval_policy="never"\nsandbox_mode="workspace-write"\n' + config
    (config_dir / "config.toml").write_text(config)


def _run_client(
    client: str,
    binary: Path,
    home: Path,
    workspace: Path,
    url: str,
    prompt: str,
    *,
    resume: bool,
    session: str,
    output: Path,
    timeout: int,
    phase: str | None = None,
    compact: bool = False,
) -> dict:
    env = _environment(home)
    if client == "codex":
        env.update({"CODEX_HOME": str(home / "codex"), "CLOAKSPAN_GATEWAY_KEY": SYNTHETIC_KEY})
        cmd = [str(binary), "exec"]
        if resume:
            cmd.extend(["resume", "--last"])
        cmd.extend(["--json", "--skip-git-repo-check", "--ignore-rules", prompt])
    else:
        env.update(
            {
                "ANTHROPIC_BASE_URL": url,
                "ANTHROPIC_API_KEY": SYNTHETIC_KEY,
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS": "1",
                "CLAUDE_CODE_DISABLE_STRUCTURED_OUTPUTS": "1",
                "CLAUDE_CODE_DISABLE_TERMINAL_TITLE": "1",
                "CLAUDE_CODE_DISABLE_TOOL_SEARCH": "1",
                "MAX_THINKING_TOKENS": "0",
                "DISABLE_INTERLEAVED_THINKING": "1",
            }
        )
        if compact:
            env.update(
                {
                    "CLAUDE_CODE_AUTO_COMPACT_WINDOW": "100000",
                    "CLAUDE_AUTOCOMPACT_PCT_OVERRIDE": "5",
                    "CLAUDE_CODE_MAX_OUTPUT_TOKENS": "1024",
                }
            )
        cmd = [
            str(binary),
            "--bare",
            "-p",
            "--model",
            "claude-sonnet-4-6",
            "--effort",
            "low",
            "--output-format",
            "stream-json",
            "--verbose",
            "--tools",
            "Read,Write,Edit,Bash,Glob,Grep",
            "--allowedTools",
            "Read,Write,Edit,Glob,Grep,Bash(python -m pytest -q)",
            "--setting-sources",
            "",
            "--strict-mcp-config",
            "--mcp-config",
            '{"mcpServers":{}}',
            "--disable-slash-commands",
            "--permission-mode",
            "acceptEdits",
            "--max-budget-usd",
            "0.50",
        ]
        cmd.extend(["--resume" if resume else "--session-id", session, prompt])
    phase = phase or ("resume" if resume else "initial")
    label = client + "-" + phase
    try:
        result = subprocess.run(  # noqa: S603 - explicit binary and controlled synthetic argv
            cmd,
            cwd=workspace,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )  # noqa: S603 - explicit binary, controlled argv
        (output / (label + "-stdout.jsonl")).write_text(result.stdout)
        (output / (label + "-stderr.txt")).write_text(result.stderr)
        return {
            "client": client,
            "phase": phase,
            "resume": resume,
            "returncode": result.returncode,
            "timed_out": False,
            "stdout_file": label + "-stdout.jsonl",
            "completed": _client_completion(client, _read_events(result.stdout)),
        }
    except subprocess.TimeoutExpired as exc:
        (output / (label + "-stdout.jsonl")).write_bytes(exc.stdout or b"")
        (output / (label + "-stderr.txt")).write_bytes(exc.stderr or b"")
        return {
            "client": client,
            "phase": phase,
            "resume": resume,
            "returncode": None,
            "timed_out": True,
            "completed": False,
            "stdout_file": label + "-stdout.jsonl",
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex-binary", type=Path)
    parser.add_argument("--claude-binary", type=Path)
    parser.add_argument("--mode", choices=("record", "gateway"), default="gateway")
    parser.add_argument(
        "--workflow", action="store_true", help="Run actual read/edit/test plus resumed follow-up"
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Grow inspectable tool history; require automatic compaction and resumed replay",
    )
    parser.add_argument(
        "--output-dir", type=Path, help="New empty directory for synthetic recording artifacts"
    )
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args(argv)
    if args.compact and not args.workflow:
        parser.error("--compact requires --workflow")
    binaries = {
        name: binary.resolve()
        for name, binary in (("codex", args.codex_binary), ("claude", args.claude_binary))
        if binary
    }
    if not binaries:
        parser.error(
            "Supply an installed --codex-binary or --claude-binary; no download is performed."
        )
    root = (
        args.output_dir.resolve()
        if args.output_dir
        else Path(tempfile.mkdtemp(prefix="cloakspan-public-clients-"))
    )
    if args.output_dir:
        root.mkdir(parents=True, exist_ok=False)
    (root / "repos").mkdir()
    repository = Path(__file__).resolve().parents[1]
    for client in binaries:
        workspace = root / "repos" / client
        workspace.mkdir()
        (workspace / "sample_math.py").write_text(SOURCE)
        (workspace / "test_sample_math.py").write_text(TEST_SOURCE)
        (workspace / "synthetic_notes.txt").write_text(NOTES)
        (root / (client + "-home")).mkdir()
    providers = {
        protocol: ScriptedProvider(protocol, root / "repos" / client, args.workflow)
        for protocol, client in (("responses", "codex"), ("messages", "claude"))
    }
    audit = MemorySink()
    recorder = Recorder(_app(args.mode, providers, root, audit), root)
    listening = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listening.bind(("127.0.0.1", 0))
    url = "http://127.0.0.1:" + str(listening.getsockname()[1])
    server = uvicorn.Server(
        uvicorn.Config(recorder, log_level="error", access_log=False, lifespan="on")
    )
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listening]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        raise RuntimeError("Local synthetic gateway did not start")
    runs = []

    def invoke(client: str, *positional: Any, **keyword: Any) -> dict[str, Any]:
        protocol = "responses" if client == "codex" else "messages"
        request_start = len(recorder.requests)
        provider_start = len(providers[protocol].received)
        result = _run_client(client, *positional, **keyword)
        return {
            **result,
            "request_start": request_start,
            "request_end": len(recorder.requests),
            "provider_start": provider_start,
            "provider_end": len(providers[protocol].received),
        }

    try:
        for client, binary in binaries.items():
            home = root / (client + "-home")
            if client == "codex":
                _codex_config(home, url, repository, compact=args.compact)
            version = subprocess.run(  # noqa: S603 - explicit binary, fixed version flag
                [str(binary), "--version"],
                env=_environment(home),
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )  # noqa: S603
            _validate_version(client, version.stdout)
            prompt = (
                f"Fix addition in sample_math.py for {CANARY}. Read the file, edit it, "
                "and run python -m pytest -q."
                if args.workflow
                else f"Confirm receipt for {CANARY}; no tools are needed."
            )
            session = str(uuid.uuid4())
            runs.append(
                invoke(
                    client,
                    binary,
                    home,
                    root / "repos" / client,
                    url,
                    prompt,
                    resume=False,
                    session=session,
                    output=root,
                    timeout=args.timeout,
                    compact=args.compact,
                )
            )
            if args.workflow and runs[-1]["returncode"] == 0:
                runs.append(
                    invoke(
                        client,
                        binary,
                        home,
                        root / "repos" / client,
                        url,
                        f"Follow up for {CANARY}: explain the tested edit using replayed history.",
                        resume=True,
                        session=session,
                        output=root,
                        timeout=args.timeout,
                        compact=args.compact,
                    )
                )
            if args.compact and runs[-1]["returncode"] == 0:
                for phase, extra_prompt in (
                    (
                        "long-session",
                        f"{LONG_SESSION_MARKER}: Read synthetic_notes.txt for {CANARY}. "
                        "Use the notes to confirm the tested edit and preserve task progress.",
                    ),
                    (
                        "post-compaction-resume",
                        f"Follow up after the long session for {CANARY}: confirm the tested edit "
                        "using the inspectable history preserved by the client.",
                    ),
                ):
                    runs.append(
                        invoke(
                            client,
                            binary,
                            home,
                            root / "repos" / client,
                            url,
                            extra_prompt,
                            resume=True,
                            session=session,
                            output=root,
                            timeout=args.timeout,
                            phase=phase,
                            compact=True,
                        )
                    )
                    if runs[-1]["returncode"] != 0:
                        break
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        listening.close()
        _write_json(root / "requests.json", recorder.requests)
        _write_json(
            root / "provider-requests.json",
            {key: value.received for key, value in providers.items()},
        )
        _write_json(root / "audit.json", [event.to_dict() for event in audit.events])
    report = _build_report(
        root=root,
        clients=list(binaries),
        mode=args.mode,
        workflow=args.workflow,
        compact=args.compact,
        runs=runs,
        requests=recorder.requests,
        provider_requests={protocol: provider.received for protocol, provider in providers.items()},
        audit=[event.to_dict() for event in audit.events],
    )
    _write_json(root / "report.json", report)
    print(json.dumps(report, indent=2))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
