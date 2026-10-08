"""Synthetic direct/gateway agent runtime benchmark; no client or live provider."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import platform
import secrets
import statistics
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gateway.api.agent_runtime import AgentRuntime  # noqa: E402
from gateway.audit.events import MemorySink  # noqa: E402
from gateway.config import Settings, build_detectors, load_policy_and_filters  # noqa: E402
from gateway.domain import RequestContext  # noqa: E402
from gateway.inspection.pipeline import SecurityPipeline  # noqa: E402
from gateway.protocols import parse_messages_request, parse_responses_request  # noqa: E402
from gateway.restoration.engine import RestorationEngine  # noqa: E402
from gateway.routing.base import MockProvider  # noqa: E402
from gateway.routing.responses import MockAgentProvider  # noqa: E402
from gateway.streaming.sse import json_object, parse_sse  # noqa: E402
from gateway.transformations.engine import TransformationEngine  # noqa: E402
from gateway.transformations.tokens import TokenMinter  # noqa: E402
from gateway.vault.store import KeyRing, SurrogateVault  # noqa: E402

CANARY = "synthetic-agent@example.test"
UNIT = f"# synthetic source\ncontact = '{CANARY}'\ndef add(a, b): return a + b\n"


def sample(size: int) -> str:
    return (UNIT * (size // len(UNIT) + 1))[:size]


def fixture(protocol: str, payload: dict[str, Any]) -> dict[str, Any]:
    text = payload["input"] if protocol == "responses" else payload["messages"][0]["content"]
    # These counters are whitespace estimates, deliberately not tokenizer claims.
    usage = {"input_tokens": len(text.split()), "output_tokens": len(text.split())}
    if protocol == "messages":
        return {
            "id": "msg_synthetic",
            "type": "message",
            "role": "assistant",
            "model": payload["model"],
            "content": [
                {"type": "text", "text": text},
                {
                    "type": "tool_use",
                    "id": "call_synthetic",
                    "name": "read_file",
                    "input": {"path": "sample.txt"},
                },
            ],
            "stop_reason": "tool_use",
            "stop_sequence": None,
            "usage": usage,
        }
    return {
        "id": "resp_synthetic",
        "object": "response",
        "created_at": 0,
        "model": payload["model"],
        "status": "completed",
        "output": [
            {
                "id": "msg_synthetic",
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": text, "annotations": []}],
            },
            {
                "id": "fc_synthetic",
                "type": "function_call",
                "status": "completed",
                "call_id": "call_synthetic",
                "name": "read_file",
                "arguments": '{"path":"sample.txt"}',
            },
        ],
        "usage": {**usage, "total_tokens": sum(usage.values())},
    }


class TimedProvider(MockAgentProvider):
    terminal_at: float | None = None

    async def stream(self, payload):
        self.terminal_at = None
        async for chunk in super().stream(payload):
            if b"event: response.completed\n" in chunk or b"event: message_stop\n" in chunk:
                self.terminal_at = time.perf_counter()
            yield chunk


def pipeline(settings: Settings) -> SecurityPipeline:
    policy, filters = load_policy_and_filters(settings)
    vault = SurrogateVault(KeyRing({1: secrets.token_bytes(32)}, 1))
    return SecurityPipeline(
        detectors=build_detectors(settings, filters=filters),
        policy=policy,
        transformer=TransformationEngine(TokenMinter(secrets.token_bytes(32)), vault),
        restorer=RestorationEngine(vault),
        providers={"external": MockProvider(), "local": MockProvider(), "mock": MockProvider()},
        audit_sink=MemorySink(),
        max_input_chars=settings.max_input_chars,
    )


async def observe(chunks, provider: TimedProvider, started: float) -> dict[str, Any]:
    first_text = None
    first_tool = None
    usage: dict[str, Any] = {}
    text = []
    terminal = False
    async for frame in parse_sse(chunks):
        if frame.heartbeat:
            continue
        event = json_object(frame.data)
        kind = event["type"]
        now = time.perf_counter()
        if kind == "response.output_text.delta" or (
            kind == "content_block_delta" and event.get("delta", {}).get("type") == "text_delta"
        ):
            first_text = first_text or now
            text.append(
                event["delta"] if kind == "response.output_text.delta" else event["delta"]["text"]
            )
        if (kind == "response.output_item.added" and event["item"]["type"] == "function_call") or (
            kind == "content_block_start" and event["content_block"]["type"] == "tool_use"
        ):
            first_tool = first_tool or now
        if kind == "response.completed":
            terminal = True
            usage = event["response"].get("usage", {})
        elif kind == "message_start":
            usage.update(event["message"].get("usage", {}))
        elif kind == "message_delta":
            usage.update(event.get("usage", {}))
        elif kind == "message_stop":
            terminal = True
        elif kind in {"error", "response.failed", "response.incomplete"}:
            raise RuntimeError("synthetic stream failed")
    if not terminal or first_text is None or first_tool is None:
        raise RuntimeError("synthetic stream was incomplete")
    return {
        "_text_digest": hashlib.sha256("".join(text).encode()).hexdigest(),
        "time_to_first_text_ms": (first_text - started) * 1000,
        "tool_release_ms": (first_tool - started) * 1000,
        "tool_release_after_provider_terminal_ms": (first_tool - provider.terminal_at) * 1000
        if provider.terminal_at is not None
        else None,
        "total_task_ms": (time.perf_counter() - started) * 1000,
        "input_tokens": usage.get("input_tokens"),
        "output_tokens": usage.get("output_tokens"),
        "cache_read_tokens": usage.get("cache_read_input_tokens"),
        "cache_creation_tokens": usage.get("cache_creation_input_tokens"),
    }


def summary(values: list[float]) -> dict[str, float] | None:
    if not values:
        return None
    ordered = sorted(values)
    return {
        "p50": round(statistics.median(values), 3),
        "p95": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 3),
        "max": round(max(values), 3),
    }


async def measure(
    protocol: str, profile: str, size: int, iterations: int, ner_model: str = ""
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="cloakspan-benchmark-") as workspace:
        settings = Settings(
            enable_responses=protocol == "responses",
            enable_messages=protocol == "messages",
            agent_workspace_root=workspace,
            ner_model_path=ner_model if profile == "ner" else "",
            dictionary_terms=("synthetic source",) if profile == "dictionary" else (),
            max_input_chars=max(65_536, size * 2),
        )
        core = pipeline(settings)
        provider = TimedProvider(protocol=protocol, response=lambda body: fixture(protocol, body))
        runtime = AgentRuntime(
            core,
            settings,
            providers={protocol: {"external": provider, "local": provider, "mock": provider}},
        )
        tool = {
            "name": "read_file",
            "description": "Read synthetic local source.",
            "parameters" if protocol == "responses" else "input_schema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
        }
        if protocol == "responses":
            tool["type"] = "function"
            payload = {
                "model": "synthetic-model",
                "input": sample(size),
                "stream": True,
                "store": False,
                "tools": [tool],
            }
            parser = parse_responses_request
        else:
            payload = {
                "model": "synthetic-model",
                "messages": [{"role": "user", "content": sample(size)}],
                "stream": True,
                "max_tokens": max(512, size),
                "tools": [tool],
            }
            parser = parse_messages_request
        results: dict[str, list[dict[str, Any]]] = {"direct": [], "gateway": []}
        failures = {"direct": 0, "gateway": 0}
        tracemalloc.start()
        try:
            for index in range(iterations):
                for path in ("direct", "gateway"):
                    provider.received.clear()
                    started = time.perf_counter()
                    try:
                        if path == "direct":
                            chunks = provider.stream(payload)
                            inspection_ms = 0.0
                        else:
                            ctx = RequestContext(
                                "synthetic-tenant",
                                "synthetic-session",
                                f"bench_{index}",
                                "synthetic-principal",
                            )
                            prepared = await runtime.prepare(ctx, parser(payload))
                            inspection_ms = prepared.inspection_ms
                            chunks = runtime.stream(ctx, prepared)
                        row = await observe(chunks, provider, started)
                        row["inspection_ms"] = inspection_ms
                        expected = hashlib.sha256(sample(size).encode()).hexdigest()
                        if row.pop("_text_digest") != expected:
                            raise RuntimeError("synthetic text was not preserved")
                        if path == "gateway" and CANARY in json.dumps(provider.received):
                            raise RuntimeError("synthetic canary reached provider")
                        if path == "gateway" and row["tool_release_after_provider_terminal_ms"] < 0:
                            raise RuntimeError(
                                "synthetic tool was released before provider completion"
                            )
                        results[path].append(row)
                    except Exception:
                        failures[path] += 1
            _, peak_bytes = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
            await runtime.aclose()
        metrics = {}
        for path, rows in results.items():
            metrics[path] = {
                key: summary([float(row[key]) for row in rows if row[key] is not None])
                for key in (
                    "inspection_ms",
                    "time_to_first_text_ms",
                    "tool_release_ms",
                    "tool_release_after_provider_terminal_ms",
                    "total_task_ms",
                    "input_tokens",
                    "output_tokens",
                    "cache_read_tokens",
                    "cache_creation_tokens",
                )
            }
            metrics[path]["failure_rate"] = failures[path] / iterations
        return {
            "protocol": protocol,
            "detector_profile": profile,
            "prompt_bytes": size,
            "request_bytes": len(json.dumps(payload).encode()),
            "iterations": iterations,
            "python_parent_peak_bytes": peak_bytes,
            "metrics": metrics,
            "input_token_change_p50": (
                metrics["gateway"]["input_tokens"]["p50"] - metrics["direct"]["input_tokens"]["p50"]
            )
            if results["direct"] and results["gateway"]
            else None,
            "output_token_change_p50": (
                metrics["gateway"]["output_tokens"]["p50"]
                - metrics["direct"]["output_tokens"]["p50"]
            )
            if results["direct"] and results["gateway"]
            else None,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", choices=["responses", "messages", "both"], default="both")
    parser.add_argument(
        "--profiles",
        nargs="+",
        choices=["deterministic", "dictionary", "ner"],
        default=["deterministic"],
    )
    parser.add_argument("--sizes", nargs="+", type=int, default=[4096, 16384])
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--ner-model", default="")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if (
        args.iterations < 1
        or any(size < 256 or size > 524_288 for size in args.sizes)
        or ("ner" in args.profiles and not args.ner_model)
    ):
        parser.error("positive iterations, sizes 256..524288 and a model for NER are required")

    async def run():
        rows = []
        for protocol in ["responses", "messages"] if args.protocol == "both" else [args.protocol]:
            for profile in args.profiles:
                for size in args.sizes:
                    rows.append(
                        await measure(protocol, profile, size, args.iterations, args.ner_model)
                    )
        return rows

    report = {
        "schema_version": 1,
        "evidence": "synthetic in-process runtime benchmark",
        "machine": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "processor": platform.processor() or "unknown",
        },
        "rows": asyncio.run(run()),
        "limitations": [
            "No HTTP/TLS/network, real model, tokenizer, client, cache or coding task measured.",
            "Token counts are synthetic whitespace estimates; absent cache metrics remain null.",
            "Python tracemalloc peak excludes detector child RSS and native/model allocations.",
            "This is not reference-deployment qualification or pilot approval.",
        ],
    }
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return int(
        any(
            row["metrics"][path]["failure_rate"]
            for row in report["rows"]
            for path in ("direct", "gateway")
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
