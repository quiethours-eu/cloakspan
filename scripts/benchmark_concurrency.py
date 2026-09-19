"""Concurrency benchmark: throughput under load, and event-loop responsiveness.

    python scripts/benchmark_concurrency.py --output dist/benchmark-concurrency.json

## Why this exists separately from `benchmark.py`

`benchmark.py` measures the detection path in isolation, one call at a time. It
answers "how long does inspection take". It cannot answer the question that
actually determines whether an instance stays up under load:

**while one request is being inspected, can the process serve anything else?**

Detection, transformation and restoration are synchronous and CPU-bound. Until
they were moved to a worker thread they ran on the event loop, so a single large
request blocked *every* other request in the process -- including `/healthz`,
which is what a load balancer reads to decide the instance is alive. At the
default `SAG_MAX_INPUT_CHARS` that stall was measured in seconds.

That is an availability property, not a performance one, so it gets a benchmark
that can fail rather than a number in a table.

## What is measured

1. **Sequential throughput** -- the baseline, comparable to `benchmark.py`.
2. **Concurrent throughput** at several concurrency levels. Python's GIL means
   CPU-bound threads do not scale linearly, and this says by how much rather
   than assuming.
3. **Health-check latency while large requests are in flight.** This is the
   headline. It should stay in the low milliseconds; if it tracks the
   inspection time instead, the CPU work is back on the loop.

Everything runs in-process against the ASGI app through `httpx.ASGITransport`:
no ports, no sockets, no external model. The provider is the offline mock, so
the numbers are the gateway's own cost and nothing else's.

As with `benchmark.py`, this is a **regression signal on the machine that
produced it**, not a published figure. It records the hardware for that reason.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import statistics
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402

from gateway.api.app import create_app  # noqa: E402
from gateway.auth.keys import ApiKey, ApiKeyStore, hash_key  # noqa: E402
from gateway.config import Settings  # noqa: E402
from gateway.crypto import TOKEN_KEY_INFO, VAULT_KEY_INFO, derive_key  # noqa: E402
from gateway.detectors.deterministic import default_detectors  # noqa: E402
from gateway.inspection.pipeline import SecurityPipeline  # noqa: E402
from gateway.policy.engine import PolicyEngine  # noqa: E402
from gateway.restoration.engine import RestorationEngine  # noqa: E402
from gateway.routing.base import MockProvider  # noqa: E402
from gateway.transformations.engine import TransformationEngine  # noqa: E402
from gateway.transformations.tokens import TokenMinter  # noqa: E402
from gateway.vault.store import KeyRing, SurrogateVault  # noqa: E402

API_KEY = "sgw_live_benchmark_key"

#: One sentence carrying four entity types, repeated to reach a target size.
UNIT = (
    "Klienta Anna Kalnina personas kods ir 120385-12342, e-pasts a1@example.lv, "
    "konts LV80 BANK 0000 4351 9500 1, karte 4111 1111 1111 1111. "
)

#: Gate on the **median** health-check latency, not the tail.
#:
#: Measured A/B on identical CPU work, four concurrent requests, timing how long
#: a bare `await asyncio.sleep(0)` waits to be rescheduled:
#:
#:     inline on the loop    p50 12200 ms   (rescheduled ONCE in three seconds)
#:     asyncio.to_thread     p50  0.03 ms   (rescheduled 29 times)
#:
#: Five orders of magnitude, so the median detects the regression with no
#: ambiguity. The tail is a different phenomenon -- see the saturation run.
#:
#: **On the size of this budget.** A full `/healthz` round trip is not a bare
#: loop yield: it goes through the ASGI stack, routing, and the handler, each of
#: which needs the GIL that a detection thread is holding in 5 ms slices. So the
#: realistic figure is tens of milliseconds, not the 0.03 ms above, and an
#: earlier version of this file set the budget from the wrong measurement and
#: failed against correct code.
#:
#: 500 ms is chosen to be *operationally* meaningful rather than tight: load
#: balancers use timeouts measured in seconds, so anything under this is
#: harmless, while the regression it guards against overshoots it by 24x. A
#: tripwire, not an SLO -- a tight budget here would fail the build for running
#: the benchmark on a busy laptop, which is exactly how a useful gate gets
#: disabled.
HEALTH_STALL_BUDGET_MS = 500.0


class _NullSink:
    """Audit events are not what is being measured, and writing them to stdout
    would make the benchmark measure the terminal."""

    def write(self, event: Any) -> None:  # noqa: D102
        return None


def _text_of(size: int) -> str:
    return (UNIT * (size // len(UNIT) + 1))[:size]


def build_app() -> Any:
    settings = Settings.from_env()
    vault = SurrogateVault(
        key_ring=KeyRing(
            keys={1: derive_key(b"benchmark-vault-root-secret-32-bytes!!", VAULT_KEY_INFO)},
            active_version=1,
        ),
        ttl_seconds=3600,
    )
    minter = TokenMinter(
        secret_key=derive_key(b"benchmark-token-root-secret-32-bytes!!", TOKEN_KEY_INFO)
    )
    pipeline = SecurityPipeline(
        detectors=default_detectors(),
        policy=PolicyEngine.from_yaml(settings.policy_path),
        transformer=TransformationEngine(minter, vault),
        restorer=RestorationEngine(vault),
        providers={"external": MockProvider(), "local": MockProvider()},
        audit_sink=_NullSink(),  # type: ignore[arg-type]
    )
    store = ApiKeyStore(
        [
            ApiKey(
                key_id="bench",
                key_hash=hash_key(API_KEY),
                tenant_id="tenant-bench",
                application="bench",
            )
        ]
    )
    return create_app(pipeline=pipeline, key_store=store, settings=settings)


def _percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * pct / 100))]


async def _chat(client: httpx.AsyncClient, text: str) -> float:
    body = {"model": "bench", "messages": [{"role": "user", "content": text}]}
    start = time.perf_counter()
    response = await client.post(
        "http://gateway/v1/chat/completions",
        json=body,
        headers={"Authorization": f"Bearer {API_KEY}"},
    )
    response.raise_for_status()
    return (time.perf_counter() - start) * 1000


async def measure_throughput(
    client: httpx.AsyncClient, size: int, concurrency: int, total: int
) -> dict[str, Any]:
    text = _text_of(size)
    await _chat(client, text)  # warm

    latencies: list[float] = []
    semaphore = asyncio.Semaphore(concurrency)

    async def one() -> None:
        async with semaphore:
            latencies.append(await _chat(client, text))

    started = time.perf_counter()
    await asyncio.gather(*(one() for _ in range(total)))
    elapsed = time.perf_counter() - started

    return {
        "input_bytes": size,
        "concurrency": concurrency,
        "requests": total,
        "throughput_rps": round(total / elapsed, 1),
        "p50_ms": round(statistics.median(latencies), 2),
        "p95_ms": round(_percentile(latencies, 95), 2),
    }


async def measure_health_under_load(
    client: httpx.AsyncClient, size: int, concurrency: int
) -> dict[str, Any]:
    """The headline. Poll `/healthz` while large requests are being inspected.

    If inspection runs on the event loop, these samples inherit the inspection
    time -- that is the signature of the regression this guards against.
    """
    text = _text_of(size)
    stop = asyncio.Event()
    samples: list[float] = []

    async def poll() -> None:
        while not stop.is_set():
            start = time.perf_counter()
            await client.get("http://gateway/healthz")
            samples.append((time.perf_counter() - start) * 1000)
            await asyncio.sleep(0.005)

    async def load() -> None:
        # Enough rounds that the poller collects a stable sample at every
        # concurrency level, rather than a handful at the lowest.
        for _ in range(max(8, concurrency * 2)):
            await asyncio.gather(*(_chat(client, text) for _ in range(concurrency)))

    poller = asyncio.create_task(poll())
    try:
        await load()
    finally:
        stop.set()
        await poller

    return {
        "input_bytes": size,
        "concurrency": concurrency,
        "samples": len(samples),
        "p50_ms": round(statistics.median(samples), 2),
        "p95_ms": round(_percentile(samples, 95), 2),
        "max_ms": round(max(samples), 2),
        "budget_ms": HEALTH_STALL_BUDGET_MS,
        "within_budget": statistics.median(samples) <= HEALTH_STALL_BUDGET_MS,
    }


async def run() -> dict[str, Any]:
    app = build_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, timeout=120.0) as client:
        # The app's lifespan does not run under ASGITransport, so nothing here
        # depends on it: the mock provider holds no connections to close.
        throughput = [
            await measure_throughput(client, 4_096, concurrency, 60) for concurrency in (1, 4, 16)
        ]
        # Two different questions, deliberately separated.
        #
        # concurrency=1 is the *architectural* one: while a single large request
        # is inspected, does the process still serve anything? That is what the
        # thread hop changed, and it is what regresses if the CPU work ever
        # moves back onto the loop. It is the gate.
        #
        # concurrency=4 is a *capacity* question: with every core busy on
        # pure-Python detection, the GIL is contended and the health check
        # queues behind it. Reported, never gated -- the answer there is more
        # processes, and failing a build for it would be measuring the machine.
        health = await measure_health_under_load(client, 65_536, 1)
        saturated = await measure_health_under_load(client, 65_536, 4)
    return {
        "machine": platform.platform(),
        "python": platform.python_version(),
        "throughput": throughput,
        "health_under_load": health,
        "health_under_saturation": saturated,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)

    report = asyncio.run(run())

    print("Throughput (4 KB requests, mock provider, in-process)")
    print(f"  {'concurrency':>12} {'rps':>9} {'p50 ms':>9} {'p95 ms':>9}")
    for row in report["throughput"]:
        print(
            f"  {row['concurrency']:>12} {row['throughput_rps']:>9} "
            f"{row['p50_ms']:>9} {row['p95_ms']:>9}"
        )

    health = report["health_under_load"]
    print(f"\nHealth check while one {health['input_bytes']} byte request is inspected  [GATE]")
    print(
        f"  p50 {health['p50_ms']} ms, p95 {health['p95_ms']} ms, max {health['max_ms']} ms "
        f"({health['samples']} samples)"
    )
    verdict = "within" if health["within_budget"] else "OVER"
    print(f"  median {verdict} the {health['budget_ms']} ms stall budget")
    if not health["within_budget"]:
        print("  ^ the event loop is being blocked by inspection. See pipeline.process.")

    saturated = report["health_under_saturation"]
    print(
        f"\nHealth check with {saturated['concurrency']} concurrent "
        f"{saturated['input_bytes']} byte requests  [reported, not gated]"
    )
    print(
        f"  p50 {saturated['p50_ms']} ms, p95 {saturated['p95_ms']} ms, "
        f"max {saturated['max_ms']} ms"
    )
    print(
        "  Detection is pure Python, so saturating the CPU contends the GIL and the\n"
        "  health check queues behind it. That is a capacity limit answered by more\n"
        "  processes, not a blocked loop -- and it is why one instance per core is\n"
        "  the deployment shape rather than one instance with more threads."
    )

    print(f"\nmachine: {report['machine']}")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"wrote {args.output}")

    return 0 if health["within_budget"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
