"""Lazy command dispatch: diagnostics and playground do not build the gateway app."""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import json
import math
import os
import secrets
import socket
import sys


def _positive_timeout(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError:
        value = float("nan")
    if not math.isfinite(value) or value <= 0 or value > 15:
        raise argparse.ArgumentTypeError("timeout must be a finite number between 0 and 15 seconds")
    return value


def _run_playground(port: int) -> int:
    from gateway.config import Settings
    from gateway.playground.app import create_playground_app

    try:
        settings = Settings.from_env()
        access_code = secrets.token_urlsafe(32)
        app = create_playground_app(settings, port=port, access_code=access_code)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as check:
            check.bind(("127.0.0.1", port))
    except OSError:
        print(f"Cannot bind 127.0.0.1:{port}; choose another --port.", file=sys.stderr)
        return 2
    except Exception:
        print(
            "Playground configuration could not be loaded. "
            "Check policy, filters, routing, and NER settings.",
            file=sys.stderr,
        )
        return 2

    config = app.state.configuration
    print(f"Cloakspan local privacy playground: http://127.0.0.1:{port}")
    print(f"Session access code: {access_code}")
    print(
        f"Policy: {config.policy_version}; routing: {config.routing_mode}; "
        f"profile: {config.coverage['profile']}"
    )
    for warning in config.warnings:
        print(f"Coverage note: {warning}")
    print("Inspection stays in this Python process. No provider is contacted.")

    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=port, access_log=False, log_level="warning")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cloakspan", description="Cloakspan gateway, local preview, and setup checks"
    )
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("serve", help="start the gateway server (the default)")
    doctor = commands.add_parser(
        "doctor", help="inspect configuration without starting the gateway"
    )
    doctor.add_argument("--format", choices=("text", "json"), default="text")
    doctor.add_argument("--strict", action="store_true", help="return nonzero for warnings")
    doctor.add_argument(
        "--load-model",
        action="store_true",
        help="load local NER in a subprocess (60-second deadline); no downloads",
    )
    doctor.add_argument(
        "--probe-providers",
        action="store_true",
        help=(
            "allow DNS and authenticated GET /models to configured providers; honors opted-in proxy"
        ),
    )
    doctor.add_argument(
        "--timeout",
        type=_positive_timeout,
        default=5.0,
        help="per-provider probe timeout in seconds (default: 5; overall: 15)",
    )
    playground = commands.add_parser(
        "playground", help="inspect sample text in a private loopback browser page"
    )
    playground.add_argument(
        "--port", type=int, default=8765, help="loopback port (default: 8765)"
    )
    args = parser.parse_args(argv)

    if args.command in (None, "serve"):
        from gateway.main import run

        run()
        return 0

    if args.command == "playground":
        if not 1 <= args.port <= 65535:
            parser.error("--port must be between 1 and 65535")
        return _run_playground(args.port)

    try:
        from gateway.diagnostics.models import CheckResult, DoctorReport
        from gateway.diagnostics.report import render_json, render_text

        unavailable = []
        for name in ("anyio", "fastapi", "httpx", "pydantic", "yaml", "cryptography", "uvicorn"):
            try:
                importlib.import_module(name)
            except Exception:
                unavailable.append(name)
        if unavailable:
            try:
                version = importlib.metadata.version("secure-ai-gateway")
            except importlib.metadata.PackageNotFoundError:
                version = "0.1.0a1"
            report = DoctorReport(
                gateway_version=version,
                environment="unverified",
                routing_mode="unverified",
                coverage=(),
                checks=tuple(
                    CheckResult(
                        f"runtime.dependency.{name}",
                        "fail",
                        f"Required dependency {name} is unavailable",
                        f"Install the package dependencies to restore {name}.",
                    )
                    for name in unavailable
                ),
            )
        else:
            from gateway.diagnostics.runner import run_doctor

            report = run_doctor(
                os.environ,
                load_ner_model=args.load_model,
                probe=args.probe_providers,
                timeout=args.timeout,
            )
    except Exception:
        if args.format == "json":
            print(
                json.dumps(
                    {
                        "schema_version": 1,
                        "gateway_version": "unverified",
                        "environment": "unverified",
                        "routing_mode": "unverified",
                        "status": "error",
                        "counts": {"pass": 0, "warn": 0, "fail": 1, "skip": 0},
                        "coverage": [],
                        "checks": [
                            {
                                "id": "diagnostics.internal",
                                "status": "fail",
                                "summary": "Unexpected diagnostics failure",
                                "details": {},
                            }
                        ],
                    }
                )
            )
        else:
            print("Cloakspan doctor: unexpected diagnostics failure")
        return 2
    print(render_json(report) if args.format == "json" else render_text(report))
    return report.exit_code(strict=args.strict)


def run(argv: list[str] | None = None) -> int:
    """Keep compatibility with earlier console script entry points."""
    return main(argv)


if __name__ == "__main__":
    raise SystemExit(main())