"""Command dispatch that never imports the ASGI app for help or diagnostics."""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import json
import math
import os


def _positive_timeout(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError:
        value = float("nan")
    if not math.isfinite(value) or value <= 0 or value > 15:
        raise argparse.ArgumentTypeError("timeout must be a finite number between 0 and 15 seconds")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cloakspan", description="Cloakspan gateway and setup checks"
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
    args = parser.parse_args(argv)

    if args.command in (None, "serve"):
        from gateway.main import run

        run()
        return 0

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


if __name__ == "__main__":
    raise SystemExit(main())
