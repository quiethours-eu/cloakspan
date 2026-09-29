"""Lazy command dispatch: diagnostics and playground do not build the gateway app."""

from __future__ import annotations

import argparse
import secrets
import socket
import sys


def run(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="cloakspan")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("serve", help="Start the configured gateway (default)")
    playground = commands.add_parser(
        "playground", help="Inspect sample text in a private loopback browser page"
    )
    playground.add_argument("--port", type=int, default=8765, help="loopback port (default: 8765)")
    args = parser.parse_args(argv)

    if args.command in (None, "serve"):
        from gateway.main import run as serve

        serve()
        return

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    from gateway.config import Settings
    from gateway.playground.app import create_playground_app

    try:
        settings = Settings.from_env()
        access_code = secrets.token_urlsafe(32)
        app = create_playground_app(settings, port=args.port, access_code=access_code)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as check:
            check.bind(("127.0.0.1", args.port))
    except OSError:
        print(f"Cannot bind 127.0.0.1:{args.port}; choose another --port.", file=sys.stderr)
        raise SystemExit(2) from None
    except Exception:
        print(
            "Playground configuration could not be loaded. "
            "Check policy, filters, routing, and NER settings.",
            file=sys.stderr,
        )
        raise SystemExit(2) from None

    config = app.state.configuration
    print(f"Cloakspan local privacy playground: http://127.0.0.1:{args.port}")
    print(f"Session access code: {access_code}")
    print(
        f"Policy: {config.policy_version}; routing: {config.routing_mode}; "
        f"profile: {config.coverage['profile']}"
    )
    for warning in config.warnings:
        print(f"Coverage note: {warning}")
    print("Inspection stays in this Python process. No provider is contacted.")

    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=args.port, access_log=False, log_level="warning")


if __name__ == "__main__":
    run()
