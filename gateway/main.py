"""Process entrypoint."""

from __future__ import annotations

import logging

from gateway.api.app import create_app
from gateway.config import Settings


def build() -> object:
    settings = Settings.from_env()
    logging.basicConfig(
        level=settings.log_level,
        format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
    )
    return create_app(settings=settings)


app = build()


def run() -> None:
    import uvicorn

    settings = Settings.from_env()
    uvicorn.run(
        "gateway.main:app",
        host=settings.bind_host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        # Graceful shutdown: finish in-flight requests before exiting so a
        # deploy never truncates a response mid-restoration.
        timeout_graceful_shutdown=30,
    )


if __name__ == "__main__":
    run()
