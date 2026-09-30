"""Supervised, single-job preview worker with hard process deadlines."""

from __future__ import annotations

import asyncio
import json
import multiprocessing as mp
import threading
import time
from multiprocessing.connection import Connection
from typing import Any

from gateway.api.schema import RequestRejected
from gateway.config import (
    Settings,
    _require_ner_for_detected,
    build_detectors,
    load_policy_and_filters,
)
from gateway.inspection.preparation import DetectionError
from gateway.normalization import SuspiciousEncodingError
from gateway.playground.preview import MAX_BODY_BYTES, MAX_RESULT_BYTES, inspect_locally

LOAD_TIMEOUT_SECONDS = 60.0
INSPECT_TIMEOUT_SECONDS = 15.0


class WorkerBusy(Exception):
    pass


class WorkerUnavailable(Exception):
    pass


def _send(connection: Connection, value: dict[str, Any], max_bytes: int) -> None:
    encoded = json.dumps(value, ensure_ascii=False).encode("utf-8")
    if len(encoded) > max_bytes:
        raise ValueError("worker message exceeds its limit")
    connection.send_bytes(encoded)


def _receive(connection: Connection, max_bytes: int) -> dict[str, Any]:
    value = json.loads(connection.recv_bytes(maxlength=max_bytes))
    if not isinstance(value, dict):
        raise ValueError("worker message is not an object")
    return value


def _await_ready(connection: Connection, process: mp.Process) -> bool:
    deadline = time.monotonic() + LOAD_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if connection.poll(min(0.2, max(0.0, deadline - time.monotonic()))):
            return True
        if not process.is_alive():
            return False
    return False


def _limit_memory() -> None:
    """Cap worker address space on POSIX; Windows has no portable RLIMIT_AS."""
    try:
        import resource

        limit = 2 * 1024 * 1024 * 1024
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        resource.setrlimit(resource.RLIMIT_AS, (min(soft, limit) if soft > 0 else limit, hard))
    except (ImportError, OSError, ValueError):
        pass


def _worker_main(connection: Connection, settings: Settings) -> None:
    _limit_memory()
    try:
        policy, filters = load_policy_and_filters(settings)
        detectors = build_detectors(settings, filters=filters)
        _require_ner_for_detected(settings, detectors)
        _send(connection, {"ready": True}, 1024)
    except Exception:
        _send(connection, {"ready": False}, 1024)
        connection.close()
        return

    try:
        while True:
            try:
                job = _receive(connection, MAX_BODY_BYTES + 1024)
            except (EOFError, KeyboardInterrupt, OSError, ValueError):
                break
            try:
                result = inspect_locally(
                    settings,
                    detectors,
                    policy,
                    job["text"],
                    job["role"],
                    job["application"],
                )
            except (RequestRejected, DetectionError, SuspiciousEncodingError):
                result = {
                    "error": {
                        "code": "inspection_failed",
                        "message": (
                            "The text could not be inspected. Check the input and try again."
                        ),
                    }
                }
            except Exception:
                result = {
                    "error": {
                        "code": "inspection_unavailable",
                        "message": "Inspection failed inside the local worker.",
                    }
                }
            _send(connection, result, MAX_RESULT_BYTES)
    finally:
        connection.close()


class WorkerSupervisor:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._context = mp.get_context("spawn")
        self._process: mp.Process | None = None
        self._connection: Connection | None = None
        self._slot = threading.Lock()
        self.ready = False
        self.recovering = False
        self._recovery_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self.ready = False
        parent, child = self._context.Pipe(duplex=True)
        process = self._context.Process(
            target=_worker_main, args=(child, self.settings), daemon=True
        )
        self._process = process
        self._connection = parent
        try:
            process.start()
            child.close()
            available = await asyncio.to_thread(_await_ready, parent, process)
            if not available or _receive(parent, 1024) != {"ready": True}:
                raise WorkerUnavailable(
                    "The local inspection worker could not load its configuration or model."
                )
            self.ready = True
        except (EOFError, OSError, ValueError, WorkerUnavailable) as exc:
            self.stop()
            raise WorkerUnavailable(
                "The local inspection worker could not load its configuration or model."
            ) from exc

    def stop(self) -> None:
        self.ready = False
        if self._connection is not None:
            self._connection.close()
            self._connection = None
        if self._process is not None:
            if self._process.is_alive():
                self._process.terminate()
            self._process.join(timeout=2)
            if self._process.is_alive():
                self._process.kill()
                self._process.join(timeout=2)
            self._process.close()
            self._process = None

    async def _recover(self) -> None:
        self.recovering = True
        try:
            await self.start()
        except WorkerUnavailable:
            pass
        finally:
            self.recovering = False

    async def inspect(self, job: dict[str, str]) -> dict[str, Any]:
        if not self.ready or self._connection is None:
            raise WorkerUnavailable("The local inspection worker is recovering.")
        if not self._slot.acquire(blocking=False):
            raise WorkerBusy
        try:
            connection = self._connection
            return await asyncio.wait_for(
                asyncio.to_thread(self._exchange, connection, job), INSPECT_TIMEOUT_SECONDS
            )
        except TimeoutError as exc:
            self.stop()
            self._recovery_task = asyncio.create_task(self._recover())
            raise WorkerUnavailable(
                "Inspection timed out; the local worker is restarting."
            ) from exc
        except (EOFError, OSError, ValueError) as exc:
            self.stop()
            self._recovery_task = asyncio.create_task(self._recover())
            raise WorkerUnavailable(
                "The local inspection worker stopped and is restarting."
            ) from exc
        except asyncio.CancelledError:
            self.stop()
            self._recovery_task = asyncio.create_task(self._recover())
            raise
        finally:
            self._slot.release()

    @staticmethod
    def _exchange(connection: Connection, job: dict[str, str]) -> dict[str, Any]:
        _send(connection, job, MAX_BODY_BYTES + 1024)
        if not connection.poll(INSPECT_TIMEOUT_SECONDS):
            raise TimeoutError
        return _receive(connection, MAX_RESULT_BYTES)

    async def close(self) -> None:
        if self._recovery_task is not None:
            self._recovery_task.cancel()
            try:
                await self._recovery_task
            except asyncio.CancelledError:
                pass
        self.stop()
