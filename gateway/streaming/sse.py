"""A bounded SSE parser. Invalid UTF-8 and incomplete frames fail closed."""

from __future__ import annotations

import codecs
import json
from collections.abc import AsyncIterable, AsyncIterator
from dataclasses import dataclass
from typing import Any

from gateway.api.schema import RequestRejected
from gateway.protocols.base import bounded_json

MAX_EVENT_BYTES = 1024 * 1024


class StreamProtocolError(Exception):
    """Safe public error: no provider content is included in its message."""

    def __init__(self, code: str = "invalid_provider_stream") -> None:
        self.code = code
        super().__init__(code)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StreamProtocolError()
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise StreamProtocolError()


def json_object(data: str) -> dict[str, Any]:
    """Decode one JSON object without duplicates, NaN, or excessive nesting."""
    try:
        result = json.loads(data, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise StreamProtocolError() from exc
    if not isinstance(result, dict):
        raise StreamProtocolError()
    try:
        bounded_json(result)
    except RequestRejected as exc:
        raise StreamProtocolError() from exc
    return result


@dataclass(frozen=True, slots=True)
class SSEEvent:
    event: str | None
    data: str
    heartbeat: bool = False


async def parse_sse(
    chunks: AsyncIterable[bytes], *, max_event_bytes: int = MAX_EVENT_BYTES
) -> AsyncIterator[SSEEvent]:
    if max_event_bytes < 1:
        raise ValueError("max_event_bytes must be positive")
    decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
    line: list[str] = []
    data: list[str] = []
    event: str | None = None
    frame_bytes = 0
    frame_seen = False
    skip_lf = False

    def take_line() -> SSEEvent | None:
        nonlocal event, frame_bytes, frame_seen
        current = "".join(line)
        line.clear()
        if not current:
            result = None
            if frame_seen:
                result = SSEEvent(event, "\n".join(data), heartbeat=not data and event is None)
                if event is not None and not data:
                    raise StreamProtocolError()
            data.clear()
            event = None
            frame_bytes = 0
            frame_seen = False
            return result
        frame_seen = True
        if current.startswith(":"):
            return None
        field, separator, value = current.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field == "data":
            data.append(value)
        elif field == "event" and event is None and value:
            event = value
        else:
            # Replay IDs/retry controls are not part of the stateless contract.
            raise StreamProtocolError()
        return None

    try:
        async for chunk in chunks:
            if not isinstance(chunk, bytes):
                raise StreamProtocolError()
            for offset in range(0, len(chunk), 8192):
                decoded = decoder.decode(chunk[offset : offset + 8192])
                for char in decoded:
                    if skip_lf:
                        skip_lf = False
                        if char == "\n":
                            continue
                    # Charge both CRLF bytes at CR, before dispatching a frame.
                    # A bare CR is conservatively charged the same two bytes.
                    frame_bytes += 2 if char == "\r" else len(char.encode("utf-8"))
                    if frame_bytes > max_event_bytes:
                        raise StreamProtocolError("provider_event_too_large")
                    if char in "\r\n":
                        skip_lf = char == "\r"
                        parsed = take_line()
                        if parsed is not None:
                            yield parsed
                    else:
                        line.append(char)
        decoder.decode(b"", final=True)
    except UnicodeError as exc:
        raise StreamProtocolError() from exc
    if line or frame_seen or data or event is not None:
        raise StreamProtocolError("truncated_provider_stream")


def encode_event(payload: dict[str, Any], event: str | None = None) -> bytes:
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    prefix = f"event: {event}\n" if event is not None else ""
    return f"{prefix}data: {data}\n\n".encode()
