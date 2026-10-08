"""Incremental prose restoration with a suffix bounded by token grammar."""

from __future__ import annotations

import re

from gateway.domain import RequestContext
from gateway.restoration.engine import RestorationEngine, RestorationOutcome
from gateway.streaming.sse import StreamProtocolError
from gateway.transformations.tokens import TOKEN_FORMATS, TOKEN_PATTERN, TokenProvenance

# Extract the entity repetition bound from the actual matcher rather than a
# separately configured streaming limit that could drift from the grammar.
_width = re.search(r"\{0,(\d+)\}", TOKEN_PATTERN.pattern)
if _width is None:
    raise RuntimeError("unsupported token grammar")
ENTITY_WIDTH = 1 + int(_width.group(1))
MAX_TOKEN_LENGTH = (
    1
    + ENTITY_WIDTH
    + 1
    + max(len(version) + 1 + fmt.tag_hex_length + 1 for version, fmt in TOKEN_FORMATS.items())
)


def _possible_prefix(value: str) -> bool:
    if not value.startswith("<") or len(value) >= MAX_TOKEN_LENGTH:
        return False
    body = value[1:]
    if ":" not in body:
        return (
            not body or bool(re.fullmatch(r"[A-Z][A-Z0-9_]*", body)) and len(body) <= ENTITY_WIDTH
        )
    entity, _, rest = body.partition(":")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", entity) or len(entity) > ENTITY_WIDTH:
        return False
    if ":" not in rest:
        return any(version.startswith(rest) for version in TOKEN_FORMATS)
    version, _, tag = rest.partition(":")
    fmt = TOKEN_FORMATS.get(version)
    return (
        fmt is not None and len(tag) <= fmt.tag_hex_length and bool(re.fullmatch(r"[0-9a-f]*", tag))
    )


class IncrementalRestorer:
    """One independent text block; no token fragment leaves this object."""

    def __init__(
        self,
        ctx: RequestContext,
        provenance: TokenProvenance,
        restorer: RestorationEngine,
        outcome: RestorationOutcome,
        max_output_bytes: int,
    ) -> None:
        self.ctx = ctx
        self.provenance = provenance
        self.restorer = restorer
        self.outcome = outcome
        self.max_output_bytes = max_output_bytes
        self.suffix = ""
        self._raw: list[str] = []
        self._text: list[str] = []
        self._raw_bytes = 0
        self._text_bytes = 0
        self.closed = False

    @property
    def raw(self) -> str:
        return "".join(self._raw)

    @property
    def text(self) -> str:
        return "".join(self._text)

    def feed(self, delta: str, *, final: bool = False) -> str:
        if self.closed or not isinstance(delta, str):
            raise StreamProtocolError()
        self._raw_bytes += len(delta.encode("utf-8"))
        if delta:
            self._raw.append(delta)
        if self._raw_bytes > self.max_output_bytes:
            raise StreamProtocolError("provider_output_too_large")
        combined = self.suffix + delta
        self.suffix = ""
        if not final:
            start = combined.rfind("<", max(0, len(combined) - MAX_TOKEN_LENGTH))
            if start >= 0 and _possible_prefix(combined[start:]):
                self.suffix = combined[start:]
                combined = combined[:start]
        result = self.restorer.restore(
            self.ctx,
            combined,
            self.provenance,
            max_output_bytes=self.max_output_bytes - self._text_bytes,
        )
        self.outcome.merge(result)
        self._text_bytes += len(result.text.encode("utf-8"))
        if result.text:
            self._text.append(result.text)
        self.closed = final
        return result.text
