"""Process-local admission limits for the Chat Completions path.

Two controls, both deliberately simple and both per process:

* :class:`RateLimiter` -- a token bucket per authenticated API key. Buckets are
  created only for a key that has already authenticated, so the number of
  buckets is bounded by the configured keys, not by anything a client sends.
* :class:`ConcurrencyLimiter` -- a cap on admitted requests. When it is full a
  request is refused at once; there is no queue to grow.

Everything here runs on the event loop thread, so no lock is needed. Nothing
here is shared across processes or nodes, and nothing survives a restart.
"""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    """Token bucket per key id: ``per_minute`` requests, refilled continuously.

    The bucket holds at most one minute's allowance, so a key that has been
    idle can send that many at once; the concurrency cap, not this, bounds how
    many of them run simultaneously. ``per_minute`` of zero disables the limit.

    ``clock`` must be monotonic. It is injectable so tests advance time rather
    than sleep.
    """

    def __init__(self, per_minute: int, *, clock: Callable[[], float] = time.monotonic) -> None:
        if per_minute < 0:
            raise ValueError("per_minute cannot be negative")
        self.per_minute = per_minute
        self.clock = clock
        self._buckets: dict[str, _Bucket] = {}

    @property
    def enabled(self) -> bool:
        return self.per_minute > 0

    def acquire(self, key_id: str) -> float | None:
        """Take one request from ``key_id``'s bucket.

        Returns ``None`` when admitted, otherwise the seconds until the next
        request would be admitted. Call only with an authenticated key id.
        """
        if not self.enabled:
            return None
        now = self.clock()
        capacity = float(self.per_minute)
        refill_per_second = self.per_minute / 60.0
        bucket = self._buckets.get(key_id)
        if bucket is None:
            bucket = self._buckets[key_id] = _Bucket(tokens=capacity, updated=now)
        else:
            # max(): a clock that steps backwards must not mint tokens.
            elapsed = max(0.0, now - bucket.updated)
            bucket.tokens = min(capacity, bucket.tokens + elapsed * refill_per_second)
            bucket.updated = max(bucket.updated, now)
        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return None
        return (1.0 - bucket.tokens) / refill_per_second

    def refund(self, key_id: str) -> None:
        """Return one request taken by :meth:`acquire` that was not served.

        Only an existing bucket is credited, so this never creates one.
        """
        bucket = self._buckets.get(key_id)
        if bucket is not None:
            bucket.tokens = min(float(self.per_minute), bucket.tokens + 1.0)

    def __len__(self) -> int:
        return len(self._buckets)


def retry_after_header(seconds: float) -> str:
    """Whole seconds, rounded up, never zero: zero invites an immediate retry."""
    return str(max(1, math.ceil(seconds)))


class Slot:
    """One admitted request. Released exactly once, whichever way it ends."""

    __slots__ = ("_limiter", "_held", "_released")

    def __init__(self, limiter: ConcurrencyLimiter) -> None:
        self._limiter = limiter
        self._held = False
        self._released = False

    def release(self) -> None:
        """Return the slot, unless an overrun is still holding it."""
        if self._held:
            return
        self._free()

    def hold_until(self, work: asyncio.Future[Any]) -> None:
        """Keep the slot until ``work`` -- a detector still running -- finishes.

        The request has already been refused. The thread behind ``work`` cannot
        be interrupted, so it keeps occupying a worker until it returns; this
        keeps it counted, which is what stops one pathological input from being
        resubmitted into an unbounded number of busy threads.
        """
        if self._released or self._held:
            return
        self._held = True
        self._limiter.overruns += 1

        def finished(_: asyncio.Future[Any]) -> None:
            self._limiter.overruns -= 1
            self._held = False
            self._free()

        work.add_done_callback(finished)

    def _free(self) -> None:
        if self._released:
            return
        self._released = True
        self._limiter.active -= 1


class ConcurrencyLimiter:
    """Admit at most ``limit`` requests at once; refuse, never queue, beyond it."""

    def __init__(self, limit: int) -> None:
        if limit < 1:
            raise ValueError("the concurrency limit must be at least 1")
        self.limit = limit
        self.active = 0
        #: Admitted requests that have already been answered but whose detector
        #: thread is still running. Included in ``active``.
        self.overruns = 0

    def try_acquire(self) -> Slot | None:
        if self.active >= self.limit:
            return None
        self.active += 1
        return Slot(self)
