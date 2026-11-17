"""Counters and gauges in the Prometheus text exposition format, hand-rolled.

No client library: the runtime dependency set is hash-pinned and this needs
none of it. The format is small and stable -- see
https://prometheus.io/docs/instrumenting/exposition_formats/.

**Every label value comes from a closed set fixed in this module.** A value
outside that set is recorded as ``other``. No tenant, key, model, conversation,
path, or any other client-supplied or operator-supplied string can become a
label, so the metrics surface cannot become a copy of request content
(security invariant SI-11) and cannot grow per distinct client value.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from gateway.audit.reasons import ReasonCode
from gateway.domain import Action

logger = logging.getLogger("gateway.metrics")

OTHER = "other"

ROUTES = frozenset({"chat_completions"})
STATUS_CLASSES = frozenset({"2xx", "4xx", "5xx", "none"})
DECISIONS = frozenset({action.value for action in Action} | {"none"})
DESTINATIONS = frozenset({"external", "local", "mock", "none"})
REASONS = frozenset(reason.value for reason in ReasonCode)
TOKEN_REFUSAL_REASONS = frozenset({"not_minted", "vault_miss", "cross_tenant", "key_unavailable"})


@dataclass(frozen=True, slots=True)
class _Family:
    name: str
    kind: str  # "counter" or "gauge"
    help: str
    labels: tuple[tuple[str, frozenset[str]], ...] = ()


_FAMILIES = (
    _Family(
        "cloakspan_requests_total",
        "counter",
        "Requests that reached a terminal outcome, by route, status class, "
        "policy decision and destination.",
        (
            ("route", ROUTES),
            ("status_class", STATUS_CLASSES),
            ("decision", DECISIONS),
            ("destination", DESTINATIONS),
        ),
    ),
    _Family(
        "cloakspan_request_refusals_total",
        "counter",
        "Requests that ended without a successful response, by stable reason code.",
        (("route", ROUTES), ("reason", REASONS)),
    ),
    _Family(
        "cloakspan_tokens_restored_total",
        "counter",
        "Tokens restored into successful responses.",
    ),
    _Family(
        "cloakspan_tokens_refused_total",
        "counter",
        "Tokens left unrestored in successful responses, by refusal reason.",
        (("reason", TOKEN_REFUSAL_REASONS),),
    ),
)

_GAUGES = (
    _Family(
        "cloakspan_requests_in_flight",
        "gauge",
        "Admitted requests currently holding a concurrency slot, including "
        "answered requests whose detector thread is still running.",
        (("route", ROUTES),),
    ),
    _Family(
        "cloakspan_max_concurrent_requests",
        "gauge",
        "Configured concurrency cap.",
        (("route", ROUTES),),
    ),
    _Family(
        "cloakspan_detector_overruns_in_flight",
        "gauge",
        "Detector threads still running after their request timed out or was "
        "cancelled. Each keeps holding a concurrency slot.",
        (("route", ROUTES),),
    ),
)

_BY_NAME = {family.name: family for family in (*_FAMILIES, *_GAUGES)}


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(family: _Family, given: Mapping[str, str]) -> tuple[str, ...]:
    if set(given) != {name for name, _ in family.labels}:
        raise ValueError(f"{family.name} takes labels {[n for n, _ in family.labels]}")
    return tuple(
        value if (value := str(given[name])) in allowed else OTHER
        for name, allowed in family.labels
    )


def status_class(status: int | None) -> str:
    if status is None:
        return "none"
    return f"{status // 100}xx" if 200 <= status < 600 else OTHER


class Metrics:
    """In-process counters, plus gauges read from callbacks at render time."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[str, ...]], float] = {}
        self._gauges: dict[tuple[str, tuple[str, ...]], Callable[[], float]] = {}

    def inc(self, name: str, amount: float = 1.0, **labels: str) -> None:
        family = _BY_NAME[name]
        if family.kind != "counter" or amount < 0:
            raise ValueError(f"{name} is not a counter, or the increment is negative")
        key = (name, _labels(family, labels))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0.0) + amount

    def gauge(self, name: str, read: Callable[[], float], **labels: str) -> None:
        family = _BY_NAME[name]
        if family.kind != "gauge":
            raise ValueError(f"{name} is not a gauge")
        self._gauges[(name, _labels(family, labels))] = read

    def value(self, name: str, **labels: str) -> float:
        """A counter's current value. For tests and diagnostics."""
        family = _BY_NAME[name]
        return self._counters.get((name, _labels(family, labels)), 0.0)

    def render(self) -> str:
        with self._lock:
            counters = dict(self._counters)
        gauges: dict[tuple[str, tuple[str, ...]], float] = {}
        for key, read in self._gauges.items():
            try:
                gauges[key] = float(read())
            except Exception:  # a broken gauge must not break the scrape
                logger.exception("metrics gauge %s could not be read", key[0])
        lines: list[str] = []
        for family in (*_FAMILIES, *_GAUGES):
            samples = counters if family.kind == "counter" else gauges
            lines.append(f"# HELP {family.name} {family.help}")
            lines.append(f"# TYPE {family.name} {family.kind}")
            for (name, values), sample in sorted(samples.items()):
                if name != family.name:
                    continue
                lines.append(_sample(family, values, sample))
        return "\n".join(lines) + "\n"


def _sample(family: _Family, values: Iterable[str], sample: float) -> str:
    rendered = ",".join(
        f'{name}="{_escape(value)}"' for (name, _), value in zip(family.labels, values, strict=True)
    )
    number = repr(float(sample)) if sample != int(sample) else str(int(sample))
    return f"{family.name}{{{rendered}}} {number}" if rendered else f"{family.name} {number}"


def token_matches(presented: str, expected: str) -> bool:
    """Constant-time comparison that also hides the expected token's length."""
    if not presented or not expected:
        return False
    return hmac.compare_digest(
        hashlib.sha256(presented.encode("utf-8")).digest(),
        hashlib.sha256(expected.encode("utf-8")).digest(),
    )
