"""Audit events.

The defining property: **an audit event never contains raw prompt content, and
never contains provider credentials.** Security invariants SI-11 and SI-12; see
docs/security-invariants.md.

This is enforced structurally rather than by review discipline. The event is a
closed dataclass with an explicit field list -- there is no ``extra`` dict and
no ``**kwargs`` through which a well-meaning future change could smuggle prompt
text into the log. ``tests/test_audit_no_raw_content.py`` additionally asserts
that a canary value present in a request never appears in the serialised event.

Note what *is* recorded: entity **counts** and **types**, never values. That is
enough to answer "was personal data sent to this provider?" -- the question a
regulator asks -- without the audit log becoming a second copy of the data.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from gateway.domain import PolicyDecision, RequestContext

logger = logging.getLogger("gateway.audit")


#: Audit schema version. Bump on any field addition, removal, or semantic
#: change, so a downstream consumer can tell which shape it is parsing rather
#: than inferring it from which keys happen to be present.
AUDIT_SCHEMA_VERSION = 3


@dataclass(frozen=True, slots=True)
class AuditEvent:
    schema_version: int
    request_id: str
    tenant_id: str
    conversation_id: str
    api_key_id: str
    application: str
    timestamp: float

    model_requested: str
    destination: str
    provider: str

    decision: str
    rule_name: str
    policy_version: str

    entity_counts: dict[str, int] = field(default_factory=dict)
    #: Deceptive-encoding findings keyed by reason code: bidi controls,
    #: invisible characters, confusables, mixed script. Counts only -- a log
    #: that quoted the payload would make this class of attack a way to write
    #: attacker-controlled strings into our logs.
    encoding_signals: dict[str, int] = field(default_factory=dict)
    entities_transformed: int = 0

    restoration_performed: bool = False
    tokens_restored: int = 0
    tokens_refused: int = 0
    #: Refusal counts keyed by reason: not_minted, vault_miss, cross_tenant,
    #: key_unavailable. Counts only -- no token strings, no values. Without the
    #: breakdown, an empty vault after a restart and an attacker enumerating
    #: tokens produce the identical signal, which makes the signal unalertable.
    tokens_refused_by_reason: dict[str, int] = field(default_factory=dict)

    raw_content_logged: bool = False
    latency_ms: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False)


class AuditSink(Protocol):
    def write(self, event: AuditEvent) -> None: ...


class JsonLogSink:
    """Writes audit events as structured JSON to the standard logger."""

    def write(self, event: AuditEvent) -> None:
        logger.info("audit", extra={"audit_event": event.to_dict()})
        print(event.to_json(), flush=True)  # noqa: T201 - the audit stream is stdout by design


class MemorySink:
    """Collects events in memory. Used by tests and the demo."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)


def build_event(
    ctx: RequestContext,
    *,
    model_requested: str,
    decision: PolicyDecision,
    provider: str,
    entity_counts: dict[str, int],
    encoding_signals: dict[str, int] | None = None,
    entities_transformed: int = 0,
    restoration_performed: bool = False,
    tokens_restored: int = 0,
    tokens_refused: int = 0,
    tokens_refused_by_reason: dict[str, int] | None = None,
    latency_ms: float = 0.0,
    error: str | None = None,
) -> AuditEvent:
    return AuditEvent(
        schema_version=AUDIT_SCHEMA_VERSION,
        request_id=ctx.request_id,
        tenant_id=ctx.tenant_id,
        conversation_id=ctx.conversation_id,
        api_key_id=ctx.api_key_id,
        application=ctx.application,
        timestamp=time.time(),
        model_requested=model_requested,
        destination=decision.destination,
        provider=provider,
        decision=decision.action.value,
        rule_name=decision.rule_name,
        policy_version=decision.policy_version,
        entity_counts=dict(entity_counts),
        encoding_signals=dict(encoding_signals or {}),
        entities_transformed=entities_transformed,
        restoration_performed=restoration_performed,
        tokens_restored=tokens_restored,
        tokens_refused=tokens_refused,
        tokens_refused_by_reason=dict(tokens_refused_by_reason or {}),
        raw_content_logged=False,
        latency_ms=latency_ms,
        error=error,
    )
