"""Stable reason codes for terminal request outcomes.

One closed vocabulary, shared by the audit stream (``AuditEvent.error``), the
HTTP error envelope where a code is new, and metric labels. A reason code is a
fixed string chosen by the gateway: never an exception message, never a value a
client sent. That is what makes it safe to write into the audit log and to use
as a metric label (security invariant SI-11).
"""

from __future__ import annotations

import asyncio
import enum

from gateway.inspection.preparation import DetectionError, DetectorTimeoutError
from gateway.normalization import SuspiciousEncodingError
from gateway.policy.local_routing import LocalRoutingViolation
from gateway.routing.base import ProviderError
from gateway.routing.egress import EgressBlockedError
from gateway.vault.store import VaultError


class ReasonCode(enum.StrEnum):
    """Why a request ended without a successful response."""

    # Authentication and admission, before the body is read.
    INVALID_API_KEY = "invalid_api_key"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    CAPACITY_EXCEEDED = "capacity_exceeded"
    RESERVED_CONVERSATION_SCOPE = "reserved_conversation_scope"

    # The request body and its contract.
    REQUEST_TOO_LARGE = "request_too_large"
    REQUEST_TIMEOUT = "request_timeout"
    INVALID_JSON = "invalid_json"
    MODEL_NOT_ALLOWED = "model_not_allowed"
    INVALID_REQUEST = "invalid_request"
    STREAMING_UNSUPPORTED = "streaming_unsupported"
    UNKNOWN_FIELD = "unknown_field"
    UNINSPECTABLE_FIELD = "uninspectable_field"
    UNSUPPORTED_ROLE = "unsupported_role"
    INVALID_MESSAGE = "invalid_message"

    # Inspection and policy.
    BLOCKED_BY_POLICY = "blocked_by_policy"
    INSPECTION_FAILED = "inspection_failed"
    DETECTOR_TIMEOUT = "detector_timeout"
    SUSPICIOUS_ENCODING_BIDI = "suspicious_encoding_bidi"
    SUSPICIOUS_ENCODING_INVISIBLE = "suspicious_encoding_invisible"
    SUSPICIOUS_ENCODING_MIXED_SCRIPT = "suspicious_encoding_mixed_script"
    SUSPICIOUS_ENCODING_CONFUSABLE = "suspicious_encoding_confusable"
    LOCAL_ROUTING_VIOLATION = "local_routing_violation"
    VAULT_ERROR = "vault_error"

    # Egress, the provider, and restoration.
    EGRESS_BLOCKED = "egress_blocked"
    DESTINATION_UNAVAILABLE = "destination_unavailable"
    PROVIDER_TIMEOUT = "provider_timeout"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    PROVIDER_ERROR = "provider_error"
    PROVIDER_BAD_RESPONSE = "provider_bad_response"
    RESTORATION_REFUSED = "restoration_refused"

    # Everything else.
    CANCELLED = "cancelled"
    INTERNAL_ERROR = "internal_error"


#: The values a client-facing ``RequestRejected.code`` can take on the Chat
#: Completions path. Anything else maps to ``invalid_request`` rather than being
#: copied into the audit log.
_CONTRACT_CODES = frozenset(
    {
        ReasonCode.INVALID_REQUEST,
        ReasonCode.STREAMING_UNSUPPORTED,
        ReasonCode.UNKNOWN_FIELD,
        ReasonCode.UNINSPECTABLE_FIELD,
        ReasonCode.UNSUPPORTED_ROLE,
        ReasonCode.INVALID_MESSAGE,
        ReasonCode.INSPECTION_FAILED,
    }
)


def contract_reason(code: str) -> ReasonCode:
    """Map a request-contract rejection code onto the closed vocabulary."""
    try:
        reason = ReasonCode(code)
    except ValueError:
        return ReasonCode.INVALID_REQUEST
    return reason if reason in _CONTRACT_CODES else ReasonCode.INVALID_REQUEST


def reason_for_exception(exc: BaseException) -> ReasonCode:
    """Classify an exception that ended a request. Never reads its message."""
    if isinstance(exc, asyncio.CancelledError):
        return ReasonCode.CANCELLED
    if isinstance(exc, DetectorTimeoutError):
        return ReasonCode.DETECTOR_TIMEOUT
    if isinstance(exc, SuspiciousEncodingError):
        try:
            return ReasonCode(exc.reason)
        except ValueError:
            return ReasonCode.INSPECTION_FAILED
    if isinstance(exc, DetectionError):
        return ReasonCode.INSPECTION_FAILED
    if isinstance(exc, LocalRoutingViolation):
        return ReasonCode.LOCAL_ROUTING_VIOLATION
    if isinstance(exc, EgressBlockedError):
        return ReasonCode.EGRESS_BLOCKED
    if isinstance(exc, ProviderError):
        try:
            return ReasonCode(exc.reason)
        except ValueError:
            return ReasonCode.PROVIDER_ERROR
    if isinstance(exc, VaultError):
        return ReasonCode.VAULT_ERROR
    return ReasonCode.INTERNAL_ERROR
