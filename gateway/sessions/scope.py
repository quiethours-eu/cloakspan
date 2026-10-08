"""Derive stable namespaces without persisting transcripts or authorization sets."""

from __future__ import annotations

import hashlib
import re
import uuid

from gateway.auth.keys import ApiKey
from gateway.domain import RequestContext
from gateway.transformations.tokens import length_prefixed

_SESSION = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")


class SessionScopeError(Exception):
    """An invalid or conflicting client session identity was presented."""


def session_scope(
    key: ApiKey, identities: list[str | None], *, agent_id: str | None = None
) -> tuple[str, str]:
    """A guessed header never selects another principal's vault namespace.

    Key IDs represent principals in the current single-node credential contract.
    Key rotation must preserve the key ID to preserve scope. Forks use new session
    IDs and replay original history; they inherit no restoration authorization.
    """
    supplied = [identity for identity in identities if identity is not None]
    if any(not _SESSION.fullmatch(identity) for identity in supplied):
        raise SessionScopeError("Use an ASCII session ID of 1 to 128 letters, digits, '_' or '-'.")
    if len(set(supplied)) > 1:
        raise SessionScopeError("Send one consistent session ID across session headers.")
    identity = supplied[0] if supplied else f"session_{uuid.uuid4().hex}"
    if agent_id is not None and not _SESSION.fullmatch(agent_id):
        raise SessionScopeError("Use an ASCII agent ID of 1 to 128 letters, digits, '_' or '-'.")
    namespace = length_prefixed("agent-session-v1", key.tenant_id, key.key_id, identity)
    if agent_id is not None:
        namespace = length_prefixed("agent-subagent-v1", namespace.hex(), agent_id)
    digest = hashlib.sha256(namespace)
    return identity, "agent_" + digest.hexdigest()


def scoped_cache_key(
    ctx: RequestContext,
    protocol: str,
    model: str,
    destination: str,
    policy_version: str,
    identity: str,
) -> str:
    """Keep native caching stable without exporting client or principal identifiers."""
    return (
        "cache_"
        + hashlib.sha256(
            length_prefixed(
                "agent-cache-v1",
                ctx.tenant_id,
                ctx.api_key_id,
                ctx.conversation_id,
                protocol,
                model,
                destination,
                policy_version,
                identity,
            )
        ).hexdigest()
    )
