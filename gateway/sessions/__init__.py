"""Client-owned inspectable history with principal-scoped session identities."""

from gateway.sessions.scope import SessionScopeError, session_scope

__all__ = ["SessionScopeError", "session_scope"]
