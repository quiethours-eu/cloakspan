"""Offline configuration checks; enabling a flag never implies client qualification."""

from __future__ import annotations

from pathlib import Path

from gateway.config import Settings
from gateway.diagnostics.models import CheckResult


def agent_checks(settings: Settings) -> list[CheckResult]:
    if not (settings.enable_responses or settings.enable_messages):
        return []
    root = Path(settings.agent_workspace_root)
    valid_root = bool(settings.agent_workspace_root) and root.is_absolute() and root.is_dir()
    checks = [
        CheckResult(
            "agent.workspace",
            "pass" if valid_root else "fail",
            "Agent tool workspace is configured"
            if valid_root
            else "Agent tool workspace is missing",
            None
            if valid_root
            else "Set SAG_AGENT_WORKSPACE_ROOT to an existing absolute directory.",
        ),
        CheckResult(
            "agent.qualification",
            "warn",
            "Agent protocols are experimental and clients are unqualified",
            "Complete the pinned client, desktop, compaction and resume gates "
            "in docs/agent-compatibility.md.",
        ),
        CheckResult(
            "agent.continuation",
            "pass",
            "Only inspectable client history is supported",
            details={"stored_state": False, "opaque_compaction": False, "websockets": False},
        ),
        CheckResult(
            "agent.resource_limits",
            "pass",
            "Agent work has isolated detectors and bounded streams",
            details={
                "max_concurrent": settings.agent_max_concurrent,
                "detector_deadline_seconds": settings.agent_detector_timeout_seconds,
                "stream_idle_seconds": settings.agent_stream_idle_seconds,
                "stream_total_seconds": settings.agent_stream_total_seconds,
                "max_event_bytes": settings.agent_max_event_bytes,
                "max_output_bytes": settings.agent_max_output_bytes,
            },
        ),
    ]
    if (
        settings.enable_messages
        and not settings.messages_base_url
        and settings.local_routing.value != "all"
    ):
        checks.append(
            CheckResult(
                "agent.messages_provider",
                "warn",
                "Native Messages external provider is unset",
                "Set SAG_MESSAGES_BASE_URL and gateway-held upstream credentials; "
                "production refuses a selected mock destination.",
            )
        )
    return checks
