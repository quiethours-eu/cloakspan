"""Output rendering; all supplied fields originate from safe diagnostic checks."""

from __future__ import annotations

import json

from gateway.diagnostics.models import DoctorReport


def render_json(report: DoctorReport) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def render_text(report: DoctorReport) -> str:
    lines = [
        f"Cloakspan doctor: {report.status} "
        f"({report.counts['fail']} failed, {report.counts['warn']} warnings, "
        f"{report.counts['skip']} skipped)",
        f"Environment: {report.environment}; routing: {report.routing_mode}",
    ]
    for check in report.checks:
        lines.append(f"[{check.status.upper()}] {check.id}: {check.summary}")
        if check.remediation:
            lines.append(f"  {check.remediation}")
    return "\n".join(lines)
