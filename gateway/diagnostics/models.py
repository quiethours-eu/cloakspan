"""Versioned diagnostic report types."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

CheckStatus = Literal["pass", "warn", "fail", "skip"]


@dataclass(frozen=True, slots=True)
class CheckResult:
    id: str
    status: CheckStatus
    summary: str
    remediation: str | None = None
    details: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {key: value for key, value in asdict(self).items() if value is not None}


@dataclass(frozen=True, slots=True)
class DoctorReport:
    gateway_version: str
    environment: str
    routing_mode: str
    coverage: tuple[dict[str, object], ...]
    checks: tuple[CheckResult, ...]
    schema_version: int = 1

    @property
    def counts(self) -> dict[str, int]:
        return {
            status: sum(check.status == status for check in self.checks)
            for status in ("pass", "warn", "fail", "skip")
        }

    @property
    def status(self) -> str:
        if self.counts["fail"]:
            return "error"
        if self.counts["warn"]:
            return "warning"
        return "ok"

    def exit_code(self, *, strict: bool = False) -> int:
        return int(bool(self.counts["fail"] or strict and self.counts["warn"]))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "gateway_version": self.gateway_version,
            "environment": self.environment,
            "routing_mode": self.routing_mode,
            "status": self.status,
            "counts": self.counts,
            "coverage": list(self.coverage),
            "checks": [check.to_dict() for check in self.checks],
        }
