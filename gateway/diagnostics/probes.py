"""Bounded subprocess supervision for optional doctor checks."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from collections.abc import Mapping

from gateway.diagnostics.checks import Destination
from gateway.diagnostics.models import CheckResult


def _worker(payload: dict[str, object], timeout: float) -> dict[str, object]:
    try:
        result = subprocess.run(  # noqa: S603 - fixed interpreter and module
            [sys.executable, "-m", "gateway.diagnostics.worker"],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"outcome": "timeout"}
    if result.returncode != 0:
        return {"outcome": "worker_failed"}
    try:
        report = json.loads(result.stdout.splitlines()[-1])
    except (IndexError, ValueError):
        return {"outcome": "worker_failed"}
    return report if isinstance(report, dict) else {"outcome": "worker_failed"}


def load_model(path: str) -> CheckResult:
    outcome = _worker({"operation": "model", "path": path}, 60)
    if outcome.get("outcome") == "loaded":
        allowed = {"PERSON", "ORG", "LOCATION", "ADDRESS"}

        def safe_entities(key: str) -> list[str]:
            raw = outcome.get(key)
            return (
                sorted(set(raw) & allowed)
                if isinstance(raw, list) and all(isinstance(item, str) for item in raw)
                else []
            )

        mapped = safe_entities("backend_mapped_entities")
        observed = safe_entities("observed_smoke_entities")
        return CheckResult(
            "detection.model_load",
            "warn" if not mapped else "pass",
            "NER backend loaded but exposes no mapped labels"
            if not mapped
            else "NER backend loaded and smoke check finished",
            "Review the model's NER labels and LABEL_MAP." if not mapped else None,
            details={
                "backend_mapped_entities": mapped,
                "observed_smoke_entities": observed,
            },
        )
    status = "fail"
    summary = (
        "NER model load exceeded 60 seconds"
        if outcome.get("outcome") == "timeout"
        else "NER backend dependency is unavailable"
        if outcome.get("outcome") == "dependency_missing"
        else "NER model backend failed to load or run"
    )
    return CheckResult(
        "detection.model_load",
        status,
        summary,
        "Check the [ner] dependency and the configured model backend.",
    )


def probe_providers(
    destinations: tuple[Destination, ...], env: Mapping[str, str], timeout: float
) -> list[CheckResult]:
    checks: list[CheckResult] = []
    deadline = time.monotonic() + 15.0
    for destination in destinations:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            checks.append(
                CheckResult(
                    f"provider.{destination.name}",
                    "fail",
                    "Overall 15-second probe budget expired",
                    "Retry --probe-providers when the destination is responsive.",
                )
            )
            continue
        trust_proxy = env.get("SAG_TRUST_ENV_PROXY", "").lower() in {"1", "true", "yes"}
        if destination.name == "local" and env.get("SAG_LOCAL_ROUTING", "off").lower() != "off":
            trust_proxy = False
        outcome = _worker(
            {
                "operation": "probe",
                "name": destination.name,
                "url": destination.base_url,
                "api_key": destination.api_key,
                "allowed_hosts": sorted(destination.policy.allowed_hosts),
                "allow_private": destination.policy.allow_private,
                "require_private_network": destination.policy.require_private_network,
                "trust_env": trust_proxy,
                "trust_env_certs": env.get("SAG_TRUST_ENV_PROXY", "").lower()
                in {"1", "true", "yes"},
                "timeout": min(timeout, remaining),
            },
            min(timeout, remaining),
        )
        code = outcome.get("outcome")
        if code == "listed":
            checks.append(
                CheckResult(
                    f"provider.{destination.name}",
                    "pass",
                    "GET /models succeeded",
                    details={"endpoint_only": True},
                )
            )
        elif code == "listing_unsupported":
            checks.append(
                CheckResult(
                    f"provider.{destination.name}",
                    "warn",
                    "Provider does not support GET /models",
                    "Check provider compatibility separately; inference was not tested.",
                )
            )
        elif code == "auth_rejected":
            checks.append(
                CheckResult(
                    f"provider.{destination.name}",
                    "fail",
                    "Provider rejected configured credentials",
                    f"Check the {destination.name} provider credentials.",
                )
            )
        else:
            summaries = {
                "egress_blocked": "Destination DNS or egress validation failed",
                "timeout": "Provider probe timed out",
                "oversized": "Provider listing exceeded 64 KiB",
                "redirect": "Provider listing redirected",
                "connection_failed": "Provider connection failed",
                "http_error": "Provider listing returned an error",
                "worker_failed": "Provider probe worker failed",
            }
            checks.append(
                CheckResult(
                    f"provider.{destination.name}",
                    "fail",
                    summaries.get(code, "Provider probe failed"),
                    "Check destination DNS, TLS, egress, and GET /models support.",
                )
            )
    return checks
