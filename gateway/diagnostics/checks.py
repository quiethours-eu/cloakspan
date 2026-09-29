"""Offline checks. No sockets, resource construction, inference, or writes."""

from __future__ import annotations

import importlib.metadata
import ipaddress
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from gateway.config import Settings
from gateway.config_validation import ParsedEnvironment, inspect_environment
from gateway.detectors.capabilities import builtin_capabilities
from gateway.detectors.ner import verify_model
from gateway.diagnostics.models import CheckResult, DoctorReport
from gateway.policy.engine import PolicyEngine
from gateway.policy.local_routing import LocalRouting
from gateway.routing.egress import EgressBlockedError, EgressPolicy, policy_for
from recognizers.custom.customer_rules import CustomRegexDetector, DictionaryDetector
from recognizers.custom.filters import FilterSet


@dataclass(frozen=True, slots=True)
class Destination:
    name: str
    base_url: str
    api_key: str
    policy: EgressPolicy


@dataclass(frozen=True, slots=True)
class OfflineResult:
    report: DoctorReport
    probe_destinations: tuple[Destination, ...]
    model_path: str | None


def _safe_destination(url: str) -> dict[str, object]:
    """Never show userinfo, path, query, fragment, or an invalid raw URL."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
        if not host or not re.fullmatch(r"[A-Za-z0-9.\-:\[\]]{1,253}", host):
            return {"configured": True}
        return {"scheme": parts.scheme, "host": host.lower(), "port": port}
    except ValueError:
        return {"configured": True}


def _version() -> str:
    try:
        return importlib.metadata.version("secure-ai-gateway")
    except importlib.metadata.PackageNotFoundError:
        return "0.1.0a1"


def inspect_offline(env: Mapping[str, str]) -> OfflineResult:
    parsed: ParsedEnvironment = inspect_environment(env)
    settings = Settings.from_mapping(dict(env), for_diagnostics=True)
    checks: list[CheckResult] = []
    coverage: list[dict[str, object]] = list(builtin_capabilities())
    destinations: list[Destination] = []

    checks.append(
        CheckResult(
            "runtime.python",
            "pass" if sys.version_info >= (3, 12) else "fail",
            "Python version is supported"
            if sys.version_info >= (3, 12)
            else "Python 3.12 or newer is required",
            None if sys.version_info >= (3, 12) else "Install Python 3.12 or newer.",
        )
    )
    checks.append(
        CheckResult("runtime.dependencies", "pass", "Required Python dependencies are importable")
    )
    seen_issues: set[str] = set()
    for issue in parsed.issues:
        if issue.id in seen_issues:
            continue
        seen_issues.add(issue.id)
        checks.append(CheckResult(issue.id, issue.status, issue.summary, issue.remediation))

    production = env.get("SAG_ENVIRONMENT", "").strip().lower() in {"prod", "production"}
    mode = parsed.routing
    if mode is not None:
        checks.append(
            CheckResult(
                "routing.mode", "pass", "Local routing mode parsed", details={"mode": mode.value}
            )
        )
    else:
        checks.append(
            CheckResult(
                "routing.mode",
                "skip",
                "Routing checks need a valid mode",
                "Set SAG_LOCAL_ROUTING to off, detected, or all.",
            )
        )

    policy = None
    try:
        policy = PolicyEngine.from_yaml(settings.policy_path)
    except Exception:
        checks.append(
            CheckResult(
                "policy.load",
                "fail",
                "Policy cannot be read or parsed",
                "Fix the file named by SAG_POLICY_PATH and its policy schema.",
            )
        )
    else:
        checks.append(
            CheckResult(
                "policy.load", "pass", "Policy loaded", details={"rule_count": len(policy.rules)}
            )
        )

    filters = None
    if settings.filters_path is None:
        checks.append(
            CheckResult(
                "filters.load",
                "skip",
                "No filter file configured",
                "Set SAG_FILTERS_PATH to enable operator filters.",
            )
        )
    else:
        try:
            filters = FilterSet.from_yaml(settings.filters_path)
        except Exception:
            checks.append(
                CheckResult(
                    "filters.load",
                    "fail",
                    "Filter file cannot be loaded",
                    "Fix the file named by SAG_FILTERS_PATH and its filter schema.",
                )
            )
        else:
            checks.append(
                CheckResult(
                    "filters.load",
                    "pass",
                    "Filter file loaded",
                    details={"enabled_count": len(filters.detectors)},
                )
            )
            coverage.extend(
                {
                    "name": f"operator_filter_{index + 1}",
                    "kind": "filter",
                    "matcher": "dictionary"
                    if isinstance(detector, DictionaryDetector)
                    else "regex",
                    "entities": [],
                }
                for index, detector in enumerate(filters.detectors)
            )

    if settings.dictionary_terms:
        coverage.append(
            {"name": "customer_dictionary", "kind": "custom", "entities": ["CUSTOMER_TERM"]}
        )
    custom_patterns_valid = True
    for index, (_entity, _pattern) in enumerate(settings.custom_patterns):
        try:
            CustomRegexDetector(_pattern, _entity)
        except ValueError:
            custom_patterns_valid = False
            continue
        # Entity labels can be operator secrets. Count configured legacy rules
        # without showing their source or label.
        coverage.append({"name": f"legacy_regex_{index + 1}", "kind": "custom", "entities": []})
    if not custom_patterns_valid:
        checks.append(
            CheckResult(
                "detection.custom_patterns",
                "fail",
                "A legacy custom pattern is invalid or unsafe",
                "Fix SAG_CUSTOM_PATTERNS or move rules to SAG_FILTERS_PATH.",
            )
        )

    ner_verified = False
    if not settings.ner_model_path:
        checks.append(
            CheckResult(
                "detection.ner",
                "warn",
                "Contextual NER is disabled",
                "Configure SAG_NER_MODEL_PATH to inspect contextual entities.",
                {"enabled": False},
            )
        )
    else:
        try:
            manifest = verify_model(Path(settings.ner_model_path))
        except Exception:
            checks.append(
                CheckResult(
                    "detection.ner",
                    "fail",
                    "NER model verification failed",
                    "Check SAG_NER_MODEL_PATH, its manifest, and file checksums.",
                    {"enabled": True, "manifest_verified": False},
                )
            )
        else:
            ner_verified = True
            declared_languages = [
                language
                for language in manifest.languages
                if isinstance(language, str) and re.fullmatch(r"[A-Za-z0-9-]{1,20}", language)
            ][:32]
            checks.append(
                CheckResult(
                    "detection.ner",
                    "pass",
                    "NER model manifest verified",
                    details={
                        "enabled": True,
                        "manifest_verified": True,
                        "declared_languages": declared_languages,
                        "runtime_loaded": False,
                    },
                )
            )
            coverage.append(
                {
                    "name": "ner",
                    "kind": "contextual",
                    "entities": [],
                    "possible_mapped_entities": ["PERSON", "ORG", "LOCATION", "ADDRESS"],
                    "declared_languages": declared_languages,
                    "runtime_verified": False,
                }
            )
    checks.append(
        CheckResult(
            "detection.inventory",
            "pass",
            "Configured detector inventory collected",
            details={"count": len(coverage)},
        )
    )

    if mode is LocalRouting.DETECTED and not ner_verified:
        checks.append(
            CheckResult(
                "routing.detected_coverage",
                "fail",
                "Detected-only routing requires verified NER",
                "Configure SAG_NER_MODEL_PATH or use SAG_LOCAL_ROUTING=all.",
            )
        )
    elif mode is LocalRouting.DETECTED:
        checks.append(
            CheckResult(
                "routing.detected_coverage",
                "warn",
                "Detected-only routing depends on detector coverage",
                "Evaluate detection accuracy for your actual data before use.",
            )
        )

    required: frozenset[str] | None = None
    if policy is None or (settings.filters_path is not None and filters is None) or mode is None:
        checks.append(
            CheckResult(
                "routing.policy",
                "skip",
                "Routing needs valid policy, filters, and mode",
                "Resolve policy.load, filters.load, and routing.mode first.",
            )
        )
    else:
        try:
            if filters is not None:
                policy = policy.with_rules(
                    filters.rules, version_suffix=f"filters:{filters.fingerprint}"
                )
            policy = policy.with_local_routing(mode)
            required = policy.required_destinations
        except Exception:
            checks.append(
                CheckResult(
                    "routing.policy",
                    "fail",
                    "Policy and filters conflict",
                    "Resolve duplicate names or invalid routing in policy and filters.",
                )
            )
        else:
            checks.append(
                CheckResult(
                    "routing.policy",
                    "pass",
                    "Effective routing composed",
                    details={
                        "required_destinations": sorted(required & {"external", "local", "mock"}),
                        "unknown_destination_count": len(required - {"external", "local", "mock"}),
                        "rule_count": len(policy.rules),
                        "effective_version": (
                            policy.version
                            if policy.version
                            in {
                                "community-default-v1",
                                "community-default-v1+local-routing:detected",
                                "community-default-v1+local-routing:all",
                            }
                            else "redacted"
                        ),
                    },
                )
            )

    if required is not None:
        known = {"external", "local", "mock"}
        if required - known:
            checks.append(
                CheckResult(
                    "routing.destinations",
                    "fail",
                    "Policy names an unknown destination",
                    "Use an available destination in the policy or filters.",
                )
            )
        else:
            missing = []
            if "local" in required and not settings.local_base_url:
                if production or mode is not LocalRouting.OFF:
                    missing.append("SAG_LOCAL_BASE_URL")
                else:
                    checks.append(
                        CheckResult(
                            "routing.local_mock",
                            "warn",
                            "Local destination uses the development mock",
                            "Configure SAG_LOCAL_BASE_URL for local model traffic.",
                        )
                    )
            if "external" in required and not settings.external_base_url:
                if production:
                    missing.append("SAG_EXTERNAL_BASE_URL")
                else:
                    checks.append(
                        CheckResult(
                            "routing.mock_fallback",
                            "warn",
                            "External destination uses the development mock",
                            "Configure SAG_EXTERNAL_BASE_URL for real provider traffic.",
                        )
                    )
            if production and "mock" in required:
                missing.append("a non-mock policy destination")
            if missing:
                checks.append(
                    CheckResult(
                        "routing.destinations",
                        "fail",
                        "Required provider destination is unavailable",
                        "Configure " + ", ".join(missing) + " or change the policy.",
                    )
                )
            else:
                checks.append(
                    CheckResult(
                        "routing.destinations", "pass", "Required destinations are configured"
                    )
                )

        for name in ("local", "external"):
            if name not in required:
                continue
            url = settings.local_base_url if name == "local" else settings.external_base_url
            if not url:
                continue
            egress = policy_for(
                name,
                allowed_hosts=frozenset(h.lower() for h in settings.egress_allowlist),
                allow_private_override=settings.egress_allow_private or None,
                require_private_network=name == "local" and mode is not LocalRouting.OFF,
            )
            try:
                egress.validate_offline(url)
            except EgressBlockedError:
                checks.append(
                    CheckResult(
                        f"egress.{name}.url",
                        "fail",
                        f"{name} destination fails offline egress validation",
                        f"Check SAG_{name.upper()}_BASE_URL and SAG_EGRESS_ALLOWLIST.",
                    )
                )
                continue
            checks.append(
                CheckResult(
                    f"egress.{name}.url",
                    "pass",
                    f"{name} destination passes offline URL checks",
                    details=_safe_destination(url),
                )
            )
            try:
                ipaddress.ip_address(urlsplit(url).hostname or "")
            except ValueError:
                checks.append(
                    CheckResult(
                        f"egress.{name}.dns",
                        "skip",
                        f"{name} hostname was not resolved offline",
                        "Use --probe-providers to resolve and probe this destination.",
                    )
                )
            destinations.append(
                Destination(
                    name, url, settings.external_api_key if name == "external" else "", egress
                )
            )

    if settings.egress_allow_private:
        checks.append(
            CheckResult(
                "egress.private_override",
                "warn",
                "Global private-address egress override is enabled",
                "Review SAG_EGRESS_ALLOW_PRIVATE and restrict destinations.",
            )
        )
    if settings.trust_env_proxy:
        checks.append(
            CheckResult(
                "egress.proxy",
                "warn",
                "Ambient proxy settings are enabled",
                "Review SAG_TRUST_ENV_PROXY and the process proxy environment.",
            )
        )

    checks.append(
        CheckResult(
            "operations.vault",
            "pass",
            "Vault mappings are process local",
            details={"restart_loses_mappings": True},
        )
    )
    checks.append(
        CheckResult(
            "operations.bind",
            "pass",
            "Gateway bind address is process context only",
            details={
                "bind_all_interfaces": settings.bind_host in {"0.0.0.0", "::"},  # noqa: S104
                "host_publication_verified": False,
            },
        )
    )

    declared_environment = env.get("SAG_ENVIRONMENT", "").strip().lower()
    environment = (
        "production"
        if production
        else "invalid"
        if any(issue.id == "settings.environment" for issue in parsed.issues)
        else "test"
        if declared_environment in {"test", "testing"}
        else "development"
    )
    if mode is LocalRouting.DETECTED and not ner_verified:
        destinations = []

    report = DoctorReport(
        _version(), environment, mode.value if mode else "invalid", tuple(coverage), tuple(checks)
    )
    return OfflineResult(report, tuple(destinations), settings.ner_model_path or None)
