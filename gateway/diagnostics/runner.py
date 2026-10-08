"""Doctor orchestration."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace

from gateway.config import Settings
from gateway.diagnostics.agent_checks import agent_checks
from gateway.diagnostics.checks import inspect_offline
from gateway.diagnostics.models import CheckResult, DoctorReport
from gateway.diagnostics.probes import load_model, probe_providers


def run_doctor(
    env: Mapping[str, str],
    *,
    load_ner_model: bool = False,
    probe: bool = False,
    timeout: float = 5.0,
) -> DoctorReport:
    offline = inspect_offline(env)
    checks = list(offline.report.checks)
    checks.extend(agent_checks(Settings.from_mapping(env, for_diagnostics=True)))
    coverage = list(offline.report.coverage)
    if load_ner_model:
        ner_index = next(index for index, check in enumerate(checks) if check.id == "detection.ner")
        ner = checks[ner_index]
        if offline.model_path and ner.status == "pass":
            model_check = load_model(offline.model_path)
            checks.append(model_check)
            if model_check.details:
                checks[ner_index] = replace(ner, details={**ner.details, "runtime_loaded": True})
                coverage = [
                    {
                        **item,
                        "runtime_verified": True,
                        "backend_mapped_entities": model_check.details["backend_mapped_entities"],
                        "observed_smoke_entities": model_check.details["observed_smoke_entities"],
                    }
                    if item.get("name") == "ner"
                    else item
                    for item in coverage
                ]
        else:
            checks.append(
                CheckResult(
                    "detection.model_load",
                    "skip",
                    "Model load needs a verified configured NER model",
                    "Resolve detection.ner before using --load-model.",
                )
            )
    else:
        checks.append(
            CheckResult(
                "detection.model_load",
                "skip",
                "Model backend was not loaded",
                "Use --load-model for a supervised runtime smoke check.",
            )
        )

    if probe:
        checks.extend(probe_providers(offline.probe_destinations, env, timeout))
        if not offline.probe_destinations:
            checks.append(
                CheckResult(
                    "provider.probes",
                    "skip",
                    "No valid effective provider to probe",
                    "Resolve routing and egress checks first.",
                )
            )
    else:
        checks.append(
            CheckResult(
                "provider.probes",
                "skip",
                "Provider traffic was not requested",
                "Use --probe-providers to enable DNS and GET /models probes.",
            )
        )
    return replace(offline.report, coverage=tuple(coverage), checks=tuple(checks))
