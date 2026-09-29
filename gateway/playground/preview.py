"""Provider-free preview assembly and safe capability descriptions."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gateway.api.schema import parse_chat_completion_request
from gateway.config import Settings, load_policy_and_filters
from gateway.detectors.ner import describe_availability
from gateway.domain import RequestContext
from gateway.inspection.preparation import PreparationService
from gateway.policy.engine import PolicyEngine
from gateway.policy.local_routing import LocalRouting
from gateway.routing.base import resolve_model
from gateway.transformations.engine import TransformationEngine
from gateway.transformations.tokens import TokenMinter
from gateway.vault.store import KeyRing, SurrogateVault

PLACEHOLDER_MODEL = "preview-model"
MAX_TEXT_CHARS = 16_384
MAX_BODY_BYTES = 256 * 1024
MAX_RESULT_BYTES = 1024 * 1024


def preview_limits(settings: Settings) -> dict[str, int]:
    return {
        "request_bytes": min(MAX_BODY_BYTES, settings.max_request_bytes),
        "text_chars": min(MAX_TEXT_CHARS, settings.max_input_chars),
        "result_bytes": MAX_RESULT_BYTES,
    }


def _file_fingerprint(path: Path | None) -> bytes:
    return path.read_bytes() if path is not None else b""


@dataclass(frozen=True, slots=True)
class PreviewConfiguration:
    fingerprint: str
    policy_version: str
    applications: tuple[str, ...]
    coverage: dict[str, Any]
    warnings: tuple[str, ...]
    limits: dict[str, int]
    routing_mode: str


def describe_preview(settings: Settings) -> PreviewConfiguration:
    """Read policy and model metadata without creating providers or secret keys."""
    if settings.max_input_chars < 1 or settings.max_request_bytes < 1:
        raise ValueError("Gateway input limits must be positive.")
    policy, filters = load_policy_and_filters(settings)
    applications = tuple(sorted({"default"} | {a for r in policy.rules for a in r.applications}))
    ner = describe_availability(settings.ner_model_path or None)
    if ner.get("enabled") and not ner.get("usable"):
        raise ValueError("The enabled NER model is unavailable; check SAG_NER_MODEL_PATH.")
    if settings.local_routing is LocalRouting.DETECTED and not ner.get("enabled"):
        raise ValueError("SAG_LOCAL_ROUTING=detected requires a configured NER model.")
    fingerprint = hashlib.sha256(
        b"cloakspan-preview-v1\0"
        + _file_fingerprint(settings.policy_path)
        + b"\0"
        + _file_fingerprint(settings.filters_path)
        + b"\0"
        + str(settings.local_routing).encode()
    ).hexdigest()[:16]
    builtins = (
        "secrets",
        "email",
        "Baltic personal codes",
        "phone numbers",
        "IBAN",
        "payment cards",
        "IPv4 addresses",
    )
    coverage = {
        "profile": "contextual NER enabled" if ner.get("enabled") else "deterministic only",
        "built_in": list(builtins),
        "custom_filters": len(filters.detectors) if filters is not None else 0,
        "legacy_dictionary": bool(settings.dictionary_terms),
        "legacy_patterns": len(settings.custom_patterns),
        "contextual_ner": bool(ner.get("enabled")),
        "ner_languages_declared": ner.get("languages", []),
    }
    warnings = []
    if not ner.get("enabled"):
        warnings.append(
            "Contextual detection is unavailable: names, organisations, "
            "places and addresses may be missed."
        )
    warnings.append(
        "Detection coverage depends on enabled detectors; no-match is not a safety verdict."
    )
    warnings.append("Destination availability and deployment readiness are not checked.")
    if settings.local_routing is not LocalRouting.OFF and not settings.local_base_url:
        warnings.append("SAG_LOCAL_BASE_URL is not configured for the selected routing mode.")
    return PreviewConfiguration(
        fingerprint=fingerprint,
        policy_version=policy.version,
        applications=applications,
        coverage=coverage,
        warnings=tuple(warnings),
        limits=preview_limits(settings),
        routing_mode=str(settings.local_routing),
    )


def inspect_locally(
    settings: Settings,
    detectors: list[object],
    policy: PolicyEngine,
    text: str,
    role: str,
    application: str,
) -> dict[str, Any]:
    """Run a single preview with per-job random keys and guaranteed vault disposal."""
    started = time.perf_counter()
    request = parse_chat_completion_request(
        {"model": PLACEHOLDER_MODEL, "messages": [{"role": role, "content": text}]}
    )
    ctx = RequestContext(
        tenant_id=f"preview_{uuid.uuid4().hex}",
        conversation_id=f"preview_{uuid.uuid4().hex}",
        request_id=f"preview_{uuid.uuid4().hex}",
        api_key_id="preview-local",
        application=application,
    )
    vault = SurrogateVault(KeyRing(keys={1: secrets.token_bytes(32)}, active_version=1))
    transformer = TransformationEngine(TokenMinter(secrets.token_bytes(32)), vault)
    service = PreparationService(
        detectors,
        policy,
        transformer,
        max_input_chars=min(MAX_TEXT_CHARS, settings.max_input_chars),
        block_mixed_script=settings.block_mixed_script,
    )
    try:
        prepared = service.prepare(ctx, request.to_payload())
        detections = [
            {
                "message_index": message.index,
                "start": span.start,
                "end": span.end,
                "entity_type": span.entity_type,
                "detector": span.detector,
                "score": float(span.score),
            }
            for message in prepared.inspected
            for span in message.spans
        ]
        decision = prepared.decision
        base = prepared.base_decision
        outbound = None
        if prepared.outbound is not None:
            destination = decision.destination
            model_override = (
                settings.local_model
                if destination == "local"
                else settings.external_model
                if destination == "external"
                else ""
            )
            outbound = {
                "text": prepared.outbound["messages"][0]["content"],
                "model": resolve_model(PLACEHOLDER_MODEL, model_override),
                "projected": True,
            }
        result = {
            "schema_version": 1,
            "preview_id": ctx.request_id,
            "provider_contacted": False,
            "detections": detections,
            "decision": {
                "base_rule": base.rule_name,
                "base_action": base.action.value,
                "effective_rule": decision.rule_name,
                "effective_action": decision.action.value,
                "destination": decision.destination if outbound is not None else None,
                "routing_override_reason": decision.reason if decision != base else None,
                "policy_version": decision.policy_version,
                "matched_entity_types": list(decision.matched_entities),
            },
            "outbound_preview": outbound,
            "entity_counts": prepared.entity_counts,
            "encoding_signals": prepared.encoding_signals,
            "transformation_count": prepared.transformed_count,
            "inspection_ms": round((time.perf_counter() - started) * 1000, 2),
        }
        if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > MAX_RESULT_BYTES:
            return {
                "error": {
                    "code": "result_too_large",
                    "message": "Preview result exceeds the 1 MiB limit.",
                }
            }
        return result
    finally:
        vault.delete_conversation(ctx)
