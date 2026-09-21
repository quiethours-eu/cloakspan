"""Bundled alternative policies: what each one lets reach the external provider."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from gateway.config import Settings, build_pipeline
from gateway.domain import Action, InspectionResult, Span
from gateway.policy.engine import PolicyEngine

ROOT = Path(__file__).resolve().parent.parent
POLICIES = ROOT / "deployment" / "policies"
AUTO_LOCAL = POLICIES / "auto-local.yaml"


def inspection(*entity_types: str, score: float = 1.0) -> InspectionResult:
    return InspectionResult(
        spans=[
            Span(start=i * 10, end=i * 10 + 5, entity_type=t, text="xxxxx", score=score)
            for i, t in enumerate(entity_types)
        ]
    )


def documented_entity_types() -> set[str]:
    text = (ROOT / "docs" / "entity-taxonomy.md").read_text(encoding="utf-8")
    return set(re.findall(r"^\| `([A-Z][A-Z0-9_]*)`", text, re.MULTILINE))


def secrets_blocked_by(engine: PolicyEngine) -> frozenset[str]:
    return next(r for r in engine.rules if r.name == "block-secrets").entities


def user_message(text: str) -> dict:
    return {"messages": [{"role": "user", "content": text}]}


@pytest.fixture
def auto_local() -> PolicyEngine:
    return PolicyEngine.from_yaml(AUTO_LOCAL)


class TestAutoLocalDecisions:
    def test_no_documented_entity_type_reaches_the_external_provider(self, auto_local, ctx):
        """A new entity type added to the taxonomy but not to this policy would
        fall through to the catch-all and leave in clear. This is the guard."""
        documented = documented_entity_types()
        assert len(documented) >= 20, "the taxonomy table was not parsed"

        for entity in sorted(documented):
            # A score this low must still count: doubt resolves toward local.
            decision = auto_local.evaluate(ctx, inspection(entity, score=0.01))
            assert decision.action in (Action.BLOCK, Action.ROUTE_LOCAL), entity
            if decision.action is Action.ROUTE_LOCAL:
                assert decision.destination == "local", entity

    def test_blocks_at_least_the_default_policy_secrets(self, auto_local, ctx):
        shipped = secrets_blocked_by(PolicyEngine.from_yaml(POLICIES / "default.yaml"))
        assert shipped <= secrets_blocked_by(auto_local)
        for secret in sorted(shipped):
            decision = auto_local.evaluate(ctx, inspection("EMAIL_ADDRESS", secret))
            assert decision.action is Action.BLOCK, secret

    def test_only_a_request_with_nothing_detected_goes_external(self, auto_local, ctx):
        decision = auto_local.evaluate(ctx, inspection())
        assert decision.action is Action.ALLOW
        assert decision.destination == "external"

    def test_declares_both_destinations_so_production_checks_them(self, auto_local):
        assert auto_local.required_destinations == frozenset({"external", "local"})


class TestAutoLocalPipeline:
    @pytest.fixture
    def providers(self, mock_provider, local_provider):
        return {"external": mock_provider, "local": local_provider}

    def pipeline(self, providers, **settings):
        pipeline = build_pipeline(Settings(policy_path=AUTO_LOCAL, **settings))
        pipeline._providers.update(providers)
        return pipeline

    async def test_personal_data_reaches_only_the_local_model(self, providers, ctx):
        pipeline = self.pipeline(providers)

        await pipeline.process(ctx, user_message("Draft a reply to alex@example.com"))
        await pipeline.process(ctx, user_message("Explain what a mutex is"))

        external = [p["messages"][0]["content"] for p in providers["external"].received]
        assert external == ["Explain what a mutex is"]
        assert len(providers["local"].received) == 1

    async def test_custom_filters_without_a_destination_stay_local(self, providers, ctx, tmp_path):
        filters = tmp_path / "filters.yaml"
        filters.write_text(
            yaml.safe_dump(
                {
                    "version": 1,
                    "filters": [
                        {
                            "name": "employee-ids",
                            "entity_type": "EMPLOYEE_ID",
                            "match": {"type": "regex", "pattern": r"\bEMP-[0-9]{6}\b"},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        pipeline = self.pipeline(providers, filters_path=filters)

        result = await pipeline.process(ctx, user_message("Employee EMP-123456 asked for leave"))

        assert result.rule_name == "filter:employee-ids"
        assert providers["external"].received == []
        assert len(providers["local"].received) == 1
