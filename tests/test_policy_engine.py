"""Policy engine: determinism, deny-overrides, versioning, validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from gateway.domain import Action, InspectionResult, RequestContext, Span
from gateway.policy.engine import PolicyEngine, PolicyError

DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "deployment" / "policies" / "default.yaml"


def inspection(*entity_types: str, score: float = 1.0) -> InspectionResult:
    return InspectionResult(
        spans=[
            Span(start=i * 10, end=i * 10 + 5, entity_type=t, text="xxxxx", score=score)
            for i, t in enumerate(entity_types)
        ]
    )


class TestDeterminism:
    def test_same_input_yields_same_decision(self, policy, ctx):
        result = inspection("EMAIL_ADDRESS")
        decisions = {policy.evaluate(ctx, result).rule_name for _ in range(50)}
        assert len(decisions) == 1

    def test_rule_order_is_independent_of_input_order(self, ctx):
        rules = [
            {
                "name": "b-rule",
                "priority": 50,
                "match": {"entities": ["EMAIL_ADDRESS"]},
                "action": {"type": "transform", "destination": "external"},
            },
            {
                "name": "a-rule",
                "priority": 50,
                "match": {"entities": ["EMAIL_ADDRESS"]},
                "action": {"type": "allow", "destination": "external"},
            },
            {
                "name": "catch-all",
                "priority": 1,
                "action": {"type": "allow", "destination": "external"},
            },
        ]
        forward = PolicyEngine.from_dict({"rules": rules, "version": "v"})
        reverse = PolicyEngine.from_dict({"rules": list(reversed(rules)), "version": "v"})
        result = inspection("EMAIL_ADDRESS")
        assert forward.evaluate(ctx, result).rule_name == reverse.evaluate(ctx, result).rule_name


class TestDenyOverrides:
    def test_block_wins_at_equal_priority(self, ctx):
        engine = PolicyEngine.from_dict(
            {
                "version": "v",
                "rules": [
                    {
                        "name": "allow-it",
                        "priority": 50,
                        "match": {"entities": ["EMAIL_ADDRESS"]},
                        "action": {"type": "allow", "destination": "external"},
                    },
                    {
                        "name": "block-it",
                        "priority": 50,
                        "match": {"entities": ["EMAIL_ADDRESS"]},
                        "action": {"type": "block"},
                    },
                    {
                        "name": "catch-all",
                        "priority": 1,
                        "action": {"type": "allow", "destination": "external"},
                    },
                ],
            }
        )
        decision = engine.evaluate(ctx, inspection("EMAIL_ADDRESS"))
        assert decision.action is Action.BLOCK
        assert decision.rule_name == "block-it"

    def test_higher_priority_wins_over_deny_at_lower_priority(self, ctx):
        engine = PolicyEngine.from_dict(
            {
                "version": "v",
                "rules": [
                    {
                        "name": "high-allow",
                        "priority": 90,
                        "match": {"entities": ["EMAIL_ADDRESS"]},
                        "action": {"type": "allow", "destination": "external"},
                    },
                    {
                        "name": "low-block",
                        "priority": 10,
                        "match": {"entities": ["EMAIL_ADDRESS"]},
                        "action": {"type": "block"},
                    },
                    {
                        "name": "catch-all",
                        "priority": 1,
                        "action": {"type": "allow", "destination": "external"},
                    },
                ],
            }
        )
        assert engine.evaluate(ctx, inspection("EMAIL_ADDRESS")).action is Action.ALLOW


class TestMatching:
    def test_min_score_filters_low_confidence(self, ctx):
        engine = PolicyEngine.from_dict(
            {
                "version": "v",
                "rules": [
                    {
                        "name": "confident-only",
                        "priority": 50,
                        "match": {"entities": ["IP_ADDRESS"], "min_score": 0.9},
                        "action": {"type": "transform", "destination": "external"},
                    },
                    {
                        "name": "catch-all",
                        "priority": 1,
                        "action": {"type": "allow", "destination": "external"},
                    },
                ],
            }
        )
        assert engine.evaluate(ctx, inspection("IP_ADDRESS", score=0.6)).rule_name == "catch-all"
        assert (
            engine.evaluate(ctx, inspection("IP_ADDRESS", score=1.0)).rule_name == "confident-only"
        )

    def test_application_scoping(self, ctx):
        engine = PolicyEngine.from_dict(
            {
                "version": "v",
                "rules": [
                    {
                        "name": "legal-only",
                        "priority": 50,
                        "match": {"entities": ["EMAIL_ADDRESS"], "applications": ["legal"]},
                        "action": {"type": "block"},
                    },
                    {
                        "name": "catch-all",
                        "priority": 1,
                        "action": {"type": "allow", "destination": "external"},
                    },
                ],
            }
        )
        legal = RequestContext("t", "c", "r", "k", application="legal")
        support = RequestContext("t", "c", "r", "k", application="support")
        assert engine.evaluate(legal, inspection("EMAIL_ADDRESS")).action is Action.BLOCK
        assert engine.evaluate(support, inspection("EMAIL_ADDRESS")).action is Action.ALLOW


class TestValidation:
    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("entities", "EMAIL_ADDRESS"),
            ("entities", ["EMAIL_ADDRESS", ""]),
            ("entities", ["EMAIL_ADDRESS", 7]),
            ("applications", "legal"),
            ("applications", ["legal", "   "]),
            ("applications", ["legal", None]),
        ],
    )
    def test_rejects_malformed_match_lists(self, field, value):
        with pytest.raises(PolicyError, match=field):
            PolicyEngine.from_dict(
                {
                    "version": "v",
                    "rules": [
                        {
                            "name": "conditional",
                            "priority": 10,
                            "match": {field: value},
                            "action": {"type": "block"},
                        },
                        {
                            "name": "catch-all",
                            "priority": 1,
                            "action": {"type": "allow", "destination": "external"},
                        },
                    ],
                }
            )

    @pytest.mark.parametrize(
        "value",
        [float("nan"), float("inf"), float("-inf"), -0.01, 1.01, "0.5", True],
    )
    def test_rejects_invalid_min_score(self, value):
        with pytest.raises(PolicyError, match="min_score"):
            PolicyEngine.from_dict(
                {
                    "version": "v",
                    "rules": [
                        {
                            "name": "conditional",
                            "priority": 10,
                            "match": {"entities": ["EMAIL_ADDRESS"], "min_score": value},
                            "action": {"type": "block"},
                        },
                        {
                            "name": "catch-all",
                            "priority": 1,
                            "action": {"type": "allow", "destination": "external"},
                        },
                    ],
                }
            )

    def test_rejects_policy_without_catch_all(self):
        with pytest.raises(PolicyError, match="catch-all"):
            PolicyEngine.from_dict(
                {
                    "version": "v",
                    "rules": [
                        {
                            "name": "only",
                            "priority": 1,
                            "match": {"entities": ["X"]},
                            "action": {"type": "block"},
                        }
                    ],
                }
            )

    def test_rejects_unknown_action(self):
        with pytest.raises(PolicyError, match="unknown action"):
            PolicyEngine.from_dict(
                {
                    "version": "v",
                    "rules": [{"name": "bad", "priority": 1, "action": {"type": "encrypt"}}],
                }
            )

    def test_rejects_duplicate_rule_names(self):
        with pytest.raises(PolicyError, match="duplicate"):
            PolicyEngine.from_dict(
                {
                    "version": "v",
                    "rules": [
                        {"name": "same", "priority": 2, "action": {"type": "allow"}},
                        {"name": "same", "priority": 1, "action": {"type": "allow"}},
                    ],
                }
            )

    def test_rejects_empty_policy(self):
        with pytest.raises(PolicyError):
            PolicyEngine.from_dict({"version": "v", "rules": []})


class TestVersioning:
    def test_shipped_default_policy_loads(self):
        engine = PolicyEngine.from_yaml(DEFAULT_POLICY)
        assert engine.version == "community-default-v1"
        assert len(engine.rules) == 5

    def test_undeclared_version_is_derived_from_content_hash(self, tmp_path):
        path = tmp_path / "p.yaml"
        path.write_text("rules:\n  - name: a\n    priority: 1\n    action:\n      type: allow\n")
        first = PolicyEngine.from_yaml(path).version
        assert first.startswith("sha256:")

        path.write_text("rules:\n  - name: b\n    priority: 1\n    action:\n      type: allow\n")
        assert PolicyEngine.from_yaml(path).version != first


class TestShippedDefaultBehaviour:
    """The default policy must be safe out of the box."""

    def test_default_policy_blocks_every_secret_type(self, ctx):
        engine = PolicyEngine.from_yaml(DEFAULT_POLICY)
        for secret in (
            "AWS_ACCESS_KEY",
            "PRIVATE_KEY",
            "JWT",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GITHUB_TOKEN",
            "SLACK_TOKEN",
        ):
            assert engine.evaluate(ctx, inspection(secret)).action is Action.BLOCK, secret

    def test_default_policy_routes_baltic_ids_locally(self, ctx):
        engine = PolicyEngine.from_yaml(DEFAULT_POLICY)
        for code in ("LV_PERSONAL_CODE", "LT_PERSONAL_CODE", "EE_PERSONAL_CODE"):
            decision = engine.evaluate(ctx, inspection(code))
            assert decision.action is Action.ROUTE_LOCAL
            assert decision.destination == "local"

    def test_test_fixture_policy_blocks_at_least_the_shipped_secrets(self, policy, ctx):
        """Guard against the test policy drifting more permissive than shipped.

        A fixture that blocks less than production hides real gaps -- exactly
        the failure this suite caught during development.
        """
        shipped = PolicyEngine.from_yaml(DEFAULT_POLICY)
        shipped_secrets = next(r for r in shipped.rules if r.name == "block-secrets").entities
        fixture_secrets = next(r for r in policy.rules if r.name == "block-secrets").entities
        assert shipped_secrets <= fixture_secrets
