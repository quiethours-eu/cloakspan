"""First-public-release controls that are easy to regress accidentally."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from gateway.config import (
    ConfigurationError,
    Settings,
    build_key_store,
    build_providers,
)
from gateway.policy.engine import PolicyEngine

ROOT = Path(__file__).resolve().parent.parent


def test_default_policy_declares_every_provider_it_can_select():
    policy = PolicyEngine.from_yaml(ROOT / "deployment" / "policies" / "default.yaml")

    assert policy.required_destinations == frozenset({"external", "local"})


def test_production_refuses_provider_names_that_would_resolve_to_mock(monkeypatch):
    monkeypatch.setenv("SAG_ENVIRONMENT", "production")

    with pytest.raises(ConfigurationError, match="unconfigured/mock provider"):
        build_providers(
            Settings(),
            required_destinations=frozenset({"external", "local"}),
        )


def test_development_can_still_use_the_offline_mock(monkeypatch):
    monkeypatch.delenv("SAG_ENVIRONMENT", raising=False)

    providers = build_providers(
        Settings(),
        required_destinations=frozenset({"external", "local"}),
    )

    assert providers["external"] is providers["mock"]
    assert providers["local"] is providers["mock"]


def test_unknown_policy_destination_fails_at_startup(monkeypatch):
    monkeypatch.delenv("SAG_ENVIRONMENT", raising=False)

    with pytest.raises(ConfigurationError, match="unknown provider"):
        build_providers(Settings(), required_destinations=frozenset({"typo"}))


def test_production_requires_at_least_one_valid_api_key(monkeypatch):
    monkeypatch.setenv("SAG_ENVIRONMENT", "production")
    monkeypatch.delenv("SAG_API_KEYS", raising=False)

    with pytest.raises(ConfigurationError, match="contains no valid keys"):
        build_key_store()


@pytest.mark.parametrize(
    "configured",
    [
        "sgw_live_short:tenant:app",
        "not_the_right_prefix_01234567890123456789012345678901:tenant:app",
        "sgw_live_01234567890123456789012345678901::app",
        "sgw_live_01234567890123456789012345678901:tenant:app:extra",
    ],
)
def test_production_refuses_weak_or_malformed_api_keys(monkeypatch, configured):
    monkeypatch.setenv("SAG_ENVIRONMENT", "production")
    monkeypatch.setenv("SAG_API_KEYS", configured)

    with pytest.raises(ConfigurationError):
        build_key_store()


def test_duplicate_api_key_cannot_be_assigned_to_two_tenants(monkeypatch):
    key = "sgw_live_01234567890123456789012345678901"
    monkeypatch.delenv("SAG_ENVIRONMENT", raising=False)
    monkeypatch.setenv("SAG_API_KEYS", f"{key}:tenant-a:app,{key}:tenant-b:app")

    with pytest.raises(ConfigurationError, match="same plaintext key"):
        build_key_store()


def test_compose_has_no_usable_secret_or_mock_default():
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")

    assert 'SAG_ENVIRONMENT: "production"' in compose
    assert "sgw_live_change_me_immediately" not in compose
    assert "SAG_API_KEYS:?" in compose
    assert "SAG_VAULT_KEY:?" in compose
    assert "SAG_TOKEN_KEY:?" in compose
    assert "SAG_EXTERNAL_BASE_URL:?" in compose
    assert "SAG_LOCAL_BASE_URL:?" in compose


def test_gitleaks_keeps_default_rules_and_narrow_fixture_exceptions():
    config = tomllib.loads((ROOT / ".gitleaks.toml").read_text(encoding="utf-8"))

    assert config["extend"]["useDefault"] is True
    rendered = str(config["allowlists"])
    assert "tests/.*" not in rendered
    assert "evals/.*" not in rendered
    assert "private-key" in rendered
