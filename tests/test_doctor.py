"""Doctor behavior that protects the offline and redaction contracts."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import types
from pathlib import Path

from gateway.cli import main as cli_main
from gateway.detectors.ner import ModelManifest
from gateway.diagnostics.checks import Destination
from gateway.diagnostics.models import CheckResult
from gateway.diagnostics.probes import load_model, probe_providers
from gateway.diagnostics.report import render_json, render_text
from gateway.diagnostics.runner import run_doctor
from gateway.diagnostics.worker import _probe
from gateway.routing.egress import policy_for

ROOT = Path(__file__).resolve().parents[1]


def _production_env() -> dict[str, str]:
    return {
        "SAG_ENVIRONMENT": "production",
        "SAG_TOKEN_KEY": "t" * 32,
        "SAG_VAULT_KEY": "v" * 32,
        "SAG_API_KEYS": "sgw_live_" + "k" * 32 + ":tenant",
        "SAG_LOCAL_ROUTING": "all",
        "SAG_LOCAL_BASE_URL": "http://127.0.0.1:11434/v1",
    }


def _checks(report):
    return {check.id: check for check in report.checks}


def test_all_local_production_needs_no_external_provider():
    report = run_doctor(_production_env())
    checks = _checks(report)
    assert report.exit_code() == 0
    assert checks["routing.policy"].details["required_destinations"] == ["local"]
    assert "egress.external.url" not in checks
    assert "egress.local.dns" not in checks  # literal address was checked offline


def test_offline_does_not_resolve_or_generate_secrets(monkeypatch):
    import httpx

    def forbidden(*args, **kwargs):
        raise AssertionError("offline doctor used a forbidden operation")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr("secrets.token_bytes", forbidden)
    monkeypatch.setattr(httpx, "Client", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    env = _production_env()
    env["SAG_LOCAL_BASE_URL"] = "http://model.internal:11434/v1"
    report = run_doctor(env)
    assert _checks(report)["egress.local.dns"].status == "skip"


def test_independent_errors_and_canaries_never_appear(tmp_path):
    canary = "CONFIDENTIAL_CANARY_NEVER_PRINT"
    policy = tmp_path / "policy.yaml"
    policy.write_text(f"rules: [\n  {canary}: secret", encoding="utf-8")
    filters = tmp_path / "filters.yaml"
    filters.write_text(f"version: 1\nfilters: [{canary}]", encoding="utf-8")
    env = {
        "SAG_ENVIRONMENT": "production",
        "SAG_PORT": "broken",
        "SAG_VAULT_TTL_SECONDS": "-4",
        "SAG_LOCAL_ROUTING": "unknown",
        "SAG_TOKEN_KEY": canary,
        "SAG_VAULT_KEY": "short",
        "SAG_API_KEYS": canary,
        "SAG_POLICY_PATH": str(policy),
        "SAG_FILTERS_PATH": str(filters),
        "SAG_CUSTOM_PATTERNS": f"CUSTOM={canary}",
    }
    report = run_doctor(env)
    checks = _checks(report)
    assert checks["settings.port"].status == "fail"
    assert checks["settings.vault.ttl.seconds"].status == "fail"
    assert checks["policy.load"].status == "fail"
    assert checks["filters.load"].status == "fail"
    assert checks["routing.policy"].status == "skip"
    assert canary not in render_json(report)
    assert canary not in render_text(report)


def test_valid_operator_names_and_terms_are_redacted(tmp_path):
    canary = "CONFIDENTIAL_CANARY"
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        f"version: {canary}\ndefault_destination: {canary}\n"
        f"rules:\n  - name: {canary}\n    priority: 1\n"
        "    action: {type: allow}\n",
        encoding="utf-8",
    )
    filters = tmp_path / "filters.yaml"
    filters.write_text(
        f"version: 1\nfilters:\n  - name: {canary}\n"
        f"    entity_type: {canary}\n    match:\n      type: dictionary\n"
        f"      terms: [{canary}]\n",
        encoding="utf-8",
    )
    env = _production_env() | {
        "SAG_LOCAL_ROUTING": "off",
        "SAG_POLICY_PATH": str(policy),
        "SAG_FILTERS_PATH": str(filters),
    }
    report = run_doctor(env)
    assert _checks(report)["filters.load"].status == "pass"
    assert _checks(report)["routing.destinations"].status == "fail"
    assert canary not in render_json(report)


def test_cli_help_and_json_work_with_broken_production_settings():
    env = {key: value for key, value in os.environ.items() if not key.startswith("SAG_")}
    env["SAG_ENVIRONMENT"] = "production"
    help_result = subprocess.run(  # noqa: S603 - fixed executable and module
        [sys.executable, "-m", "gateway.cli", "--help"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert help_result.returncode == 0
    assert "doctor" in help_result.stdout
    result = subprocess.run(  # noqa: S603 - fixed executable and module
        [sys.executable, "-m", "gateway.cli", "doctor", "--format", "json"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["schema_version"] == 1
    assert report["counts"]["fail"] >= 3
    assert "Traceback" not in result.stderr


def test_no_argument_and_explicit_serve_dispatch_to_server(monkeypatch):
    calls = []
    fake_main = types.ModuleType("gateway.main")
    fake_main.run = lambda: calls.append("serve")
    monkeypatch.setitem(sys.modules, "gateway.main", fake_main)
    assert cli_main([]) == 0
    assert cli_main(["serve"]) == 0
    assert calls == ["serve", "serve"]


def test_strict_warnings_and_probe_statuses(monkeypatch):
    report = run_doctor(_production_env())
    assert report.exit_code() == 0
    assert report.exit_code(strict=True) == 1  # disabled NER warning

    destination = Destination(
        "local",
        "http://127.0.0.1:11434/v1",
        "",
        policy_for("local", require_private_network=True),
    )
    monkeypatch.setattr(
        "gateway.diagnostics.probes._worker",
        lambda payload, timeout: {"outcome": "listing_unsupported"},
    )
    checks = probe_providers((destination,), _production_env(), 5)
    assert checks[0].status == "warn"
    assert "inference" in checks[0].remediation


def test_probe_worker_uses_bounded_get_without_redirect_or_body_output(monkeypatch):
    import httpx

    response_state = {"status": 200, "body": b""}

    class Response:
        def __init__(self, status, body):
            self.status_code = status
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def iter_raw(self):
            yield self.body

    class Client:
        def __init__(self, **kwargs):
            assert kwargs["follow_redirects"] is False
            assert kwargs["trust_env"] is False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def stream(self, method, url, headers):
            assert method == "GET"
            assert url == "http://127.0.0.1:11434/v1/models"
            assert headers == {}
            return Response(response_state["status"], response_state["body"])

    monkeypatch.setattr(httpx, "Client", Client)
    payload = {
        "name": "local",
        "url": "http://127.0.0.1:11434/v1",
        "api_key": "",
        "allowed_hosts": [],
        "allow_private": True,
        "require_private_network": True,
        "trust_env": False,
        "trust_env_certs": False,
        "timeout": 5,
    }
    for status, body, expected in (
        (200, b"CONFIDENTIAL_BODY", "listed"),
        (401, b"CONFIDENTIAL_BODY", "auth_rejected"),
        (404, b"", "listing_unsupported"),
        (302, b"", "redirect"),
        (200, b"x" * 65537, "oversized"),
    ):
        response_state.update(status=status, body=body)
        assert _probe(payload) == {"outcome": expected}


def test_probe_refuses_egress_before_constructing_client(monkeypatch):
    import httpx

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("network client constructed")),
    )
    result = _probe(
        {
            "name": "external",
            "url": "http://169.254.169.254/v1",
            "api_key": "secret",
            "allowed_hosts": [],
            "allow_private": False,
            "require_private_network": False,
            "trust_env": False,
            "trust_env_certs": False,
            "timeout": 5,
        }
    )
    assert result == {"outcome": "egress_blocked"}


def test_model_worker_result_is_allowlisted_and_timeout_does_not_poison_next_call(monkeypatch):
    outcomes = iter(
        [
            {"outcome": "timeout"},
            {
                "outcome": "loaded",
                "backend_mapped_entities": ["PERSON", "CANARY_SECRET"],
                "observed_smoke_entities": ["ORG", "CANARY_SECRET"],
            },
        ]
    )
    monkeypatch.setattr(
        "gateway.diagnostics.probes._worker", lambda payload, timeout: next(outcomes)
    )
    first = load_model("unused")
    second = load_model("unused")
    assert first.status == "fail"
    assert "60 seconds" in first.summary
    assert second.status == "pass"
    assert second.details == {
        "backend_mapped_entities": ["PERSON"],
        "observed_smoke_entities": ["ORG"],
    }


def test_loaded_model_keeps_manifest_and_backend_claims_separate(monkeypatch):
    manifest = ModelManifest("test", "1", "MIT", {"model.bin": "0" * 64}, ("lv", "en"))
    monkeypatch.setattr("gateway.diagnostics.checks.verify_model", lambda path: manifest)
    monkeypatch.setattr(
        "gateway.diagnostics.runner.load_model",
        lambda path: CheckResult(
            "detection.model_load",
            "pass",
            "NER backend loaded and smoke check finished",
            details={"backend_mapped_entities": ["PERSON"], "observed_smoke_entities": []},
        ),
    )
    report = run_doctor(
        _production_env() | {"SAG_NER_MODEL_PATH": "test-model"}, load_ner_model=True
    )
    ner = next(item for item in report.coverage if item["name"] == "ner")
    assert ner["declared_languages"] == ["lv", "en"]
    assert ner["possible_mapped_entities"] == ["PERSON", "ORG", "LOCATION", "ADDRESS"]
    assert ner["backend_mapped_entities"] == ["PERSON"]
    assert ner["observed_smoke_entities"] == []
    assert ner["runtime_verified"] is True
