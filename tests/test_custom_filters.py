"""Operator filters must detect, enforce policy, and preserve restoration."""

from pathlib import Path

import pytest
import yaml

from gateway.config import ConfigurationError, Settings, build_detectors, build_pipeline
from gateway.inspection.pipeline import PolicyBlockedError
from recognizers.custom.filters import FilterConfigurationError, FilterSet


def write_filters(tmp_path, filters):
    path = tmp_path / "filters.yaml"
    path.write_text(yaml.safe_dump({"version": 1, "filters": filters}), encoding="utf-8")
    return path


def employee(**overrides):
    return {
        "name": "employee-ids",
        "entity_type": "EMPLOYEE_ID",
        "match": {"type": "regex", "pattern": r"\bEMP-[0-9]{6}\b"},
        **overrides,
    }


def test_environment_and_legacy_compatibility(tmp_path, monkeypatch):
    path = write_filters(tmp_path, [employee()])
    monkeypatch.setenv("SAG_FILTERS_PATH", str(path))
    monkeypatch.setenv("SAG_DICTIONARY_TERMS", "Project Aurora")
    monkeypatch.setenv("SAG_CUSTOM_PATTERNS", r"ORDER_ID=ORD-[0-9]{4}")
    settings = Settings.from_env()
    assert settings.filters_path == path
    spans = [
        span
        for detector in build_detectors(settings)
        for span in detector.detect("EMP-123456 ORD-1234 Project Aurora a@example.com")
    ]
    assert {s.entity_type for s in spans} >= {
        "EMPLOYEE_ID",
        "ORDER_ID",
        "CUSTOMER_TERM",
        "EMAIL_ADDRESS",
    }


@pytest.mark.parametrize("action", ["transform", "route_local"])
@pytest.mark.parametrize("value", ["EMP-123456", "EMP-12\u200b3456", "ＥＭＰ-１２３４５６"])
async def test_pipeline_transforms_and_restores(tmp_path, ctx, mock_provider, action, value):
    path = write_filters(tmp_path, [employee(action=action)])
    pipeline = build_pipeline(Settings(filters_path=path))
    destination = "local" if action == "route_local" else "external"
    pipeline._providers[destination] = mock_provider
    text = f"Employee {value}"
    result = await pipeline.process(ctx, {"messages": [{"role": "user", "content": text}]})
    assert result.decision_action == action
    assert result.rule_name == "filter:employee-ids"
    assert result.entity_counts == {"EMPLOYEE_ID": 1}
    assert result.restoration.restored == 1
    assert value in result.response["choices"][0]["message"]["content"]
    assert value not in str(mock_provider.received)
    assert "<EMPLOYEE_ID:v1:" in str(mock_provider.received)


async def test_dictionary_blocks_before_provider(tmp_path, ctx, mock_provider):
    path = write_filters(
        tmp_path,
        [
            employee(
                entity_type="PROJECT",
                action="block",
                match={"type": "dictionary", "terms": ["Project Aurora", "Project Aurora North"]},
            )
        ],
    )
    pipeline = build_pipeline(Settings(filters_path=path))
    pipeline._providers["external"] = mock_provider
    with pytest.raises(PolicyBlockedError, match="filter:employee-ids"):
        await pipeline.process(
            ctx,
            {
                "messages": [
                    {"role": "user", "content": "Discuss project aurora north"},
                ]
            },
        )
    assert mock_provider.received == []


def test_dictionary_literal_boundaries_and_case(tmp_path):
    path = write_filters(
        tmp_path,
        [
            employee(
                match={
                    "type": "dictionary",
                    "terms": ["Acme", "Acme North", "A+B"],
                }
            )
        ],
    )
    detector = FilterSet.from_yaml(path).detectors[0]
    assert [s.text for s in detector.detect("acme north Acmeville A+B")] == ["acme north", "A+B"]
    path = write_filters(
        tmp_path,
        [
            employee(
                match={
                    "type": "dictionary",
                    "terms": ["Acme"],
                    "case_sensitive": True,
                }
            )
        ],
    )
    assert FilterSet.from_yaml(path).detectors[0].detect("acme") == []


def test_regex_case_and_disabled_filter(tmp_path):
    path = write_filters(
        tmp_path,
        [
            employee(
                match={
                    "type": "regex",
                    "pattern": "EMP-[0-9]{6}",
                    "case_sensitive": False,
                }
            )
        ],
    )
    assert FilterSet.from_yaml(path).detectors[0].detect("emp-123456")
    path = write_filters(tmp_path, [employee(enabled=False)])
    filters = FilterSet.from_yaml(path)
    assert filters.detectors == filters.rules == []


@pytest.mark.parametrize(
    "change",
    [
        {"entity_type": "invalid-label"},
        {"entity_type": "A" * 65},
        {"action": "typo"},
        {"enabled": "false"},
        {"priority": True},
        {"priority": 1.5},
        {"unknown": True},
        {"match": {"type": "regex", "pattern": "["}},
        {"match": {"type": "regex", "pattern": "(a+)+"}},
        {"match": {"type": "regex", "pattern": ""}},
        {"match": {"type": "regex", "pattern": "x", "terms": ["secret"]}},
        {"match": {"type": "dictionary", "terms": "secret"}},
        {"match": {"type": "dictionary", "terms": [" "]}},
        {"match": {"type": "dictionary", "terms": []}},
        {"action": "block", "destination": "external"},
    ],
)
def test_invalid_filters_fail_startup(tmp_path, change):
    path = write_filters(tmp_path, [employee(**change)])
    with pytest.raises(ConfigurationError, match="SAG_FILTERS_PATH"):
        build_pipeline(Settings(filters_path=path))


@pytest.mark.parametrize(
    "content",
    [
        "version: 2\nfilters: []",
        "version: true\nfilters: []",
        "[]",
        "[",
        "version: 1\nversion: 1\nfilters: []",
        "version: 1\nfilters: []\ntypo: true",
        "version: 1\nfilters: null",
    ],
)
def test_invalid_document(tmp_path, content):
    path = tmp_path / "filters.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(FilterConfigurationError):
        FilterSet.from_yaml(path)


def test_missing_file_fails_startup(tmp_path):
    with pytest.raises(ConfigurationError):
        build_pipeline(Settings(filters_path=tmp_path / "missing.yaml"))


@pytest.mark.parametrize("second", [employee(), employee(name="other")])
def test_duplicates_rejected(tmp_path, second):
    with pytest.raises(FilterConfigurationError, match="unique"):
        FilterSet.from_yaml(write_filters(tmp_path, [employee(), second]))


def test_filter_edit_changes_audit_version(tmp_path):
    path = write_filters(tmp_path, [employee()])
    first = build_pipeline(Settings(filters_path=path))._policy.version
    write_filters(tmp_path, [employee(action="block")])
    second = build_pipeline(Settings(filters_path=path))._policy.version
    assert first != second
    assert "+filters:" in second


def test_default_secret_rule_still_wins(tmp_path, ctx):
    pipeline = build_pipeline(Settings(filters_path=write_filters(tmp_path, [employee()])))
    inspection, _ = pipeline.inspect_payload(
        {
            "messages": [
                {
                    "role": "user",
                    "content": "EMP-123456 AKIAIOSFODNN7EXAMPLE",
                }
            ]
        }
    )
    assert pipeline._policy.evaluate(ctx, inspection).rule_name == "block-secrets"


def test_unknown_destination_rejected(tmp_path):
    path = write_filters(tmp_path, [employee(destination="typo")])
    with pytest.raises(ConfigurationError, match="unknown provider"):
        build_pipeline(Settings(filters_path=path))


def test_shipped_example_loads():
    path = Path(__file__).resolve().parents[1] / "deployment/filters/example.yaml"
    filters = FilterSet.from_yaml(path)
    assert len(filters.detectors) == len(filters.rules) == 3
