"""Supply-chain gates: licence policy, SBOM shape, and exception hygiene.

These run in the ordinary suite rather than only in CI. A release gate that only
exists in a workflow file is a gate nobody sees until it blocks them, and the
failures here are the kind a developer should find while adding the dependency,
not two weeks later on a tag.
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from scripts.supply_chain import (
    ALLOWED,
    DENIED,
    FORBIDDEN_DISTRIBUTIONS,
    REVIEW_REQUIRED,
    build_licence_report,
    build_sbom,
    check,
    classify_expression,
    collect,
)

ROOT = Path(__file__).resolve().parent.parent
EXCEPTIONS = ROOT / "deployment" / "security-exceptions.yaml"


@pytest.fixture(scope="module")
def components():
    return collect()


# ---------------------------------------------------------------------------
# Licence policy
# ---------------------------------------------------------------------------


class TestLicencePolicy:
    def test_every_installed_distribution_is_cleared(self, components):
        """The gate itself. A new dependency with unclear terms fails here.

        Buyers in this market frequently have a written policy against AGPL, so
        a dependency that quietly introduces one is a procurement problem found
        at the worst possible moment.
        """
        problems = check(components)
        assert not problems, "\n".join(problems)

    def test_the_forbidden_distribution_is_absent(self, components):
        """LiteLLM's enterprise package forbids production use without a
        subscription. Its presence would make the Apache-2.0 claim false."""
        installed = {c.name.lower().replace("_", "-") for c in components}
        assert not (installed & FORBIDDEN_DISTRIBUTIONS)

    def test_the_verdict_buckets_do_not_overlap(self):
        """A licence in two buckets makes the outcome depend on check order."""
        assert not (ALLOWED & DENIED)
        assert not (ALLOWED & REVIEW_REQUIRED)
        assert not (DENIED & REVIEW_REQUIRED)

    @pytest.mark.parametrize(
        ("expression", "expected"),
        [
            ("MIT", "ALLOWED"),
            ("Apache-2.0", "ALLOWED"),
            ("Apache-2.0 OR BSD-3-Clause", "ALLOWED"),
            ("MIT AND Apache-2.0", "ALLOWED"),
            ("MPL-2.0", "REVIEW_REQUIRED"),
            ("MIT OR MPL-2.0", "ALLOWED"),
            ("MIT AND AGPL-3.0", "DENIED"),
            ("AGPL-3.0", "DENIED"),
            ("GPL-3.0 OR Proprietary", "DENIED"),
            ("Something-Nobody-Has-Heard-Of", "UNKNOWN"),
        ],
    )
    def test_spdx_expressions_are_parsed_not_matched_literally(self, expression, expected):
        """``OR`` is a choice, ``AND`` binds us to both.

        Matching whole strings literally reported `cryptography` as unrecognised
        — the kind of false alarm that gets a policy gate switched off.
        """
        assert classify_expression(expression) == expected

    def test_a_denied_licence_is_never_rescued_by_a_review_entry(self):
        """REVIEWED covers ambiguity, not strong copyleft.

        Otherwise the exception mechanism becomes a way to accept anything.
        """
        from scripts.supply_chain import _verdict

        verdict, _ = _verdict("certifi", ["AGPL-3.0"])
        assert verdict == "DENIED"

    def test_the_report_accounts_for_every_distribution(self, components):
        report = build_licence_report(components)
        assert report["total"] == len(components)
        assert sum(report["summary"].values()) == len(components)


# ---------------------------------------------------------------------------
# SBOM
# ---------------------------------------------------------------------------


class TestSbom:
    def test_the_document_is_valid_cyclonedx(self, components):
        sbom = build_sbom(components)
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.5"
        assert sbom["serialNumber"].startswith("urn:uuid:")
        assert sbom["metadata"]["component"]["name"] == "secure-ai-gateway"

    def test_every_component_has_a_purl_and_a_version(self, components):
        for component in build_sbom(components)["components"]:
            assert component["purl"].startswith("pkg:pypi/")
            assert component["version"]

    def test_the_serial_number_is_deterministic(self, components):
        """A randomly-serialised SBOM cannot be diffed between builds, which
        removes most of the reason to keep one."""
        assert build_sbom(components)["serialNumber"] == build_sbom(components)["serialNumber"]

    def test_the_document_is_json_serialisable(self, components):
        assert json.loads(json.dumps(build_sbom(components)))

    def test_the_sbom_and_the_licence_report_agree(self, components):
        sbom = build_sbom(components)
        report = build_licence_report(components)
        assert len(sbom["components"]) == report["total"]


# ---------------------------------------------------------------------------
# Vulnerability exceptions
# ---------------------------------------------------------------------------


def load_exceptions() -> dict:
    return yaml.safe_load(EXCEPTIONS.read_text(encoding="utf-8"))


class TestSecurityExceptions:
    def test_the_file_exists_and_declares_a_policy(self):
        document = load_exceptions()
        assert document["policy"]["block"] == ["CRITICAL"]
        assert "HIGH" in document["policy"]["block_unless_excepted"]

    def test_critical_findings_can_never_be_excepted(self):
        """Not "should not" -- cannot. If a CRITICAL is genuinely unexploitable,
        the downgrade must be a visible decision, not an invisible omission."""
        document = load_exceptions()
        for entry in document.get("exceptions") or []:
            assert entry["severity"] != "CRITICAL", (
                f"{entry['id']}: CRITICAL findings cannot be excepted"
            )

    def test_every_exception_has_an_owner_a_date_and_an_expiry(self):
        document = load_exceptions()
        for entry in document.get("exceptions") or []:
            for required in (
                "id",
                "package",
                "severity",
                "reason",
                "approved_by",
                "approved_on",
                "expires_on",
            ):
                assert entry.get(required), f"{entry.get('id')}: missing {required}"
            assert len(str(entry["approved_by"]).split()) >= 2, (
                f"{entry['id']}: approved_by must name a person, not a team -- a team "
                "cannot be asked what they were thinking eight months later"
            )

    def test_no_exception_has_expired(self):
        """An expired exception fails the build, exactly as the finding would.

        This is the assertion that makes the whole mechanism honest: without it
        an exception is a permanent silent waiver with a date on it.
        """
        document = load_exceptions()
        today = date.today()
        for entry in document.get("exceptions") or []:
            expires = entry["expires_on"]
            if not isinstance(expires, date):
                expires = date.fromisoformat(str(expires))
            assert expires >= today, (
                f"{entry['id']} expired on {expires}. Re-triage it, or fix the finding."
            )

    def test_no_exception_runs_longer_than_the_policy_allows(self):
        document = load_exceptions()
        limit = timedelta(days=document["policy"]["max_exception_days"])
        for entry in document.get("exceptions") or []:
            approved = entry["approved_on"]
            expires = entry["expires_on"]
            if not isinstance(approved, date):
                approved = date.fromisoformat(str(approved))
            if not isinstance(expires, date):
                expires = date.fromisoformat(str(expires))
            assert expires - approved <= limit, (
                f"{entry['id']}: {expires - approved} exceeds the "
                f"{document['policy']['max_exception_days']}-day maximum"
            )

    def test_there_are_currently_no_exceptions(self):
        """Recorded so that adding the first one is a deliberate, reviewed act.

        When a real exception is needed this assertion changes in the same
        commit, which puts it in front of a reviewer.
        """
        assert not (load_exceptions().get("exceptions") or []), (
            "an exception was added -- update this test in the same commit so the "
            "addition is reviewed rather than absorbed"
        )
