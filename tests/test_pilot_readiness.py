"""The Community Edition beta exit criteria, as tests.

The plan's gate reads:

    Pilot users can install, run `make demo`, configure an upstream, interpret
    audit events, and roll back without developer intervention.

Every clause there is a claim about someone else's experience, which is exactly
the kind of claim that goes unchecked until a pilot user proves it false at the
worst moment. These assert the mechanical parts — that the documented path
exists, that the commands are real, that the audit event contains what the
troubleshooting guide says to look for.

What they cannot assert is whether a stranger *understands* any of it. That
needs a stranger, and it is the part of Phase 7 no test replaces.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
CONFIGURATION_DOCS = README + (ROOT / "docs" / "configuration.md").read_text(encoding="utf-8")
LIMITATIONS_DOCS = README + (ROOT / "docs" / "limitations.md").read_text(encoding="utf-8")
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")


def make_targets() -> set[str]:
    return {match.group(1) for match in re.finditer(r"^([a-z][a-z0-9-]*):", MAKEFILE, re.MULTILINE)}


# ---------------------------------------------------------------------------
# "Install and run make demo"
# ---------------------------------------------------------------------------


class TestTheDocumentedPathExists:
    @pytest.mark.parametrize(
        "target",
        ["setup", "demo", "test", "evals", "security", "up", "down", "sbom", "licences"],
    )
    def test_every_command_the_readme_promises_is_a_real_target(self, target):
        """A README that names a command that does not exist is worse than one
        that names none: it fails at the first thing a new user tries."""
        assert f"make {target}" in README or target in ("test", "up", "down"), (
            f"`make {target}` is not mentioned in the README"
        )
        assert target in make_targets(), f"`make {target}` is not a Makefile target"

    def test_the_demo_runs_offline_and_shows_what_the_provider_received(self):
        """The demo's whole claim: you can see for yourself that the original
        values never left. If it stops printing that, the claim is unbacked."""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "scripts/demo.py"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=180,
            encoding="utf-8",
            errors="replace",
        )
        assert result.returncode == 0, result.stderr[-2000:]

        output = result.stdout
        assert "provider saw" in output, "the demo must show what the provider received"
        assert "provider saw NOTHING" in output, "and that a blocked request sent nothing"
        assert "alice@acme.lv" not in output or "<EMAIL_ADDRESS:" in output

    def test_the_demo_needs_no_credentials_or_network(self):
        """Asserted against the source, because a demo that quietly requires an
        API key is a demo nobody can run."""
        demo = (ROOT / "scripts" / "demo.py").read_text(encoding="utf-8")
        assert "MockProvider" in demo
        assert "OpenAICompatibleProvider" not in demo


class TestTheUpstreamIsConfigurable:
    @pytest.mark.parametrize(
        "variable",
        [
            "SAG_API_KEYS",
            "SAG_VAULT_KEY",
            "SAG_TOKEN_KEY",
            "SAG_EXTERNAL_BASE_URL",
            "SAG_LOCAL_BASE_URL",
            "SAG_POLICY_PATH",
            "SAG_VAULT_TTL_SECONDS",
            "SAG_EGRESS_ALLOWLIST",
        ],
    )
    def test_documented_settings_are_actually_read(self, variable):
        """Every variable the README documents must be read by the code.

        Documentation drift here is silent and expensive: an operator sets a
        variable, sees no error, and believes a control is on.
        """
        config = (ROOT / "gateway" / "config.py").read_text(encoding="utf-8")
        assert variable in CONFIGURATION_DOCS, f"{variable} is not documented"
        assert variable in config, f"{variable} is documented but never read"

    def test_every_setting_the_code_reads_is_documented(self):
        """And the reverse, which is the direction that hides features."""
        config = (ROOT / "gateway" / "config.py").read_text(encoding="utf-8")
        used = set(re.findall(r'os\.environ\.get\(\s*"(SAG_[A-Z_]+)"', config))
        used |= set(re.findall(r'os\.environ\.get\(\s*"(SAG_[A-Z_]+)"', config))
        undocumented = {name for name in used if name not in CONFIGURATION_DOCS}
        assert not undocumented, f"read but not documented: {sorted(undocumented)}"


# ---------------------------------------------------------------------------
# "Interpret audit events"
# ---------------------------------------------------------------------------


class TestAuditEventsAreInterpretable:
    async def test_an_audit_event_carries_what_troubleshooting_tells_you_to_look_at(
        self, pipeline, ctx, audit_sink
    ):
        """docs/operations.md tells an operator to check specific fields. If a
        field is renamed, the runbook silently becomes wrong."""
        await pipeline.process(
            ctx,
            {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "Mail alice@acme.lv"}],
            },
        )
        event = json.loads(audit_sink.events[-1].to_json())

        for field in (
            "schema_version",
            "request_id",
            "tenant_id",
            "conversation_id",
            "decision",
            "rule_name",
            "policy_version",
            "entity_counts",
            "tokens_restored",
            "tokens_refused",
            "tokens_refused_by_reason",
            "encoding_signals",
            "raw_content_logged",
            "latency_ms",
        ):
            assert field in event, f"operations.md refers to '{field}', which is absent"

    async def test_the_refusal_reasons_match_the_runbook(self, pipeline, ctx, audit_sink):
        """The runbook's table of reasons must be the code's set of reasons."""
        from gateway.restoration.engine import RestorationOutcome

        documented = set(
            re.findall(
                r"^\| `(not_minted|vault_miss|cross_tenant|key_unavailable)` \|",
                (ROOT / "docs" / "operations.md").read_text(encoding="utf-8"),
                re.MULTILINE,
            )
        )
        produced = set(
            RestorationOutcome(
                text="",
                refused_unknown=1,
                refused_not_minted=1,
                refused_cross_tenant=1,
                refused_key_unavailable=1,
            ).reasons()
        )
        assert produced == documented, (
            f"runbook documents {sorted(documented)}, code produces {sorted(produced)}"
        )

    async def test_an_audit_event_still_contains_no_prompt_content(self, pipeline, ctx, audit_sink):
        canary = "PILOT-CANARY-VALUE"
        await pipeline.process(
            ctx,
            {"model": "m", "messages": [{"role": "user", "content": f"{canary} hello"}]},
        )
        assert canary not in audit_sink.events[-1].to_json()


# ---------------------------------------------------------------------------
# "Roll back"
# ---------------------------------------------------------------------------


class TestRollbackIsCheap:
    def test_there_is_no_persistent_schema_to_migrate(self):
        """Rollback is cheap because there is nothing durable to reverse.

        This is a property worth protecting: the first migration added to the
        Community Edition makes rollback a different, harder operation, and this
        test should fail when that happens so it is a decision rather than a
        discovery.
        """
        # Scoped to our own source. The untracked research clone directory holds
        # copies of
        # the projects we reviewed, and one of them uses Alembic -- which is a
        # fact about them, not about us.
        ours = [ROOT / "gateway", ROOT / "recognizers", ROOT / "deployment", ROOT / "evals"]
        assert not (ROOT / "migrations").exists()
        for directory in ours:
            assert not list(directory.glob("**/alembic.ini"))
            assert not list(directory.glob("**/migrations/*.py"))

    def test_the_default_vault_backend_is_in_memory(self):
        """Which is why an upgrade loses mappings and a rollback costs nothing."""
        from gateway.vault.store import InMemoryBackend, KeyRing, SurrogateVault

        vault = SurrogateVault(key_ring=KeyRing(keys={1: b"\x01" * 32}, active_version=1))
        assert isinstance(vault._backend, InMemoryBackend)  # noqa: SLF001

    def test_operations_documents_the_upgrade_symptom(self):
        """An upgrade produces a visible `vault_miss` spike. If that is not
        written down, the first deploy generates a support ticket."""
        operations = (ROOT / "docs" / "operations.md").read_text(encoding="utf-8")
        assert "vault_miss" in operations
        assert "rollback" in operations.lower()


# ---------------------------------------------------------------------------
# "Known limitations are published and match actual behaviour"
# ---------------------------------------------------------------------------


class TestPublishedLimitationsAreTrue:
    def test_the_readme_states_alpha_status_and_links_current_limits(self):
        lowered = README.lower()
        assert "alpha" in lowered
        assert "[known limitations]" in lowered
        assert "independent security review" not in lowered

    def test_streaming_is_documented_as_unsupported_and_is(self, client_factory=None):
        lowered = LIMITATIONS_DOCS.lower()
        assert "streaming" in lowered
        assert "unsupported" in lowered or "refused" in lowered
        from gateway.api.schema import RequestRejected, parse_chat_completion_request

        with pytest.raises(RequestRejected) as caught:
            parse_chat_completion_request(
                {"model": "m", "messages": [{"role": "user", "content": "x"}], "stream": True}
            )
        assert caught.value.code == "streaming_unsupported"

    def test_ner_is_documented_as_absent_and_is(self):
        lowered = LIMITATIONS_DOCS.lower()
        assert "person, org, location, and address" in lowered
        assert "operator-supplied ner model" in lowered
        from gateway.config import Settings, build_detectors

        detectors = build_detectors(Settings())
        assert not any(getattr(d, "name", "") == "ner" for d in detectors)

    def test_tool_calls_are_documented_as_refused_and_are(self):
        lowered = LIMITATIONS_DOCS.lower()
        assert "tool calls" in lowered
        assert "refused" in lowered
        from gateway.api.schema import RequestRejected, parse_chat_completion_request

        with pytest.raises(RequestRejected) as caught:
            parse_chat_completion_request(
                {"model": "m", "messages": [{"role": "user", "content": "x"}], "tools": []}
            )
        assert caught.value.code == "uninspectable_field"

    def test_the_evaluation_report_qualifies_its_own_numbers(self):
        """The report must not read as a clean bill of health.

        This assertion used to check for the literal string "FAIL", which passed
        while two entity pairs were below threshold and broke the moment they
        were fixed -- it was proxying for honesty via a word, and the word went
        away for a good reason.

        What has to remain true regardless of the numbers is that the report
        states what they do *not* cover: the corpus is synthetic, the supports
        are small, and at least one known gap appears in no figure at all
        because it is not in the corpus.
        """
        report = (ROOT / "docs" / "evaluation-report.md").read_text(encoding="utf-8")
        lowered = report.lower()

        assert "what these numbers are not" in lowered, "the report must carry its caveats section"
        assert "synthetic" in lowered
        assert "unhyphenated" in lowered, "the gap that appears in no number must still be named"
        assert "known weak classes" in lowered
        assert "real-partner text" in lowered or "real text" in lowered, (
            "the report must say what would actually validate it"
        )

    def test_the_evaluation_report_states_the_strength_of_its_holdout_evidence(self):
        """A holdout read twice is weaker evidence than one read once, and the
        report has to say which it is rather than letting a reader assume."""
        report = (ROOT / "docs" / "evaluation-report.md").read_text(encoding="utf-8")
        assert "holdout" in report.lower()
        assert "weaker evidence" in report.lower() or "read a second time" in report.lower()
