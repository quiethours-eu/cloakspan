"""Audit and logging hygiene.

Security invariants SI-11 (raw content is not logged), SI-12 (provider
credentials never appear in logs), and SI-13 (security-critical actions generate
audit evidence). See docs/security-invariants.md.

The canary technique: put a unique string into the request, then assert it
appears nowhere in the serialised audit event or captured log output. This
catches accidental leakage through any field, including ones added later.
"""

from __future__ import annotations

import json
import logging

import pytest

from gateway.inspection.pipeline import PolicyBlockedError

CANARY_EMAIL = "canary-do-not-log@secret-domain.example"
CANARY_TEXT = "ZZZ-CANARY-PROMPT-CONTENT-ZZZ"


def payload(content: str) -> dict:
    return {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": content}]}


class TestAuditContainsNoRawContent:
    async def test_prompt_text_never_appears_in_audit_event(self, pipeline, ctx, audit_sink):
        await pipeline.process(ctx, payload(f"{CANARY_TEXT} contact {CANARY_EMAIL}"))

        assert len(audit_sink.events) == 1
        serialised = audit_sink.events[0].to_json()
        assert CANARY_TEXT not in serialised
        assert CANARY_EMAIL not in serialised
        assert "canary" not in serialised.lower()

    async def test_blocked_request_audit_contains_no_secret(self, pipeline, ctx, audit_sink):
        secret = "AKIAIOSFODNN7EXAMPLE"
        with pytest.raises(PolicyBlockedError):
            await pipeline.process(ctx, payload(f"key is {secret}"))

        assert len(audit_sink.events) == 1, "a blocked request must still be audited"
        serialised = audit_sink.events[0].to_json()
        assert secret not in serialised
        assert audit_sink.events[0].decision == "block"

    async def test_audit_records_counts_and_types_not_values(self, pipeline, ctx, audit_sink):
        await pipeline.process(ctx, payload("Mail alice@acme.lv and bob@acme.lv"))
        event = audit_sink.events[0]
        assert event.entity_counts == {"EMAIL_ADDRESS": 2}
        assert event.entities_transformed == 2
        assert "alice" not in event.to_json()

    async def test_audit_records_policy_version(self, pipeline, ctx, audit_sink):
        """Required so a decision can be reproduced later."""
        await pipeline.process(ctx, payload("hello"))
        assert audit_sink.events[0].policy_version == "test-v1"
        assert audit_sink.events[0].rule_name == "default-allow"

    async def test_audit_records_restoration_outcome(self, pipeline, ctx, audit_sink):
        await pipeline.process(ctx, payload("Mail alice@acme.lv"))
        event = audit_sink.events[0]
        assert event.restoration_performed is True
        assert event.tokens_restored >= 1

    async def test_raw_content_logged_flag_is_false(self, pipeline, ctx, audit_sink):
        await pipeline.process(ctx, payload("hello"))
        assert audit_sink.events[0].raw_content_logged is False

    def test_audit_event_has_no_extensible_field(self):
        """Structural guarantee, not a discipline guarantee.

        AuditEvent uses slots and an explicit field list, so there is no dict
        into which a future change could quietly place prompt text.
        """
        from gateway.audit.events import AuditEvent

        assert getattr(AuditEvent, "__slots__", None) is not None
        field_names = set(AuditEvent.__dataclass_fields__)
        for forbidden in ("extra", "metadata", "content", "prompt", "messages", "raw"):
            assert forbidden not in field_names


class TestNoCredentialLeakage:
    async def test_provider_error_does_not_include_credentials(self):
        """ProviderError must never carry the URL or key.

        httpx exception strings routinely include the full request URL, which
        can carry credentials in a query string. We assert the message shape.
        """
        from gateway.routing.base import OpenAICompatibleProvider, ProviderError
        from gateway.routing.egress import EgressPolicy

        provider = OpenAICompatibleProvider(
            base_url="http://127.0.0.1:9/v1",  # closed port -> connection error
            api_key="sk-super-secret-key-value",
            timeout_seconds=1.0,
            # Loopback needs an explicit local policy now: an `external`
            # destination resolving to 127.0.0.1 is refused at startup.
            egress=EgressPolicy(name="test", allow_private=True),
            max_retries=0,
        )
        with pytest.raises(ProviderError) as caught:
            await provider.chat_completion({"model": "m", "messages": []})

        message = str(caught.value)
        assert "sk-super-secret-key-value" not in message
        assert "127.0.0.1" not in message

    async def test_logs_do_not_contain_prompt_content(self, pipeline, ctx, caplog):
        with caplog.at_level(logging.DEBUG):
            await pipeline.process(ctx, payload(f"{CANARY_TEXT} here"))
        assert CANARY_TEXT not in caplog.text


class TestAuditSerialisation:
    async def test_event_is_valid_json(self, pipeline, ctx, audit_sink):
        await pipeline.process(ctx, payload("Mail alice@acme.lv"))
        parsed = json.loads(audit_sink.events[0].to_json())
        assert parsed["tenant_id"] == "tenant-a"
        assert parsed["request_id"] == "req-1"
        assert parsed["decision"] == "transform"
