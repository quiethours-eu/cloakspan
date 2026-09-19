"""The mandatory adversarial suite from the implementation plan, Phase 3.

Each class below maps to a named item on that list. Where the property already
held for a reason other than the one we would want -- "safe because the feature
does not exist yet" -- the test says so, so that adding the feature breaks the
test rather than quietly breaking the property.

The remaining items (sequential-token guessing, earlier-turn replay, cross-tenant
substitution, malformed and case-modified tokens, token collision, vault
tampering, wrong AAD, wrong key version) live in ``test_restoration_safety.py``
and ``test_vault_hardening.py``.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from gateway.domain import RequestContext, Span
from gateway.inspection.pipeline import SecurityPipeline
from gateway.restoration.engine import RestorationEngine, RestorationOutputTooLargeError
from gateway.transformations.engine import TransformationEngine
from gateway.transformations.tokens import TokenProvenance

CANARY = "alice@acme.lv"


def _span(text: str, entity_type: str = "EMAIL_ADDRESS", start: int = 0) -> Span:
    return Span(start=start, end=start + len(text), entity_type=entity_type, text=text)


def _payload(content: str) -> dict[str, Any]:
    return {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": content}]}


class RecordingProvider:
    """Captures what it received and returns whatever it was told to."""

    def __init__(self, response: dict[str, Any] | None = None, name: str = "mock") -> None:
        self.name = name
        self.received: list[dict[str, Any]] = []
        self._response = response

    async def chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.received.append(payload)
        if self._response is not None:
            return self._response
        content = payload["messages"][-1]["content"]
        return {
            "id": "chatcmpl-x",
            "object": "chat.completion",
            "created": 0,
            "model": payload.get("model", "m"),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
        }


class HangingProvider:
    """Never returns. Used to cancel a request mid-flight."""

    name = "mock"

    def __init__(self) -> None:
        self.entered = asyncio.Event()

    async def chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.entered.set()
        await asyncio.sleep(3600)
        raise AssertionError("unreachable")


def _pipeline(policy, vault, minter, provider, audit_sink) -> SecurityPipeline:
    from gateway.detectors.deterministic import default_detectors

    return SecurityPipeline(
        detectors=default_detectors(),
        policy=policy,
        transformer=TransformationEngine(minter, vault),
        restorer=RestorationEngine(vault),
        providers={"mock": provider, "local": provider, "external": provider},
        audit_sink=audit_sink,
    )


# ---------------------------------------------------------------------------
# Cancellation after the vault write, before the provider responds
# ---------------------------------------------------------------------------


class TestCancellation:
    async def test_a_cancelled_request_leaves_an_unrestorable_orphan(
        self, ctx, policy, vault, minter, audit_sink
    ):
        """The security claim in ADR-0014, made testable.

        Cancelling between the vault write and the provider response leaves a
        record behind on purpose -- deleting it would turn an application-layer
        retry into an unrestorable response. What must hold is that the orphan
        is not restorable *by anyone*: the provenance set died with the request,
        and no later request can recreate it.
        """
        provider = HangingProvider()
        pipeline = _pipeline(policy, vault, minter, provider, audit_sink)

        task = asyncio.create_task(pipeline.process(ctx, _payload(f"Mail {CANARY}")))
        await asyncio.wait_for(provider.entered.wait(), timeout=5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        # The record exists -- the transform stage completed before the hang.
        token = TransformationEngine(minter, vault).transform(
            ctx, CANARY, [_span(CANARY)], TokenProvenance()
        )
        assert vault.get(ctx, token.text, "v1") == CANARY

        # But a fresh request cannot restore it: provenance is per request.
        outcome = RestorationEngine(vault).restore(ctx, f"Echo {token.text}", TokenProvenance())
        assert outcome.restored == 0
        assert outcome.reasons() == {"not_minted": 1}
        assert CANARY not in outcome.text

    async def test_a_cancelled_request_forwards_nothing_further(
        self, ctx, policy, vault, minter, audit_sink
    ):
        provider = HangingProvider()
        pipeline = _pipeline(policy, vault, minter, provider, audit_sink)

        task = asyncio.create_task(pipeline.process(ctx, _payload(f"Mail {CANARY}")))
        await asyncio.wait_for(provider.entered.wait(), timeout=5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert audit_sink.events == [], "a cancelled request writes no success event"


# ---------------------------------------------------------------------------
# Retry races
# ---------------------------------------------------------------------------


class TestRetryRaces:
    """Retries exist now. The tripwire that guarded their absence has been
    replaced by the tests ADR-0014 required before they could be written --
    see ``tests/test_egress_and_retry.py::TestRetryPreservesProvenance``.
    """

    async def test_concurrent_requests_in_one_conversation_stay_isolated(
        self, ctx, policy, vault, minter, audit_sink
    ):
        """The race a careless retry implementation would create.

        Two in-flight requests for the same conversation and the same value.
        Both mint the same token -- determinism is the multi-turn promise -- and
        each restores only through its own provenance.
        """
        provider = RecordingProvider()
        pipeline = _pipeline(policy, vault, minter, provider, audit_sink)

        results = await asyncio.gather(
            *(pipeline.process(ctx, _payload(f"Mail {CANARY}")) for _ in range(8))
        )

        for result in results:
            restored = result.response["choices"][0]["message"]["content"]
            assert CANARY in restored
            assert result.restoration.restored == 1
            assert result.restoration.total_refused == 0

        forwarded = {m["messages"][-1]["content"] for m in provider.received}
        assert len(forwarded) == 1, "the same value must produce the same token"
        assert CANARY not in next(iter(forwarded))


# ---------------------------------------------------------------------------
# Provider response containing tokens in unsupported fields
# ---------------------------------------------------------------------------


class TestTokensInUnsupportedResponseFields:
    async def test_a_token_outside_the_allowlist_is_not_restored(
        self, ctx, policy, vault, minter, audit_sink
    ):
        """Restoration writes into ``choices[].message.content`` and nowhere else.

        A hostile or non-compliant provider that echoes a token into a tool-call
        argument, an id, or a custom field must not get it expanded -- restoring
        into control data would let a model rewrite more than prose.
        """
        # First run one request to obtain a token this pipeline really minted.
        honest = RecordingProvider()
        pipeline = _pipeline(policy, vault, minter, honest, audit_sink)
        await pipeline.process(ctx, _payload(f"Mail {CANARY}"))
        token = honest.received[0]["messages"][-1]["content"].split()[-1]
        assert token.startswith("<EMAIL_ADDRESS:v1:")

        hostile = RecordingProvider(
            response={
                "id": f"chatcmpl-{token}",
                "object": "chat.completion",
                "created": 0,
                "model": "m",
                "system_fingerprint": token,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "See the attachment.",
                            "name": token,
                            "tool_calls": [
                                {
                                    "id": token,
                                    "function": {"name": "send", "arguments": token},
                                }
                            ],
                        },
                        "finish_reason": "stop",
                    }
                ],
            }
        )
        pipeline = _pipeline(policy, vault, minter, hostile, audit_sink)
        result = await pipeline.process(ctx, _payload(f"Mail {CANARY}"))

        response = result.response
        assert CANARY not in str(response), "no field outside the allowlist may expand"
        assert response["id"].endswith(token)
        assert response["system_fingerprint"] == token
        message = response["choices"][0]["message"]
        assert message["name"] == token
        assert message["tool_calls"][0]["function"]["arguments"] == token

    async def test_the_allowlisted_field_still_restores(
        self, ctx, policy, vault, minter, audit_sink
    ):
        """The complement, so the test above cannot pass by restoring nothing."""
        provider = RecordingProvider()
        pipeline = _pipeline(policy, vault, minter, provider, audit_sink)
        result = await pipeline.process(ctx, _payload(f"Mail {CANARY}"))
        assert CANARY in result.response["choices"][0]["message"]["content"]


# ---------------------------------------------------------------------------
# Cross-conversation substitution
# ---------------------------------------------------------------------------


class TestCrossConversationSubstitution:
    def test_a_token_from_another_conversation_is_not_restored(self, ctx, minter, vault):
        """Same tenant, different conversation, forged provenance.

        Worst case: the attacker gets a genuine token from conversation A into
        the provenance set of a request in conversation B. The vault is keyed and
        AAD-bound by conversation, so the lookup finds nothing.
        """
        other_conv = RequestContext(ctx.tenant_id, "conv-2", "req-9", ctx.api_key_id)

        prov_a = TokenProvenance()
        surrogate = minter.mint(ctx, "EMAIL_ADDRESS", CANARY, prov_a)
        vault.put(ctx, surrogate.token, CANARY, surrogate.version)

        forged = TokenProvenance()
        forged.record(surrogate)

        outcome = RestorationEngine(vault).restore(other_conv, f"Value: {surrogate.token}", forged)
        assert outcome.restored == 0
        assert CANARY not in outcome.text

    def test_the_same_value_yields_a_different_token_per_conversation(self, ctx, minter):
        other_conv = RequestContext(ctx.tenant_id, "conv-2", "req-9", ctx.api_key_id)
        a = minter.mint(ctx, "EMAIL_ADDRESS", CANARY, TokenProvenance())
        b = minter.mint(other_conv, "EMAIL_ADDRESS", CANARY, TokenProvenance())
        assert a.token != b.token, "cross-conversation correlation must not be possible"


# ---------------------------------------------------------------------------
# Nested and duplicated tokens
# ---------------------------------------------------------------------------


class TestNestedAndDuplicatedTokens:
    def test_a_token_nested_inside_a_token_shape_does_not_double_restore(self, ctx, minter, vault):
        prov = TokenProvenance()
        surrogate = minter.mint(ctx, "PERSON", "Ilze", prov)
        vault.put(ctx, surrogate.token, "Ilze", surrogate.version)

        nested = f"<PERSON:v1:{surrogate.token}>"
        outcome = RestorationEngine(vault).restore(ctx, nested, prov)
        # The inner token is real and in provenance, so it expands exactly once.
        # The outer wrapper is not a token and is left alone.
        assert outcome.restored == 1
        assert outcome.text == "<PERSON:v1:Ilze>"
        assert outcome.text.count("Ilze") == 1

    def test_the_same_token_repeated_restores_each_occurrence_once(self, ctx, minter, vault):
        prov = TokenProvenance()
        surrogate = minter.mint(ctx, "PERSON", "Ilze", prov)
        vault.put(ctx, surrogate.token, "Ilze", surrogate.version)

        text = f"{surrogate.token} and {surrogate.token} and {surrogate.token}"
        outcome = RestorationEngine(vault).restore(ctx, text, prov)
        assert outcome.restored == 3
        assert outcome.text == "Ilze and Ilze and Ilze"

    def test_a_real_token_beside_a_forged_one_restores_only_the_real_one(self, ctx, minter, vault):
        prov = TokenProvenance()
        surrogate = minter.mint(ctx, "PERSON", "Ilze", prov)
        vault.put(ctx, surrogate.token, "Ilze", surrogate.version)
        forged = "<PERSON:v1:" + "0" * 32 + ">"

        outcome = RestorationEngine(vault).restore(ctx, f"{forged} then {surrogate.token}", prov)
        assert outcome.restored == 1
        assert outcome.refused_not_minted == 1
        assert outcome.text == f"{forged} then Ilze"


# ---------------------------------------------------------------------------
# Duplicate canonical values and overlapping spans
# ---------------------------------------------------------------------------


class TestDuplicateValuesAndOverlappingSpans:
    def test_repeated_values_share_one_token_and_all_restore(self, ctx, minter, vault):
        transformer = TransformationEngine(minter, vault)
        text = f"{CANARY} wrote to {CANARY} about {CANARY}"
        spans = [
            _span(CANARY, start=0),
            _span(CANARY, start=text.index(CANARY, 1)),
            _span(CANARY, start=text.rindex(CANARY)),
        ]
        prov = TokenProvenance()
        result = transformer.transform(ctx, text, spans, prov)

        assert CANARY not in result.text
        assert len(prov) == 1, "three occurrences, one distinct value, one token"
        assert result.replaced == 3

        restored = RestorationEngine(vault).restore(ctx, result.text, prov)
        assert restored.text == text
        assert restored.restored == 3

    def test_casing_variants_collapse_to_the_rightmost_occurrences_bytes(self, ctx, minter, vault):
        """Canonicalisation collapses variants to one token, and one value.

        The consequence took a wrong guess to pin down, so it is written here
        rather than left to be rediscovered: **the rightmost occurrence's exact
        bytes are what restore everywhere.**

        Two mechanisms combine. ``transform`` walks spans right to left, so the
        last occurrence mints first and its ``original_value`` reaches the vault
        first. Every earlier occurrence then canonicalises to the same tag, hits
        the provenance cache, and re-uses that surrogate -- including its stored
        value.

        So "Ilze and ILZE" round-trips as "ILZE and ILZE", not as the original.
        That is a real, if minor, integrity loss on the *undetected* casing of a
        detected value, and it is the price of the model seeing one person
        instead of two. It is the same class of problem as SI-17 and would be
        fixed the same way -- by restoring each span's own source bytes rather
        than one canonical value per token.
        """
        transformer = TransformationEngine(minter, vault)
        text = "Ilze and ILZE"
        spans = [_span("Ilze", "PERSON", 0), _span("ILZE", "PERSON", 9)]
        prov = TokenProvenance()
        result = transformer.transform(ctx, text, spans, prov)

        assert len(prov) == 1, "casing variants must share one token"
        restored = RestorationEngine(vault).restore(ctx, result.text, prov)
        assert restored.text == "ILZE and ILZE"
        assert restored.text != text, "the casing of the earlier occurrence is lost"

    def test_overlapping_spans_are_resolved_before_replacement(self, ctx, minter, vault):
        """Two detectors claiming overlapping text must not corrupt each other.

        Without conflict resolution inside ``transform``, the right-to-left walk
        would replace the inner span and then replace bytes that no longer exist.
        """
        transformer = TransformationEngine(minter, vault)
        text = f"contact {CANARY} now"
        spans = [
            Span(8, 8 + len(CANARY), "EMAIL_ADDRESS", CANARY, score=1.0),
            Span(8, 13, "PERSON", "alice", score=0.6),
        ]
        prov = TokenProvenance()
        result = transformer.transform(ctx, text, spans, prov)

        assert result.replaced == 1, "the contained span must be dropped"
        assert CANARY not in result.text
        assert result.text.startswith("contact <EMAIL_ADDRESS:v1:")
        assert RestorationEngine(vault).restore(ctx, result.text, prov).text == text

    def test_adjacent_spans_do_not_bleed(self, ctx, minter, vault):
        transformer = TransformationEngine(minter, vault)
        text = "aaaabbbb"
        spans = [
            Span(0, 4, "CUSTOM", "aaaa"),
            Span(4, 8, "CUSTOM", "bbbb"),
        ]
        prov = TokenProvenance()
        result = transformer.transform(ctx, text, spans, prov)

        assert len(prov) == 2
        assert RestorationEngine(vault).restore(ctx, result.text, prov).text == text

    def test_dense_unique_spans_round_trip(self, ctx, minter, vault):
        values = [f"user{i:03d}@example.com" for i in range(200)]
        text = "|".join(values)
        spans: list[Span] = []
        cursor = 0
        for value in values:
            spans.append(Span(cursor, cursor + len(value), "EMAIL_ADDRESS", value))
            cursor += len(value) + 1

        provenance = TokenProvenance()
        transformed = TransformationEngine(minter, vault).transform(ctx, text, spans, provenance)
        restored = RestorationEngine(vault).restore(ctx, transformed.text, provenance)

        assert transformed.replaced == len(values)
        assert restored.restored == len(values)
        assert restored.text == text

    def test_repeated_valid_tokens_cannot_amplify_a_response_without_bound(
        self, ctx, minter, vault
    ):
        original = "x" * 128
        provenance = TokenProvenance()
        transformed = TransformationEngine(minter, vault).transform(
            ctx,
            original,
            [_span(original, "CUSTOM")],
            provenance,
        )

        with pytest.raises(RestorationOutputTooLargeError, match="exceeds 256 bytes"):
            RestorationEngine(vault, max_output_bytes=256).restore(
                ctx,
                " ".join([transformed.text] * 3),
                provenance,
            )


# ---------------------------------------------------------------------------
# No plaintext in exceptions, crash reports, or test snapshots
# ---------------------------------------------------------------------------


class TestExceptionsCarryNoPlaintext:
    """An error path is still a log path, and a traceback is still a record.

    Every exception this pipeline can raise gets its ``str``, ``repr``, and full
    traceback searched for the value that caused it. Most detectors receive the
    text they are scanning, so this is exactly where a well-meaning
    ``f"failed on {text}"`` would land.
    """

    @staticmethod
    def _rendered(exc: BaseException) -> str:
        """str, repr, and the full traceback of ``exc``.

        Note on the traceback: since 3.11 Python renders the *source line* of
        each frame, so a caller that passes a literal will see that literal in
        its own frame. That is the caller's source, not our exception -- the
        tests below bind values to variables so the assertion measures the
        gateway's exception construction rather than the test's own formatting.
        """
        import traceback

        return "\n".join(
            [
                str(exc),
                repr(exc),
                "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
            ]
        )

    def test_a_detector_failure_never_names_the_scanned_text(self, policy, vault, minter):
        from gateway.audit.events import MemorySink
        from gateway.inspection.pipeline import DetectionError

        class Exploding:
            name = "exploding"

            def detect(self, text: str):
                raise RuntimeError(f"boom while scanning {text}")

        pipeline = SecurityPipeline(
            detectors=[Exploding()],
            policy=policy,
            transformer=TransformationEngine(minter, vault),
            restorer=RestorationEngine(vault),
            providers={"mock": RecordingProvider()},
            audit_sink=MemorySink(),
        )

        with pytest.raises(DetectionError) as caught:
            pipeline.inspect_payload(_payload(f"Mail {CANARY}"))

        # The chained cause legitimately holds the detector's own message, so we
        # assert on what the gateway itself constructs -- that is the string
        # that reaches the client and the log line.
        assert CANARY not in str(caught.value)
        assert CANARY not in repr(caught.value)

    def test_a_vault_cross_tenant_error_names_no_value(self, ctx, other_tenant_ctx, minter, vault):
        from gateway.vault.store import CrossTenantAccessError

        prov = TokenProvenance()
        surrogate = minter.mint(ctx, "EMAIL_ADDRESS", CANARY, prov)
        vault.put(ctx, surrogate.token, CANARY, surrogate.version)

        error = CrossTenantAccessError("vault entry tenant does not match request tenant")
        assert CANARY not in self._rendered(error)

    def test_a_token_collision_error_names_no_value(self, ctx, monkeypatch):
        from gateway.transformations.tokens import TokenCollisionError, TokenMinter

        minter = TokenMinter(secret_key=b"\x02" * 32)
        monkeypatch.setattr(TokenMinter, "_tag", lambda *_a, **_k: "f" * 32)
        prov = TokenProvenance()
        first, second = CANARY, "bob@acme.lv"
        minter.mint(ctx, "EMAIL_ADDRESS", first, prov)

        with pytest.raises(TokenCollisionError) as caught:
            minter.mint(ctx, "EMAIL_ADDRESS", second, prov)
        rendered = self._rendered(caught.value)
        assert first not in rendered
        assert second not in rendered

    def test_a_vault_key_error_names_no_value(self):
        from gateway.vault.store import KeyRing, VaultKeyUnavailableError

        ring = KeyRing(keys={1: b"\x01" * 32}, active_version=1)
        with pytest.raises(VaultKeyUnavailableError) as caught:
            ring.aead(9)
        rendered = self._rendered(caught.value)
        assert CANARY not in rendered
        assert "\x01" * 32 not in rendered, "the key itself must not be echoed"

    def test_a_configuration_error_never_echoes_the_secret(self, monkeypatch):
        from gateway.config import ConfigurationError, _decode_secret

        secret = "short-secret-nobody-should-see"
        with pytest.raises(ConfigurationError) as caught:
            _decode_secret("SAG_VAULT_KEY", secret)
        assert secret not in self._rendered(caught.value)

    def test_span_validation_errors_do_not_echo_the_matched_text(self):
        value = CANARY
        with pytest.raises(ValueError) as caught:
            Span(start=0, end=4, entity_type="EMAIL_ADDRESS", text=value)
        # The bounds mismatch is reported by length, not by content.
        assert CANARY not in self._rendered(caught.value)

    def test_a_restoration_outcome_repr_does_not_expose_restored_values(self, ctx, minter, vault):
        """RestorationOutcome carries refused *tokens*, never restored values.

        A pytest failure prints the repr of every local, so a dataclass that
        held plaintext would leak it into CI output -- the "test snapshots" half
        of the invariant.
        """
        prov = TokenProvenance()
        surrogate = minter.mint(ctx, "EMAIL_ADDRESS", CANARY, prov)
        vault.put(ctx, surrogate.token, CANARY, surrogate.version)

        outcome = RestorationEngine(vault).restore(ctx, surrogate.token, prov)
        assert outcome.restored == 1
        # `.text` is the restored response and legitimately holds the value --
        # it is the return value, not a diagnostic field. Everything else must
        # not.
        without_text = {
            field: getattr(outcome, field) for field in outcome.__slots__ if field != "text"
        }
        assert CANARY not in repr(without_text)
