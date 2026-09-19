"""Property-based and fuzz tests.

Example-based tests prove the cases we thought of. These target the cases we
did not -- which, for a transformation/restoration pair operating on
attacker-controlled text, is where the bugs live.
"""

from __future__ import annotations

import json

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from gateway.detectors.base import resolve_conflicts
from gateway.domain import RequestContext, Span
from gateway.restoration.engine import RestorationEngine
from gateway.transformations.engine import TransformationEngine
from gateway.transformations.tokens import (
    TOKEN_PATTERN,
    TokenMinter,
    TokenProvenance,
    canonicalize,
)
from gateway.vault.store import KeyRing, SurrogateVault

from .conftest import TOKEN_KEY, VAULT_KEY

CTX = RequestContext("tenant-a", "conv-1", "req-1", "key-1")

SLOW = settings(
    max_examples=200,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None,
)


def fresh() -> tuple[TransformationEngine, RestorationEngine, SurrogateVault]:
    vault = SurrogateVault(key_ring=KeyRing(keys={1: VAULT_KEY}, active_version=1))
    minter = TokenMinter(secret_key=TOKEN_KEY)
    return TransformationEngine(minter, vault), RestorationEngine(vault), vault


# ---------------------------------------------------------------------------
# Round-trip properties
# ---------------------------------------------------------------------------


@given(
    prefix=st.text(max_size=50),
    value=st.text(min_size=1, max_size=40).filter(lambda s: "<" not in s and ">" not in s),
    suffix=st.text(max_size=50),
)
@SLOW
def test_transform_then_restore_is_identity(prefix, value, suffix):
    """The core round-trip property: restore(transform(x)) == x."""
    assume("<" not in prefix and ">" not in prefix)
    assume("<" not in suffix and ">" not in suffix)

    transformer, restorer, _ = fresh()
    text = prefix + value + suffix
    span = Span(len(prefix), len(prefix) + len(value), "CUSTOM", value)

    prov = TokenProvenance()
    transformed = transformer.transform(CTX, text, [span], prov)
    restored = restorer.restore(CTX, transformed.text, prov)

    assert restored.text == text


@given(
    values=st.lists(
        # Alphabet deliberately excludes [0-9a-f] and "v": a token is
        # <ENTITY:v1:lower-case-hex>, so a short value drawn from those
        # characters would appear inside the token by chance and make the
        # "value is gone" assertion vacuous.
        st.text(min_size=1, max_size=15, alphabet="ghijklmnopqrstuwxyz"),
        min_size=1,
        max_size=6,
        unique=True,
    )
)
@SLOW
def test_multiple_spans_round_trip_without_offset_corruption(values):
    """Many replacements in one string must not corrupt each other's offsets."""
    transformer, restorer, _ = fresh()

    # Separator is punctuation only, so it can never contribute a character
    # from the value alphabet and make the leakage assertion below vacuous.
    separator = " | "
    parts, spans, cursor = [], [], 0
    for value in values:
        parts.append(separator)
        cursor += len(separator)
        spans.append(Span(cursor, cursor + len(value), "CUSTOM", value))
        parts.append(value)
        cursor += len(value)
    text = "".join(parts)

    prov = TokenProvenance()
    transformed = transformer.transform(CTX, text, spans, prov)
    for value in values:
        assert value not in transformed.text

    assert restorer.restore(CTX, transformed.text, prov).text == text


@given(value=st.text(min_size=1, max_size=30))
@SLOW
def test_minting_is_deterministic(value):
    minter = TokenMinter(secret_key=TOKEN_KEY)
    a = minter.mint(CTX, "PERSON", value, TokenProvenance())
    b = minter.mint(CTX, "PERSON", value, TokenProvenance())
    assert a.token == b.token


@given(value=st.text(min_size=1, max_size=30))
@SLOW
def test_minted_tokens_always_parse(value):
    minter = TokenMinter(secret_key=TOKEN_KEY)
    token = minter.mint(CTX, "PERSON", value, TokenProvenance()).token
    assert TOKEN_PATTERN.fullmatch(token) is not None


@given(a=st.text(min_size=1, max_size=20), b=st.text(min_size=1, max_size=20))
@SLOW
def test_canonicalization_is_idempotent(a, b):
    assert canonicalize(canonicalize(a)) == canonicalize(a)
    if canonicalize(a) == canonicalize(b):
        minter = TokenMinter(secret_key=TOKEN_KEY)
        assert (
            minter.mint(CTX, "P", a, TokenProvenance()).token
            == minter.mint(CTX, "P", b, TokenProvenance()).token
        )


# ---------------------------------------------------------------------------
# Fuzzing the token parser -- the attacker-facing surface
# ---------------------------------------------------------------------------


@given(text=st.text(max_size=200))
@SLOW
def test_restoration_never_restores_arbitrary_text(text):
    """No input, however adversarial, restores anything from an empty provenance."""
    _, restorer, _ = fresh()
    outcome = restorer.restore(CTX, text, TokenProvenance())
    assert outcome.restored == 0
    assert outcome.text == text


@given(
    entity=st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ_", max_size=20),
    version=st.sampled_from(["", "v0", "v1", "v2", "V1", "1"]),
    tag=st.text(alphabet="0123456789abcdefABCDEFxyz", max_size=34),
)
@SLOW
def test_token_shaped_garbage_is_never_restored(entity, version, tag):
    """Anything token-*shaped* is refused unless we actually minted it.

    The version component is fuzzed alongside the tag: a build that accepted an
    unknown format version would be trusting a rule it does not implement.
    """
    _, restorer, _ = fresh()
    candidate = f"<{entity}:{version}:{tag}>" if version else f"<{entity}:{tag}>"
    outcome = restorer.restore(CTX, f"text {candidate} text", TokenProvenance())
    assert outcome.restored == 0
    assert candidate in outcome.text


@given(text=st.text(max_size=300))
@SLOW
def test_token_pattern_terminates_and_does_not_crash(text):
    """The parser must be total: no exception, no hang, on any input."""
    assert isinstance(list(TOKEN_PATTERN.finditer(text)), list)


# ---------------------------------------------------------------------------
# Conflict resolution invariants
# ---------------------------------------------------------------------------


@given(
    raw=st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=80),
            st.integers(min_value=1, max_value=20),
            st.sampled_from(["EMAIL_ADDRESS", "PERSON", "IBAN"]),
            st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
        ),
        max_size=12,
    )
)
@SLOW
def test_resolved_spans_never_overlap(raw):
    spans = [
        Span(start, start + length, entity, "x" * length, score)
        for start, length, entity, score in raw
    ]
    resolved = resolve_conflicts(spans)
    for i, first in enumerate(resolved):
        for second in resolved[i + 1 :]:
            assert not first.overlaps(second)


def _naive_resolve(spans: list[Span]) -> list[Span]:
    """The original O(n**2) implementation, kept as the reference.

    `resolve_conflicts` decides what is protected and what is forwarded, so an
    optimisation there is only acceptable if it is *indistinguishable*.
    Asserting the new implementation's own invariants would not catch a change
    that is self-consistent and different; only comparing against the previous
    behaviour does.
    """
    if not spans:
        return []
    ranked = sorted(
        spans,
        key=lambda s: (-s.score, -s.length, s.start, s.entity_type, s.detector),
    )
    kept: list[Span] = []
    for span in ranked:
        if any(existing.overlaps(span) for existing in kept):
            continue
        kept.append(span)
    return sorted(kept, key=lambda s: (s.start, s.end))


@given(
    raw=st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=80),
            st.integers(min_value=1, max_value=20),
            st.sampled_from(["EMAIL_ADDRESS", "PERSON", "IBAN"]),
            st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
            st.sampled_from(["det_a", "det_b"]),
        ),
        max_size=40,
    )
)
@SLOW
def test_conflict_resolution_matches_the_reference_implementation(raw):
    """The fast path must produce exactly what the old path produced.

    The binary-search version replaced a full scan of the kept set, which was
    O(n**2) and cost 4.4 s on a 256 KB request -- 85% of the detection path.
    Speed is not a reason to change *which* spans survive, so this pins that it
    does not: same spans, same order, on random overlapping input including ties
    on score, length, entity type, and detector.
    """
    spans = [
        Span(start, start + length, entity, "x" * length, score, detector)
        for start, length, entity, score, detector in raw
    ]
    assert resolve_conflicts(list(spans)) == _naive_resolve(list(spans))


@given(
    raw=st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=50),
            st.integers(min_value=1, max_value=10),
            st.sampled_from(["A", "B"]),
            st.floats(min_value=0.1, max_value=1.0, allow_nan=False),
        ),
        max_size=10,
    )
)
@SLOW
def test_conflict_resolution_is_deterministic(raw):
    """Policy decisions must be reproducible, so resolution cannot depend on
    iteration order."""
    spans = [Span(s, s + n, e, "x" * n, sc) for s, n, e, sc in raw]
    first = resolve_conflicts(list(spans))
    for _ in range(5):
        assert resolve_conflicts(list(reversed(spans))) == first


# ---------------------------------------------------------------------------
# JSON safety
# ---------------------------------------------------------------------------


@given(value=st.text(min_size=1, max_size=30).filter(lambda s: "<" not in s and ">" not in s))
@SLOW
def test_transformed_content_remains_json_serialisable(value):
    """Tokens must never break the JSON envelope we hand to the provider."""
    transformer, _, _ = fresh()
    text = f"prefix {value} suffix"
    span = Span(7, 7 + len(value), "CUSTOM", value)
    result = transformer.transform(CTX, text, [span], TokenProvenance())

    payload = {"model": "m", "messages": [{"role": "user", "content": result.text}]}
    reparsed = json.loads(json.dumps(payload))
    assert reparsed["messages"][0]["content"] == result.text
