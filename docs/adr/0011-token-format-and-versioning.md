# ADR-0011: Token format, tag width, and versioning

**Status:** PROPOSED · 2026-08-03 · `REQUIRES_SECURITY_REVIEW`
**Supersedes the token-format portion of ADR-0005.**
**Invariants:** [SI-06](../security-invariants.md#si-06--unguessable-token-identity),
[SI-07](../security-invariants.md#si-07--unambiguous-token-derivation),
[SI-05](../security-invariants.md#si-05--cross-tenant-isolation-is-cryptographic-not-control-flow)

## Context

ADR-0005 settled the token *design* — HMAC-derived tag, provenance-checked
restoration — and the implementation has shipped and is tested. Two things it did
not settle have since become blocking.

**1. The tag is 64 bits; the implementation plan mandates 128.** The plan's
invariant #4 requires "at least a 128-bit security/collision margin unless an
independent review approves another value". The shipped tag is
`HMAC-SHA256(...)[:8]` — 64 bits
([tokens.py:69](../../gateway/transformations/tokens.py)).

**2. Tokens carry no version.** `<PERSON:3f9a1c7d2b8e4f60>` encodes an entity
type and a tag and nothing else. Any change to tag width, derivation, or entity
naming is a breaking change with no way to distinguish old tokens from new ones,
and no way to bind a token version into the vault AAD as
[SI-05](../security-invariants.md#si-05--cross-tenant-isolation-is-cryptographic-not-control-flow)
requires.

The existing 64-bit argument, from the module docstring, is not unreasonable:

> This is a *forgery* resistance problem, not a collision resistance problem: an
> attacker must produce a tag matching a specific (tenant, conversation, entity,
> value) tuple without the key. 64 bits is far beyond feasible online guessing,
> and the token must also survive the provenance check.

Both halves are true. An attacker guessing a tag must land it **within the single
request that mints it**, because provenance refuses everything else — so the
attack is not "guess 2⁶³ times offline", it is "guess correctly on the first try,
in this request". Accidental collisions are separately caught by an explicit
check that raises rather than overwrites
([tokens.py:156](../../gateway/transformations/tokens.py)).

The counter-argument is not that 64 bits is breakable. It is that:

- The birthday bound is what actually matters for the collision check, and it is
  2³² tokens, not 2⁶³. A busy tenant is not close to that, but the margin is
  smaller than the number suggests.
- "64 bits" is a number a buyer's security team will circle in a review, and the
  defence requires explaining provenance first. **Defending an unusual choice
  costs more in this market than the eight extra bytes cost in the payload.**
- Going from 64 to 128 bits costs 16 additional characters per token. On a 4 KB
  prompt with 20 entities that is 320 characters — roughly 80 tokens of context,
  under 2% of a typical prompt. It is not a meaningful cost.

## Decision

**1. Version every token.** The format becomes:

```
<ENTITY_TYPE:v1:TAG>
```

`v1` is the token-format version, matched by an anchored pattern exactly as
today. The version is bound into the HMAC input and into the vault AAD, closing
the SI-05 gap. Tokens of an unknown version are **never** restored — they fail
the pattern match and are left verbatim, which is already the safe default.

**2. Tag width is `v1` = 128 bits (32 hex characters) by default.**

> **Amended during implementation.** This ADR originally kept the 64-bit form as
> a read-only `v0` until pre-migration records expired. That was written before
> checking what such records exist: the default vault backend is in-memory and
> there is no deployment, so `v0` support would have been dead code guarding a
> corpus of zero. It is not implemented. A token of any version this build does
> not know fails `TOKEN_PATTERN` and is left verbatim, which is the safe default
> and is asserted directly by `test_malformed_tokens_are_not_restored`.

**3. The 64-bit alternative stays formally open until the Phase 7 review.** If the
independent reviewer accepts the forgery-vs-collision argument in writing, `v1`
may be re-specified at 64 bits before any release. This ADR is PROPOSED, not
Accepted, for exactly that reason — and versioning is what makes the decision
reversible either way.

**4. HMAC input encoding is unchanged and is now frozen.** Each field is
UTF-8 encoded, length-prefixed as `<byte-length>:`, and NUL-joined
([tokens.py:130](../../gateway/transformations/tokens.py)):

```
HMAC-SHA256(key, "4:acme\x00" + "6:conv42\x00" + "6:PERSON\x00" + "12:ilze bērziņa")
```

with the token version appended as a fifth field in `v1`. Raw concatenation is
prohibited: without length prefixing a tenant named `acme\x00x` collides with
tenant `acme` in conversation `x`, and the collision restores one customer's data
into another's response. This is
[SI-07](../security-invariants.md#si-07--unambiguous-token-derivation) and it is
the property most likely to be broken by a well-meaning refactor.

**5. Canonicalisation is part of the format, not an implementation detail.**
NFKC → whitespace collapse → casefold
([tokens.py:72](../../gateway/transformations/tokens.py)). Changing it changes
every token for the same input, so it is versioned with the token.

## Alternatives considered

| Option | Rejected because |
|---|---|
| Keep 64 bits, unversioned | Leaves SI-05 (version binding) unclosed and makes any future change breaking. The tag width is arguable; having no version is not |
| 256-bit tag | 64 characters per token. Real context cost, no threat it addresses that 128 does not |
| Random token ids, mapping held only in the vault | Loses determinism: the same value must yield the same token within a conversation, or the model sees three different people. Also makes the vault the sole authority, removing the HMAC defence |
| Version as a prefix (`<v1:PERSON:tag>`) | Entity type first reads better in a prompt and keeps the existing pattern shape; the model sees `<PERSON:` and treats it as a name-like placeholder |

## Consequences

**Security.** Closes the version half of SI-05. Removes the standing objection
to SI-06. Makes the tag width a versioned, reversible decision rather than a
one-way door.

**Compatibility.** Breaking for any token minted before the change. Because the
default vault TTL is one hour and the default backend is in-memory, in practice
this affects only conversations in flight during a deploy. Those tokens are left
verbatim in the response — the safe failure — rather than mis-restored.

**Delivery.** ~1 engineer-day: pattern, minter, AAD, and the property tests that
already cover round-tripping. `tests/test_properties_and_fuzz.py` must gain a case
asserting a `v0` token is not restored once `v0` support is removed.

**Reversal cost.** Low from here, because the version field exists. High if
deferred — which is the argument for doing it before the corpus of live tokens
exists rather than after.

## Open question for the independent reviewer

> Given per-request provenance as the primary control, is a 64-bit HMAC tag
> acceptable, or is 128 bits required? We have implemented 128 as the default and
> versioned the format so either answer is cheap to adopt. We are asking for the
> answer in writing because SI-06 currently reads "unless an independent review
> approves another value", and no such approval exists.
