# ADR-0016: Equality leakage of deterministic pseudonyms

**Status:** Accepted · 2026-08-04 · `REQUIRES_SECURITY_REVIEW`
**Invariants:** [SI-03](../security-invariants.md#si-03--current-request-restoration-only),
[SI-06](../security-invariants.md#si-06--unguessable-token-identity)
**Plan deliverable:** Phase 3 — *"Documented equality-leakage behaviour of
deterministic pseudonyms and a decision on whether it is acceptable."*

## Context

Tokens are deterministic within a (tenant, conversation): the same value always
yields the same token. That is not incidental — it is what lets the model reason
about identity. Without it, "Ilze" becomes `<PERSON:v1:a…>` in one sentence and
`<PERSON:v1:b…>` in the next, the model sees two people, and the answer is wrong
in a way the customer notices immediately.

Determinism has a cost that has never been written down, and the plan is right
to demand it in writing before anyone sells against it.

## What actually leaks

**To the model provider, within one conversation:**

1. **Equality.** Two occurrences of the same token mean the same underlying
   value. The provider learns that turn 1 and turn 40 concern the same person
   without learning who.
2. **Cardinality.** How many distinct people, organisations, or accounts a
   conversation involves.
3. **Entity type.** The token carries it in clear: `<LV_PERSONAL_CODE:v1:…>` says
   a Latvian personal code was present. This is deliberate — the model needs it
   to produce sensible prose — but it is disclosure.
4. **Position and frequency.** Where in the text each value appears, and how
   often. Combined with the surrounding prose this can be informative: a token
   that appears only next to "the claimant" is the claimant.
5. **Co-occurrence structure.** Which values appear together, which is the shape
   a social graph is built from.

**What does not leak:**

- The values themselves. That is the product.
- Equality **across conversations**, because the conversation id is in the HMAC
  input. The same person in two conversations gets two unrelated tokens.
- Equality **across tenants**, for the same reason.
- Anything derivable from the tag without the key: it is HMAC-SHA256 truncated to
  128 bits, so a provider cannot invert it, cannot enumerate it, and cannot test
  a guess offline against a value it suspects — the tag depends on a secret it
  does not hold.

**A subtler one, worth stating because it is easy to miss:** a provider that sees
the same token in two *requests* of the same conversation learns those requests
are linked. Provenance stops that token being *restored* across requests; it does
not stop the provider correlating them. Restoration safety and privacy against
the provider are different properties, and only the first is enforced by
provenance.

## The alternatives, and what they cost

| Option | Leaks equality? | Cost |
|---|---|---|
| **Deterministic per conversation** *(chosen)* | Yes, within a conversation | None to usability |
| Randomised per occurrence | No | The model sees N people instead of one. Multi-turn reasoning breaks; summarisation and drafting produce visibly wrong output. Restoration still works, so this fails on usefulness, not safety |
| Deterministic per request | Within a request only | Multi-turn identity breaks at the turn boundary — the model cannot connect "Ilze" in turn 5 to turn 4 |
| Realistic synthetic surrogates | Yes, and worse | A surrogate that looks like a real name is indistinguishable from one, so a leak of the *surrogate* looks like real data to everyone downstream. Explicitly out of scope in v1 |
| Format-preserving encryption | Yes, identically | Same equality leak, plus a custom cryptographic construction. No benefit here |

Randomised-per-occurrence is the only option that closes the leak, and it closes
it by making the product not work.

## Decision

**Accept the leak, scoped to one conversation, and state it plainly in
customer-facing material.**

Specifically:

1. Determinism stays scoped to (tenant, conversation, entity type, canonical
   value, token version). It is never widened — in particular, a
   deployment-wide deterministic mode would leak equality across every
   conversation and every user, and must not be offered as a "consistency"
   feature.
2. `docs/entity-taxonomy.md` and the README state that a provider learns
   *whether* two mentions are the same, and *which type* of entity each is.
3. Customers for whom equality disclosure is itself unacceptable are directed to
   the `route_local` policy action, which is the honest answer: if the fact that
   two prompts concern the same person is sensitive, the prompt should not reach
   a third-party model at all. The default policy already routes Baltic personal
   codes this way.
4. Shortening the conversation lifetime reduces the window in which equality is
   observable, which is a second reason the vault TTL is a privacy control and
   not just a memory bound ([ADR-0013](0013-vault-lifetime-deletion-and-restart.md)).

## Why this is acceptable, stated as an argument rather than an assertion

The comparison that matters is not "deterministic pseudonyms versus perfect
privacy". It is **deterministic pseudonyms versus what the customer does
today**, which is sending the raw prompt. Against that baseline the gateway
removes the values and leaves the equality structure.

An attacker who holds only the transformed prompts learns a graph with no
labels. Re-identifying a node requires an external correlation — knowing that a
particular conversation concerns a particular case — at which point they have
the answer from the outside, not from us.

The residual is real and it is not zero. It belongs in the threat model as a
stated residual, not as a solved problem, and it is on the agenda for the
independent review.

## Consequences

**Product.** No code change. This ADR is a decision plus a disclosure
obligation.

**Documentation.** README, `docs/entity-taxonomy.md`, and `docs/threat-model.md`
(T18) must carry it. A customer who finds this in our documentation trusts the
rest; one who works it out themselves does not.

**Sales.** "Pseudonymisation" must never be described as "anonymisation" —
GDPR Recital 26 is explicit that pseudonymised data remains personal data, and
equality-preserving pseudonyms are squarely within that. Any material claiming
otherwise is a compliance problem for the customer and a credibility problem for
us.

**Review.** Named for the Phase 7 reviewer, alongside the tag-width question in
[ADR-0011](0011-token-format-and-versioning.md).

## Open question for the independent reviewer

> Is per-conversation equality disclosure to the model provider an acceptable
> residual for a product sold as a privacy control to regulated European
> buyers — given that the only alternative that closes it makes multi-turn
> reasoning unusable? We have accepted it and documented it. We would like the
> disclosure wording checked by someone who did not write it.
