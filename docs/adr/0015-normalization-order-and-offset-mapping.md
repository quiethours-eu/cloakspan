# ADR-0015: Normalization order and offset mapping

**Status:** IMPLEMENTED · 2026-08-04 · `REQUIRES_SECURITY_REVIEW`
**Implementation:** `gateway/normalization/`, wired in
`gateway/inspection/pipeline.py`. Two decisions changed during implementation
and are amended in place below, each marked.
**Invariants:** [SI-17](../security-invariants.md#si-17--original-text-integrity),
[SI-01](../security-invariants.md#si-01--no-uninspected-egress),
[SI-02](../security-invariants.md#si-02--reject-unknown-content)

## Context

Two invariants currently contradict each other, and the code resolves the
contradiction by sacrificing one of them.

- [SI-01](../security-invariants.md#si-01--no-uninspected-egress) says nothing
  reaches the provider that was not inspected.
- [SI-17](../security-invariants.md#si-17--original-text-integrity) says text the
  gateway did not detect reaches the provider byte-identical to what the client
  sent.

The pipeline applies NFKC and then **forwards the normalized text**
([pipeline.py:212](../../gateway/inspection/pipeline.py)). The reasoning, from
the source, is correct as far as it goes:

> NFKC preserves length for the characters we care about in the common case, but
> *not* universally (ligatures expand). Because offsets can shift, the pipeline
> detects on normalised text and transforms the *same* normalised text — it never
> maps offsets back onto the raw original.

That buys SI-01 at the cost of SI-17. It is the right trade if you must pick one,
and it is why the current behaviour is deliberate rather than accidental. But it
means a customer's code block, signed payload, or carefully formatted document is
silently rewritten in transit, and there is no way for them to see that it
happened.

It is also **not sufficient for the evasion it was introduced to stop.** NFKC
folds fullwidth digits and ligatures. It does not fold Cyrillic `а` (U+0430) to
Latin `a`, and it does not strip zero-width or bidirectional control characters
(T4, R-04). An attacker writing a Latvian personal code with one Cyrillic digit
lookalike, or with a zero-width space inside it, evades every regex the product
owns — and the resulting text is forwarded, because nothing detected it.

So the current design pays the SI-17 cost and does not get the security benefit
it was paying for.

## Decision

Build a **detection-only view** with a reversible offset map. Detect on the view;
replace validated spans **in the original**; forward the original everywhere else.
This satisfies both invariants rather than trading them.

### 1 · Pipeline order

```
raw bytes
  → 1. decode UTF-8 strictly            (invalid → 422, fail closed)
  → 2. scan for suspicious encodings    (bidi controls, excess default-ignorables)
  → 3. build the detection view + offset map
         a. drop default-ignorable and zero-width characters
         b. NFKC
         c. fold confusables to a skeleton
  → 4. detect on the view
  → 5. map every span back to original offsets
  → 6. validate the mapped spans against the original
  → 7. policy, then replace mapped spans in the ORIGINAL text
  → 8. forward the original with only validated spans replaced
```

Each of 3a/3b/3c extends the same map. Order matters: stripping invisibles before
NFKC means `1​2` normalizes as `12`; the reverse order leaves the invisible
inside a normalized run and the digits stay unjoined.

### 2 · The offset map

For each character in the detection view, the map records the **half-open range of
original indices** it derives from. Two properties are required, and both are
testable:

- **Totality.** Every index in the original text is covered by exactly one map
  entry, including characters dropped in 3a. A dropped character is attached to
  the map entry of the character that follows it (or precedes it, at end of
  string). Nothing in the original is unreachable from the view.

  This is what preserves SI-01: the gateway forwards original bytes, but every
  original byte was accounted for during inspection.

  > **Amended.** Totality has exactly **one** exception, found by the property
  > test on the input `"\x08"`: when a message consists *entirely* of ignorable
  > characters the view is empty and no index is covered. That is sound — there
  > is nothing to detect because there is nothing visible — but an invariant
  > with an undocumented exception is worse than one with a documented one. The
  > property test now asserts the exception positively: an empty view is
  > legitimate only when every input character is ignorable.

- **Expansion.** A view span maps to the union of the original ranges of its
  characters. A detection over `1​2​3` in the view (`123`) maps back to
  the original span **including** both zero-width characters, so replacement
  removes them along with the digits. Leaving them behind would emit
  `<LV_PERSONAL_CODE:v1:…>​​`, which is both ugly and a signal to an
  attacker that their invisible characters survived.

### 3 · Span validation before replacement

Before any span is replaced in the original, it must satisfy
([domain.py:44](../../gateway/domain.py) already enforces the first two for the
view):

1. `0 <= start < end <= len(original)`.
2. The span does not overlap another mapped span — re-run `resolve_conflicts`
   **after** mapping, because two non-overlapping view spans can map to
   overlapping original ranges when dropped characters are attached.
3. The mapped original text, when passed through steps 3a–3c, reproduces the view
   text the detector matched.

**Check 3 is the load-bearing one.** It is what makes "only validated source
spans are replaced" true rather than aspirational: a mapping bug cannot cause the
wrong bytes to be replaced, because the replacement is rejected if the round trip
does not agree. A failed check is a `DetectionError` → 422, not a silent skip —
skipping would forward an entity we detected.

### 4 · Confusable folding

Fold to a skeleton using a **pinned, curated, strictly 1:1** confusable map in
the repository — not a runtime download and not an implicit dependency on the
host's ICU version, because the detection surface must not change when a base
image is rebuilt.

> **Amended.** Full UTS #39 maps some characters to multi-character sequences
> (`œ` → `oe`), which would make the folded view a different length from the
> view it derives from — a second offset map, composed with the first, on the
> most correctness-critical path in the product. The evasion we actually defend
> against is entirely 1:1: an attacker swaps a digit or letter for a visually
> identical Cyrillic or Greek one. So the map is **restricted to 1:1 by
> construction and verified at import**, the folded view shares indices with its
> source exactly, and a whole class of offset bug cannot exist. Multi-character
> confusables are not folded; `œ` and `oe` are not confusable in any identifier
> this product detects.

Folding raises false positives: `ldap` and `1dap` skeletonise together. That cost
is acceptable for identifier-shaped entities that carry a checksum, where a false
skeleton match still fails validation. It is **not** acceptable for dictionary
terms and NER, where a false positive tokenises ordinary text and degrades the
model's answer.

So folding is applied **per detector**, not globally: checksum-validated
detectors see the folded view, dictionary and NER detectors see the unfolded
(NFKC-only) view. Both views share one offset map.

### 5 · Suspicious encodings are blocked, not silently cleaned

Step 2 blocks the request when it finds:

- Bidirectional formatting controls (U+202A–U+202E, U+2066–U+2069) — the Trojan
  Source class. There is no legitimate use in a prompt that justifies the
  ambiguity between what a human reviewer sees and what the model receives.
- More than a configurable ratio of default-ignorable characters — invisible
  padding used to break up an identifier.
- Mixed-script confusion **within a single token**: a word containing characters
  from both Latin and Cyrillic scripts, excluding the Latin-plus-diacritics
  ranges Baltic languages legitimately use.

  > **Amended: this one signals, it does not block, unless the operator opts in
  > via `SAG_BLOCK_MIXED_SCRIPT`.** The reasoning is this ADR's own: a false
  > positive here refuses legitimate multilingual traffic in the exact market
  > the product is for, which is worse than the evasion it prevents. And the
  > evasion is already handled — confusable folding *detects and protects* the
  > identifier rather than refusing the request, which is a strictly better
  > outcome for the customer. Blocking would add refusals without adding
  > protection. It is recorded as an audit signal so an operator can see the
  > rate before deciding to enforce it.

Blocking returns 422 with an **audit reason code** —
`suspicious_encoding_bidi`, `suspicious_encoding_invisible`,
`suspicious_encoding_mixed_script` — and **no content**, per
[SI-11](../security-invariants.md#si-11--no-content-in-observability). The
operator learns that a request was refused and why, without the log becoming a
copy of the attack payload.

Mixed-script detection must be tested hard against Baltic text specifically.
`Bērziņa`, `Šiauliai`, and `Jõgeva` are ordinary Latin-with-diacritics and must
never trigger it. A false positive here blocks legitimate customer traffic in the
exact market the product is for, which is worse than the evasion it prevents.

## Alternatives considered

| Option | Rejected because |
|---|---|
| Status quo — forward normalized text | Silently rewrites customer content; still misses homoglyphs and invisibles |
| Forward the raw original, detect on normalized, replace by value | `str.replace` corrupts text that was never detected — "Ada" rewrites "Canada". The whole span discipline exists to avoid this |
| Reject any input where NFKC changes the text | Rejects legitimate content — fullwidth characters are ordinary in CJK text and appear in pasted documents |
| Normalize only when a detection occurs | The detection *is* what needs the normalized view. Circular |
| Depend on host ICU for confusables | Detection behaviour would change when the base image is rebuilt. Unacceptable for a control whose output is evidence |

## Consequences

**Security.** Closes SI-17 and R-04/T4. Removes "partially mitigated" as the
answer to the homoglyph question, which is the answer that loses a sales meeting.

**Correctness risk.** This is the highest-risk change in the plan. The offset map
sits between detection and replacement — a bug corrupts customer text or drops a
detection. Mitigations, in order of value:

1. Round-trip validation (check 3 above) makes a mapping bug fail closed.
2. Property test: for any input with no detections, the forwarded text is
   **byte-identical** to the input. This single property would catch most
   plausible bugs.
3. Property test: replacing every span and then reversing the replacement
   reproduces the original.
4. Fixture corpus: Cyrillic/Latin confusables, fullwidth forms, inserted
   controls, combining marks, ligatures, RTL text, and Baltic diacritics.

**Delivery.** ~4 engineer-days including the confusables data file and fixtures.
The largest single item in Phase 4.

**Measured outcome.** On corpus v1.1.0, the adversarial slice went from
**33% → 100%** recall on Latvian personal codes and **0% → 100%** on emails,
with **no new false positives** on the boundary corpus. Detection latency rose
from 3.9 ms to 13.8 ms p95 on a 4 KB request — 3.5×, against a 150 ms budget.
The cost is the round-trip check, which rebuilds a view per candidate span; that
is the price of the mitigation that makes a mapping bug fail closed, and it is
worth paying at this margin.

**Reversal cost.** Medium. The map is internal, but the *behaviour* — customers
receiving their own bytes back — becomes something they depend on.

## Note on ordering within the plan

The implementation plan sequences this as Phase 4, after detection (Phase 2) and
restoration hardening (Phase 3). That ordering is right for delivery risk, but the
**contract** belongs in Phase 0 — which is why this ADR exists now. NER detectors
built in Phase 2 must consume the detection view rather than raw text, and
retrofitting that later means rewriting every detector's interface after they are
already measured.
