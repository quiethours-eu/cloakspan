# Detection Evaluation Report

**Corpus:** v2.0.0 · **Read:** 2026-08-04 · **Status:** all thresholds pass

This is the report the product plan requires before detection quality may be
described to anyone. It contains the bad numbers as well as the good ones,
because a buyer who finds a problem we already documented trusts the rest of the
document, and one who finds a problem we hid does not.

**Read "What these numbers are not" before quoting any figure here.** The
headline is 100% across the board, and the most useful thing this report can
tell you is why that number is weaker evidence than it looks.

---

## What changed in v2.0.0, and why it matters

The v1.x holdout was not a holdout. Both splits drew from the same template
lists and differed only in the random seed, so the "held-out" set was the dev set
with different digits substituted in: **30 of its 66 unique texts were
byte-identical to dev**, and `dev-lv-pos-0001` and `hol-lv-pos-0001` were the
same sentence. Every v1.x holdout figure was therefore a re-measurement of dev,
reported as independent corroboration.

v2.0.0 rebuilds the holdout from **its own template, name, organisation, and city
pools**. No example, and no sentence shape, is shared between the two splits;
this is now enforced by `test_splits_do_not_share_examples` and
`test_splits_do_not_share_sentence_shapes` rather than by a docstring.

**On its first run the new holdout found a real defect.** An export date-stamp,
`20231104-11220`, was reported as a `PAYMENT_CARD`: the pattern permitted a
separator at any position, and roughly one such digit string in ten also
satisfies Luhn. `PAYMENT_CARD` precision on the holdout read **50%**. The pattern
now requires a card-shaped grouping — contiguous, fours, or the Amex 4-6-5 — and
the case is pinned by `test_a_date_stamp_is_not_a_payment_card`.

That single finding is the best argument in this document for treating the rest
of it sceptically: the defect had been present all along, and a corpus that
paraphrased itself could never have surfaced it.

Also new in v2.0.0: the seven credential entities that carried published
thresholds while appearing in **no example** now have coverage. Because
precision and recall both return 1.0 on a zero denominator, those thresholds had
been reporting themselves as met for detectors the corpus never ran.

---

## The headline

| | Dev | Holdout |
|---|---|---|
| Entity/language pairs passing threshold | **all** | **all** |
| Aggregate precision / recall | 100% / 100% | 100% / 100% |
| Gold spans scored | 66 | 48 |
| Entities with coverage | 15 of 15 | 15 of 15 |
| Adversarial (Unicode evasion) recall | 100% | 100% |
| **Known-gap recall** (deliberate non-detection) | **0%** | **0%** |
| Gate | passes | passes |

The known-gap row is not a failure. It is an unlabelled phone number, which the
product has decided not to detect, now measured instead of merely mentioned —
see below.

---

## Holdout results, per entity

Corpus v2.0.0, 75 examples scored, 48 gold spans. **Read the support column.**

| Entity | Precision | Recall | Gold | FP | Verdict |
|---|---|---|---|---|---|
| `EMAIL_ADDRESS` | 100% | 100% | 9 | 0 | PASS |
| `IBAN` | 100% | 100% | 9 | 0 | PASS |
| `PHONE_NUMBER` | 100% | 100% | 8 | 0 | PASS |
| `BALTIC_PERSONAL_CODE` | 100% | 100% | 4 | 0 | PASS |
| `LV_PERSONAL_CODE` | 100% | 100% | 4 | 0 | PASS |
| `EE_PERSONAL_CODE` | 100% | 100% | 3 | 0 | PASS |
| `LT_PERSONAL_CODE` | 100% | 100% | 2 | 0 | PASS |
| `PAYMENT_CARD` | 100% | 100% | 2 | 0 | PASS |
| `AWS_ACCESS_KEY` | 100% | 100% | 1 | 0 | PASS |
| `PRIVATE_KEY` | 100% | 100% | 1 | 0 | PASS |
| `JWT` | 100% | 100% | 1 | 0 | PASS |
| `OPENAI_API_KEY` | 100% | 100% | 1 | 0 | PASS |
| `ANTHROPIC_API_KEY` | 100% | 100% | 1 | 0 | PASS |
| `GITHUB_TOKEN` | 100% | 100% | 1 | 0 | PASS |
| `SLACK_TOKEN` | 100% | 100% | 1 | 0 | PASS |

The seven credential rows are new in v2.0.0 and each rests on a **support of 1**.
That is coverage — proof the detector runs and the threshold is capable of
failing — not a measurement of credential-detection quality. Before v2.0.0 these
entities had thresholds and no examples, which reported as a permanent silent
pass.

### Known gaps, scored separately

| Entity | Precision | Recall | Gold | Reason |
|---|---|---|---|---|
| `PHONE_NUMBER` | 100% | **0%** | 2 | national format with no context word |

**Latency:** 11.3 ms p95 for a 4 KB request against a 150 ms budget. This was a
developer-machine measurement, **not** a published reference-hardware result.

---

## Earlier: the Lithuanian/Estonian label collapse (corpus v1.1.0 → v1.2.0)

Retained because it is the clearest worked example of the gate doing its job.

The v1.1.0 read failed two pairs: Lithuanian personal codes
scored **0% recall** and Estonian **60% precision**, because the two are the same
construction with the same check digit and conflict resolution kept the Estonian
label for every code.

The recogniser now reads **country context** — the identifier's own name
(`asmens kodas`, `isikukood`) within a 64-character window, falling back to
document-level markers (country and city names, `+370`/`+372`, IBAN prefixes,
`.lt`/`.ee`) when the identifier is unnamed. Where nothing indicates a country it
emits **`BALTIC_PERSONAL_CODE`** rather than guessing.

That last part is the point. A coin-flip label on a personal identifier looks
authoritative and is wrong half the time, and a wrong country on a personal
identifier is the kind of error that ends up in a regulatory filing.

**It cost nothing in protection.** `BALTIC_PERSONAL_CODE` is scored CERTAIN — the
checksum makes the *detection* certain, only the *label* is uncertain — and the
shipped policy routes it to the local model alongside the three country-specific
labels. A test asserts every label the detector can emit is routed there, because
adding the fallback without adding it to the policy would have sent exactly the
codes we are least sure about to the external provider.

---

## ⚠️ The holdout figures are weaker evidence than they look

Stated plainly, because the table above would otherwise overclaim.

The v2.0.0 holdout is the first one that is genuinely disjoint from dev — its own
templates, its own names, organisations, and cities. That is a real improvement
over v1.x, where the holdout was a paraphrase of dev and its agreement with dev
meant nothing.

It is nonetheless **not** "read once, never seen":

- It was read, it reported a `PAYMENT_CARD` precision of 50%, the underlying
  detector bug was fixed, and it was read again. The fix addressed a structural
  property — a card is written in card-shaped groups — rather than the specific
  failing example, and no holdout text was tuned against. But a second read is
  a weaker claim than a first, and nobody should treat this 100% as equivalent
  to 100% on an untouched set.
- One boundary example was corrected in the same change, because it was wrong:
  `5500000000000004` is a published Mastercard test number and passes Luhn, and
  it had been sitting in the corpus labelled "fails Luhn". That was an authoring
  error in the corpus, not a detector finding.

**The honest summary:** dev and holdout agree at 100/100 on v2.0.0 over 15
entities; the disjoint holdout immediately paid for itself by finding a real
false positive; and the strongest available evidence for the *next* detector
change would be a third split that has never been read. Real-partner text under
a data-processing agreement remains the measurement that actually matters, and
none of the numbers here substitute for it.

---

## Dev and holdout agree

| | Dev | Holdout |
|---|---|---|
| Examples scored | 92 | 66 |
| Aggregate precision / recall | 100% / 100% | 100% / 100% |
| Failing pairs | none | none |
| Adversarial recall | 100% | 100% |

Disjoint seeds and value pools. The agreement is expected rather than
impressive at this corpus size — see the support column, and the caveats below.

---

## What these numbers are not

This is the section that decides whether the rest of the report can be trusted.

**The corpus is synthetic.** Every identifier is computed from a published
check-digit algorithm; every name and company is invented. That is a deliberate
choice — a privacy product should not hold real personal data — and it has a
real cost: **the corpus over-represents patterns we already thought of.** It
measures whether the detectors do what we believe. It does not measure whether
reality resembles our beliefs.

**The measurement is partly circular, and this is the most important caveat.**
The generator computes its identifiers from the same published check-digit
algorithms the detectors validate against — the Latvian weight tuple in
`evals/datasets/generate.py` is the same tuple as in
`recognizers/baltic/personal_codes.py`, and the IBAN builder is the exact
inverse of `iban_valid`. When the detector agrees with the generator, that
demonstrates the code is self-consistent. It is not evidence about detection
quality, and it should never be presented as such.

What the corpus *does* measure honestly:

- **Span segmentation** — whether the right substring is found, at the right
  offsets, surrounded by punctuation, other entities, and text in four
  languages. This is where real bugs have actually been caught.
- **Precision against boundary and negative cases**, which are written by hand
  and derived from no detector. The payment-card false positive was found here.

**The corpus is small.** 101 dev and 75 holdout examples scored, with per-entity
support in single or low double digits — seven entities rest on a support of 1.
One missed span moves recall by ten points or more. A 100% here means "no
failures in one to thirteen examples", not "99% confidence of 99% recall".
Anyone quoting these figures without the support column is misrepresenting them.

**Contextual entities are absent, not failing.** `PERSON`, `ORG`, `LOCATION`,
and `ADDRESS` carry no gold spans, because no detector emits them: the NER
adapter is written and tested, but no model artefact ships. They appear in the
corpus text — 37 examples contain an invented person or company name — and are
**not counted as misses**. Recall above is therefore recall *over the entity
types the product already detects*. When NER ships, the reported numbers **will
drop sharply**; that is the measurement starting to work, not a regression.

**One deliberate gap is now measured rather than described.** An unlabelled
national-format phone number — `"Anna Kalniņa, 25938547, Rīgas birojs."` — is not
detected, because a context word (`tālr.`, `tel.`, `mob.`, `phone`) is what
separates a phone number from an order number. `PHONE_NUMBER` recall was lowered
to 0.90 to pay for that concession, and until v2.0.0 no example exercised it, so
the lowered threshold measured nothing. It now appears in a **Known gaps**
section that `make evals` prints, at 0% recall on both splits.

**Latvian codes are now detected in both forms.** The hyphenated `DDMMYY-XXXXX`
and the bare eleven-digit form a database extract produces. The bare form is
ambiguous with the Lithuanian and Estonian construction — roughly one Latvian
code in eleven satisfies both check-digit rules — and where the digits and the
surrounding text cannot settle it, the label falls back to
`BALTIC_PERSONAL_CODE`. The fallback costs a name, not protection: all four
labels route locally under the shipped policy.

**Spaced IBANs are now detected.** `LV80 BANK 0000 4351 9500 1`, the form banks
actually print, was previously missed because the pattern was contiguous while
the validator already stripped spaces.

**Secrets are scored here as of v2.0.0**, one example per entity, on top of the
leakage suite and unit tests. A support of 1 is coverage, not confidence.

**Real-text validation has not happened.** Running against real Baltic business
text with a design partner, under a data-processing agreement, is a pilot
deliverable. Nothing in this report substitutes for it.

---

## Known weak classes, in priority order

1. **Country attribution depends on context that may not be there.** Every
   Lithuanian and Estonian code is detected regardless, but a document that
   names neither country gets `BALTIC_PERSONAL_CODE`. In this corpus that is 6
   of 13 Baltic codes on dev. In a customer's document set the proportion is
   unknown, and it is the first thing to measure in a pilot: if most real
   documents are unattributed, the country-specific labels are close to
   decorative.
2. **Unhyphenated Latvian codes** — undetected, and unmeasured. Likely the most
   commercially damaging gap, because it will show up in a customer's first real
   document rather than in a test.
3. **Contextual entities** — not implemented. The product's canonical example
   ("Ask Ilze from Acme Latvia about contract LV-2026-0042") still misses both
   the person and the company.
4. **Multi-character confusables** — `œ` does not fold to `oe`. Deliberate: the
   fold is strictly 1:1 so the folded view shares indices with its source, which
   removes a class of offset bug. Not confusable in any identifier we detect.
5. **`PHONE_NUMBER` recall on unlabelled numbers** — a number with no country
   code and no nearby context word is not detected, by design. The corpus
   supplies context in every case, so the reported 100% recall **does not
   measure this trade-off**. Threshold is 95/90 rather than 99/99 for exactly
   this reason.
6. **`JWT` and `OPENAI_API_KEY` false positives** — documentation samples and
   `sk-` prefixed identifiers. Rated Medium FP cost in the taxonomy; not
   represented in the corpus.

---

## Reproducing this

```bash
make evals            # dev split, strict labelling. Exits non-zero
make evals-aliased    # dev split, LT and EE merged
make evals-holdout    # the locked split. Read deliberately, not routinely
```

The corpus is regenerated deterministically by `make corpus`; CI asserts the
committed files match the generator byte for byte, so a silent edit to the
corpus is not possible.

---

## What would change these numbers

| Change | Effect |
|---|---|
| ~~Merge LT/EE into one advertised class~~ | Would have passed the gate by lowering the claim. Not taken |
| ~~Add country context to the Baltic recogniser~~ | **Done.** Gate passes with the labels intact |
| ~~Add unhyphenated Latvian codes to the corpus~~ | **Done (v2.0.0).** The form is now detected *and* measured, so recall held rather than falling |
| ~~Give the holdout its own template pool~~ | **Done (v2.0.0).** Found a real `PAYMENT_CARD` false positive on the first run |
| Annotate the person and organisation names already in the corpus | Aggregate recall **falls sharply** — 37 examples contain an undetected name today, uncounted. Blocked on NER shipping, and the honest precursor to it |
| Measure how often real documents carry country context | Would tell us whether attribution is useful or decorative |
| Ship NER | Aggregate numbers fall sharply as four unmeasured entities start being scored |
| Real-partner text under a DPA | The only change that tests whether any of this survives contact |

The last row is the one that matters, and it is the one this report cannot
provide.
