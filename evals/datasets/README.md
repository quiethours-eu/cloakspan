# Evaluation corpus

**Version:** 1.0.0 · generated 2026-08-03 by `python -m evals.datasets.generate`

## Provenance and licence

**Every example is synthetic.** This repository contains no real personal data,
and none may ever be added to it.

| Content | Source | Licence |
|---|---|---|
| Personal identity codes (LV, LT, EE) | Computed from the published national check-digit algorithms | The algorithms are public specifications; the values are generated |
| IBANs | Computed with ISO 13616 mod-97, fictional `BANK` institution code | Generated |
| Payment cards | Computed with Luhn mod-10 from a `4xxx` prefix | Generated |
| Email addresses | `example.lv` / `example.lt` / `example.et` — reserved by RFC 2606 | Generated |
| Personal names | A fixed list of invented names, plausible for each language | Original to this repository, Apache-2.0 with the rest |
| Organisations, cities | Invented companies; real city names, which are not personal data | Original / public |
| Sentence templates | Written for this corpus | Original, Apache-2.0 |

No text was scraped, copied from a customer, or derived from a third-party
dataset. There is nothing here to attribute and nothing here to leak.

## What this corpus is honest about

**It over-represents what we already thought of.** It measures whether the
detectors do what we believe they do — not whether reality resembles our
beliefs. A detector that handles every template here can still fail on the first
real customer document, because real Baltic business text has formatting,
abbreviation, and code-switching habits that no generator invents.

Real-text validation with a design partner under a data-processing agreement is
a pilot deliverable. It is not replaced by this corpus, and any published
precision/recall figure must say which one it came from.

**It is small.** 87 dev and 63 holdout examples. Large enough to catch a broken
detector, far too small for a confidence interval. Per-entity supports are in
single or low double digits, so one missed span moves recall by ten points or
more. Treat the numbers as a regression signal, not a measurement of the field.

## Layout

```
dev/       lv.jsonl lt.jsonl et.jsonl en.jsonl VERSION
holdout/   lv.jsonl lt.jsonl et.jsonl en.jsonl VERSION
```

Format and the meaning of each `kind` are documented in
[schema.py](schema.py).

## Split discipline

`dev` is for tuning. **`holdout` is locked.**

Generated from disjoint seeds so the holdout set is not a paraphrase of dev.
Reading it while a detector is being changed turns the number it produces into a
description of the detectors rather than a measurement of them — so
`run_evals.py` prints a warning when the holdout split is loaded, and the
warning is the point.

Thresholds are frozen in [../run_evals.py](../run_evals.py) **before** any
holdout result is read.

## Regenerating

```bash
python -m evals.datasets.generate
```

Deterministic: the same version and seeds reproduce the files byte for byte. The
generator refuses to write if any boundary fixture turns out to be
checksum-*valid*, which it verifies from the published algorithms rather than by
asking our own detectors — a check added after the first eval run flagged a
false positive that turned out to be a bad fixture, not a bad detector.

Bump `CORPUS_VERSION` on any change to the generator. A corpus that changes
without its version changing makes two eval reports incomparable.

## Known limitations, listed rather than discovered

1. **No contextual entities are gold-labelled.** `PERSON`, `ORG`, `LOCATION`,
   and `ADDRESS` appear in the text but carry no gold spans, because no detector
   emits them. Labelling entities nothing can produce would report 0% recall for
   a capability we have never claimed. They become gold spans when
   `gateway/detectors/ner.py` ships, and the reported numbers will drop sharply
   at that moment — that is the measurement working, not a regression.
2. **Lithuanian and Estonian codes are structurally identical**, so the
   Lithuanian gold label is unachievable under strict scoring. See
   `../scoring.py` and `docs/entity-taxonomy.md`.
3. **Latvian codes appear in both forms** as of v2.0.0 — hyphenated, and the bare
   eleven-digit form that database extracts produce. Adding the second one did
   not cost recall, because the detector was extended in the same change.
4. **Secrets are represented** as of v2.0.0, one example per entity, on top of
   `evals/leakage/` and `tests/test_detectors.py`. Before that, seven credential
   entities carried published thresholds and appeared in no example, which
   reported as a permanent silent pass because precision and recall both return
   1.0 on a zero denominator.
5. **Adversarial examples are Latvian only** and cover four evasion techniques.
   A Phase 4 corpus needs bidi controls, combining marks, and mixed-script cases
   per language.
