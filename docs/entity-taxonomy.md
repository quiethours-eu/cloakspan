# Entity Taxonomy

**Status:** FROZEN for v1 · 2026-08-03

The complete list of entity types the gateway can emit, with severity, detector
type, language coverage, default policy action, and false-positive cost.

**The rule this document enforces:** the advertised support matrix must exactly
match measured capability. An entity type appears in marketing only when it
appears here as **Advertised**, and it becomes Advertised only when
`make evals` reports it above threshold on the locked holdout set.

## Column meanings

| Column | Meaning |
|---|---|
| **Severity** | What a leak of one instance costs. Drives the default action, not the detection order |
| **Detector** | `checksum` (deterministic + validated), `pattern` (deterministic, shape only), `ner` (statistical), `dictionary` (customer-supplied exact terms) |
| **Conf.** | Score the detector assigns. Policy rules filter on `min_score` |
| **Default** | Action in `deployment/policies/default.yaml` |
| **FP cost** | What a false positive does to the customer. High FP cost means the customer turns the detector off, at which point protection is zero |
| **Status** | `Shipped` (detects today) · `Measured` (detects and has published precision/recall) · `Advertised` (Measured and above threshold) · `Absent` (not implemented) |

Five entities are now **Measured** against corpus v1.1.0. None is yet
**Advertised**: that requires passing on the *locked holdout* set, which has
deliberately not been read. See [§ Measurement status](#measurement-status).

---

## Tier 1 — Credentials and secrets

A leaked credential is not a privacy incident, it is an access incident. These
are **blocked, never tokenised**: pseudonymising a secret leaves the value in the
vault, restores it into the response, and produces a credential leak with extra
steps. The value is also useless to the model.

| Entity | Severity | Detector | Conf. | Languages | Default | FP cost | Status |
|---|---|---|---|---|---|---|---|
| `AWS_ACCESS_KEY` | Critical | pattern (prefix-anchored: AKIA/ASIA/AIDA/AROA/AIPA/ANPA/ANVA/ABIA + 16) | CERTAIN | any | **block** | Low — the prefix set is specific | Shipped |
| `PRIVATE_KEY` | Critical | pattern (PEM block) | CERTAIN | any | **block** | Low | Shipped |
| `JWT` | Critical | pattern (`eyJ` + two base64url segments) | CERTAIN | any | **block** | **Medium** — a JWT in a prompt is often a *sample* token from documentation. Blocking a doc example is a visible annoyance | Shipped |
| `OPENAI_API_KEY` | Critical | pattern (`sk-` / `sk-proj-` + 20) | CERTAIN | any | **block** | Medium — `sk-` is short; a hyphenated identifier of the right shape collides | Shipped |
| `ANTHROPIC_API_KEY` | Critical | pattern (`sk-ant-` + 20) | CERTAIN | any | **block** | Low | Shipped |
| `GITHUB_TOKEN` | Critical | pattern (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 36) | CERTAIN | any | **block** | Low | Shipped |
| `SLACK_TOKEN` | Critical | pattern (`xox[baprs]-`) | CERTAIN | any | **block** | Low | Shipped |

Source: [recognizers/secrets/detectors.py](../recognizers/secrets/detectors.py).

**Known gaps:** no Google/GCP service-account keys, no Azure keys, no Stripe
keys, no generic high-entropy string detection, no `.env`-style
`KEY=value` recognition. A customer pasting a `docker-compose.yml` is not
protected by this tier.

---

## Tier 2 — National identifiers

National identifiers directly identify a person and may need stricter handling
under an organisation's policy. Default action for the supported types is
**route to the local model** rather than pseudonymise. Current built-in coverage
is Latvia, Lithuania, and Estonia; this is a coverage boundary, not a geographic
restriction on use of the gateway.

| Entity | Severity | Detector | Conf. | Languages | Default | FP cost | Status |
|---|---|---|---|---|---|---|---|
| `LV_PERSONAL_CODE` (legacy `DDMMYY-XXXXX`) | High | **checksum** — mod-11 weighted, plus date plausibility | CERTAIN | lv | **route_local** | Low | Shipped |
| `LV_PERSONAL_CODE` (post-2017 `32xxxx-xxxxx`) | High | pattern — the national spec defines no equivalent checksum | MEDIUM | lv | **route_local** | **Medium** — no checksum to lean on. Reported at MEDIUM rather than claiming certainty | Shipped |
| `LT_PERSONAL_CODE` | High | **checksum** + country context | CERTAIN | lt | **route_local** | Low | Measured — 100/100 |
| `EE_PERSONAL_CODE` | High | **checksum** + country context | CERTAIN | et | **route_local** | Low | Measured — 100/100 |
| `BALTIC_PERSONAL_CODE` | High | **checksum**, country undetermined | CERTAIN | lt, et | **route_local** | Low | Measured — 100/100 |

Source: [recognizers/baltic/personal_codes.py](../recognizers/baltic/personal_codes.py).
These do not exist in Presidio, which ships 18 country packages and none for
Latvia, Lithuania, or Estonia.

### How LT and EE are told apart

They cannot be told apart from their digits. Both are eleven digits with a
leading 1–6, and the **published specifications use the same two-pass check
digit** — so every valid Lithuanian code is also a valid Estonian one. That is a
fact about the identifiers, not a limitation of this implementation.

Attribution therefore comes from context, in two scopes:

| Scope | Signal | Strength |
|---|---|---|
| **Local** (64 chars before) | The identifier's own name: `asmens kodas`, `asmens kodą`, `a.k.` / `isikukood`, `isikukoodi` | Decisive. A document containing a personal code almost always names it, in the issuing country's language |
| **Document** | `Lietuv…`/`Estonia`, city stems, `+370`/`+372`, `LT…`/`EE…` IBAN prefixes, `.lt`/`.ee` | Used only when the identifier is unnamed, and only when exactly one country is indicated |

Nearest term wins, not "terms present": in a document listing an Estonian client
and then a Lithuanian one, the second code's window still contains the first
client's `isikukood`, and treating that as a conflict would refuse to label a
number whose own term sits three words away.

**Where nothing indicates a country, the label is `BALTIC_PERSONAL_CODE`.** Not a
guess. A coin-flip label on a personal identifier looks authoritative and is
wrong half the time, and a wrong country on a personal identifier is the kind of
error that ends up in a regulatory filing.

Two properties keep this from costing protection, both asserted by tests:

- `BALTIC_PERSONAL_CODE` is scored **CERTAIN**. The checksum makes the detection
  certain; only the label is uncertain. Scoring it lower would let a policy with
  a `min_score` filter skip it — losing protection over a naming question.
- The shipped policy routes **all four** labels to the local model.
  `test_every_label_the_detector_emits_is_routed_by_the_shipped_policy` fails if
  a new label is added without a policy entry.

**Open question for a pilot:** in this corpus, 6 of 13 Baltic codes on the dev
split carry no country context. The proportion in real customer documents is
unknown, and if it is high the country-specific labels are close to decorative.

### Both Latvian forms are detected, and the second one is ambiguous

`_LV_PATTERN` matches the printed `DDMMYY-XXXXX`. `_LV_PLAIN_PATTERN` matches the
bare eleven-digit form that database extracts and ERP exports produce, which was
previously missed entirely and is the form most likely to appear in a prompt
pasted out of a finance system.

The bare form is **not structurally distinct** from the Lithuanian and Estonian
construction, and roughly one Latvian code in eleven satisfies both national
check-digit rules. `_plain_code_label` resolves it in order of evidence: only-LV
accepts → Latvian; both accept and context names LT or EE → that country; both
accept and context points at Latvia → Latvian; otherwise
`BALTIC_PERSONAL_CODE`. The fallback costs a label, not protection — all four
labels route locally under the shipped policy.

---

## Tier 3 — Financial identifiers

| Entity | Severity | Detector | Conf. | Languages | Default | FP cost | Status |
|---|---|---|---|---|---|---|---|
| `IBAN` | High | **checksum** — ISO 13616 mod-97 | CERTAIN | any | **transform** | Low — mod-97 is decisive | Shipped |
| `PAYMENT_CARD` | High | **checksum** — Luhn mod-10, 13–19 digits | CERTAIN | any | **transform** | **Medium** — Luhn is only a 1-in-10 filter, so long numeric runs (order ids, concatenated references) still pass at a real rate | Shipped |

Source: [gateway/detectors/deterministic.py](../gateway/detectors/deterministic.py).
The checksum is what makes these usable. Without it the pattern fires on any
13–19 digit run and the customer disables the detector.

---

## Tier 4 — Contact and network identifiers

| Entity | Severity | Detector | Conf. | Languages | Default | FP cost | Status |
|---|---|---|---|---|---|---|---|
| `EMAIL_ADDRESS` | Medium | pattern (RFC-practical, not RFC-complete) | CERTAIN | any | **transform** (`min_score` 0.5) | Low | Shipped |
| `IP_ADDRESS` | Low | pattern (IPv4 only) | **MEDIUM** | any | none — falls to catch-all `allow` | **High** — most IPs in prompts are documentation examples, private ranges, or infrastructure the customer is debugging. Tokenising them makes the model useless for the ops use case | Shipped |
| `PHONE_NUMBER` | Medium | pattern — numbering-plan validation, plus a required context word for national formats | CERTAIN (with `+CC`) / HIGH (national) | lv, lt, et, en | none by default | Managed by the context rule; see below | **Measured** — 100% P / 100% R on dev v1.1.0 |

### How `PHONE_NUMBER` buys precision, and what it costs

There is no checksum for a telephone number. Length and prefix are all the
structure a numbering plan gives, and *any* eight-digit run satisfies the Baltic
plans — so a shape-only recogniser flags every order number, quantity, and part
number in every prompt, and the customer switches it off.

So [recognizers/baltic/phone_numbers.py](../recognizers/baltic/phone_numbers.py)
detects only when **either** an explicit country code is present with a valid
national length, **or** a context word (`tālr.`, `tel.`, `mob.`, `telefonas`,
`phone`, …) appears within 24 characters before the number.

The cost is real and is the reason this entity's threshold is asymmetric —
**95% precision, 90% recall**, where the other deterministic detectors are held
to 99/99. An unlabelled number in a signature block is missed by design.
Demanding 99% recall here would force dropping the context rule, and the first
customer demo would tokenise an invoice.

`IP_ADDRESS` is deliberately scored MEDIUM and deliberately not in any default
rule. It is available for customers who add a rule for it. Detecting something
and choosing not to act on it is a policy decision, and the audit event records
the count either way.

---

## Tier 5 — Contextual entities

**The adapter exists; no model ships.** `gateway/detectors/ner.py` is
implemented, tested, and wired into `build_detectors` behind
`SAG_NER_MODEL_PATH`. It enforces three rules: no runtime download (the model is
loaded by *path*, never by package name), checksum verification against a
committed manifest before loading, and **fail closed when enabled but
unavailable** — a configured-but-broken model is a startup failure, never a
silent degradation to deterministic-only detection.

**No model artefact is in this repository**, so with the default configuration
the entities below are still not detected. Selecting one is a Detection-owner
decision with a licence review attached: the candidate multilingual spaCy models
are MIT or CC BY-SA, and the difference matters to a customer redistributing a
container.

| Entity | Severity | Detector | Languages planned | Default (planned) | FP cost | Status |
|---|---|---|---|---|---|---|
| `PERSON` | High | ner | lv, lt, et, en | transform | Medium | **Absent** |
| `ORG` | Medium | ner | lv, lt, et, en | transform | **High** — over-tokenising organisation names destroys the model's ability to answer business questions | **Absent** |
| `LOCATION` | Medium | ner | lv, lt, et, en | transform | High — same reason | **Absent** |
| `ADDRESS` | High | ner + pattern | lv, lt, et, en | transform | Medium | **Absent** |

⚠️ **`deployment/policies/default.yaml` already lists `PERSON` in the
`pseudonymise-personal-data` rule.** No detector emits it, so that rule matches
only on `EMAIL_ADDRESS` and `CUSTOMER_TERM` today. The policy is not wrong — it is
forward-declared — but anyone reading it will reasonably assume PERSON detection
exists. The quickstart and the support matrix must say plainly that it does not.

This is the gap that matters commercially. The product's canonical example is
*"Ask Ilze from Acme Latvia about contract LV-2026-0042"*: today the contract
reference is caught by a customer rule, and **both the person and the company are
missed**.

---

## Tier 6 — Customer-defined

The capability a generic PII engine cannot provide: a customer knows "Project
Aurora" is confidential and no pretrained model does.

| Entity | Severity | Detector | Conf. | Default | FP cost | Status |
|---|---|---|---|---|---|---|
| `CUSTOMER_TERM` | Customer-defined | **dictionary** — exact, case-insensitive, longest-first | CERTAIN | **transform** (`min_score` 0.5) | Customer-controlled | Shipped (inactive unless `SAG_DICTIONARY_TERMS` is set) |
| *customer-named* | Customer-defined | **regex**, validated for length and nested unbounded quantifiers | HIGH | none by default | Customer-controlled | Shipped (inactive unless `SAG_CUSTOM_PATTERNS` is set) |

Source: [recognizers/custom/customer_rules.py](../recognizers/custom/customer_rules.py).

Dictionary matching uses word-boundary lookarounds rather than value replacement,
so a term like `Ada` does not corrupt `Canada` or `Adapter`. Customer regexes are
attacker-adjacent input — they run on every request against text an attacker can
influence — so patterns over 500 characters or containing nested unbounded
quantifiers (`(a+)+`) are refused at load time. The screen is a conservative
heuristic, not a complete ReDoS analysis; Python's `re` has no backtracking limit.
Tracked as R-03.

---

## What a tokenised prompt still tells the provider

Tokens are deterministic within a (tenant, conversation), which is what lets the
model treat two mentions of the same person as one person. The cost is that the
provider learns the **equality structure** of the prompt: which mentions match,
how many distinct values there are, what type each is, and which values co-occur.
It never learns the values, and nothing correlates across conversations or
tenants.

This is an accepted residual, not an oversight — the only alternative that closes
it makes multi-turn reasoning unusable. Argued and decided in
[ADR-0016](adr/0016-equality-leakage-of-deterministic-pseudonyms.md), and it is
why nothing here may be described as *anonymisation*.

## Conflict resolution

When detectors disagree about overlapping text
([detectors/base.py:48](../gateway/detectors/base.py)):

1. **Contained spans are dropped.** `alice@acme.lv` is one `EMAIL_ADDRESS`, not
   an email containing a person.
2. **Partial intersections** resolve by higher score, then longer span, then
   earlier start, then entity type ascending, then detector name ascending.

The final two tiebreaks exist so the outcome never depends on dict or set
iteration order — policy decisions must be reproducible, which is a release gate.
They are also why `EE_PERSONAL_CODE` deterministically beats `LT_PERSONAL_CODE`.

**Priority is not severity.** A CERTAIN `IP_ADDRESS` would beat a MEDIUM
`LV_PERSONAL_CODE` on score alone if they overlapped. They cannot overlap today,
but an entity priority table independent of confidence is the correct long-term
design and is not yet built.

---

## Measurement status

`make evals` · corpus **v2.0.0**, dev split, 101 scored examples, 66 gold spans.

| Entity | Precision | Recall | Gold | Verdict |
|---|---|---|---|---|
| `EMAIL_ADDRESS` | 100% | 100% | 13 | PASS |
| `IBAN` | 100% | 100% | 13 | PASS |
| `PHONE_NUMBER` | 100% | 100% | 12 | PASS |
| `BALTIC_PERSONAL_CODE` | 100% | 100% | 6 | PASS |
| `LV_PERSONAL_CODE` | 100% | 100% | 5 | PASS |
| `EE_PERSONAL_CODE` | 100% | 100% | 4 | PASS |
| `LT_PERSONAL_CODE` | 100% | 100% | 3 | PASS |
| `PAYMENT_CARD` | 100% | 100% | 3 | PASS |
| `AWS_ACCESS_KEY` | 100% | 100% | 1 | PASS |
| `PRIVATE_KEY` | 100% | 100% | 1 | PASS |
| `JWT` | 100% | 100% | 1 | PASS |
| `OPENAI_API_KEY` | 100% | 100% | 1 | PASS |
| `ANTHROPIC_API_KEY` | 100% | 100% | 1 | PASS |
| `GITHUB_TOKEN` | 100% | 100% | 1 | PASS |
| `SLACK_TOKEN` | 100% | 100% | 1 | PASS |

**Known gaps, scored separately:** `PHONE_NUMBER` in national format with no
context word — 0% recall over 2 examples, on both splits. A deliberate precision
trade, now measured rather than only described.

**Every entity/language pair passes**, on dev and on the genuinely disjoint
holdout split.

All fifteen thresholded entities now have corpus coverage. The seven credential
rows were added in v2.0.0; before that they carried thresholds and appeared in no
example, and because precision and recall both return 1.0 on a zero denominator
they reported as passing for detectors that were never run. Each still rests on a
support of 1 — that is coverage, not confidence.

The LT/EE label collapse that made this table fail on v1.1.0 is closed by country
context — see Tier 2. The full published results, including why a 100% here is
weaker evidence than it looks, are in
[evaluation-report.md](evaluation-report.md).

Adversarial examples (Unicode evasion) are scored separately so they neither drag
nor flatter the headline. **Phase 4 closed this gap:** `LV_PERSONAL_CODE` went
33% → **100%** recall and `EMAIL_ADDRESS` 0% → **100%**, covering Cyrillic
homoglyphs, zero-width insertion, fullwidth digits, and en-dash substitution —
with **no new false positives** on the boundary corpus, which is the number that
matters when a change buys recall by loosening matching.

P95 detection latency: **13.8 ms** for a 4 KB request against a 150 ms budget —
measured on a developer machine, not on published reference hardware, so it is a
regression signal rather than a publishable figure.

Caveats that belong beside every number above: the corpus is **synthetic and
small** (86 dev, 66 holdout), per-entity supports are in single or low double
digits so one missed span moves recall by ten points or more, and it
over-represents the patterns we already thought of. See
[evals/datasets/README.md](../evals/datasets/README.md). Real-text validation
with a design partner under a data-processing agreement is a pilot deliverable
and is not replaced by this.

The leakage suite (`evals/leakage/`, 17 tests) remains the complementary
evidence: it proves *specific* values do not reach the provider, which is a
different claim from a catch rate.

### Thresholds, frozen before any holdout result is read

| Class | Precision | Recall |
|---|---|---|
| Structured credentials, national identifiers, IBAN, payment card, email | ≥ 99% | ≥ 99%, plus 100% on mandatory checksum-valid regression cases |
| `PHONE_NUMBER` | ≥ 95% | ≥ 90% — see the context-rule trade in Tier 4 |
| `PERSON`, `ORG`, `LOCATION`, `ADDRESS` | ≥ 85% | ≥ 90% |

Per advertised entity/language pair. **No aggregate score may conceal a failing
entity or language** — `evals/run_evals.py` gates on the per-pair table and
prints the aggregate marked informational. Any entity below threshold is removed
from the advertised support matrix or blocks the release.

P95 detection-path latency: ≤ 150 ms for a 4 KB text request on published
reference hardware.

**The holdout split has not been read.** It stays locked until thresholds are
final and a release candidate exists.

---

## Adding an entity type

1. Add a row here first, with severity, FP cost, and planned languages.
2. Add positive, negative, and boundary fixtures to `evals/datasets/` **before**
   the detector, including a negative set built from the specific false-positive
   sources named in the FP cost column.
3. Implement behind the `Detector` protocol
   ([detectors/base.py:20](../gateway/detectors/base.py)). Detectors must be
   pure and side-effect free; the pipeline may run them on partial,
   attacker-controlled text.
4. Add a default policy rule, or state explicitly that there is none.
5. Run `make evals`. Status becomes **Measured**.
6. Status becomes **Advertised** only after the threshold passes on the locked
   holdout set — and only then may it appear in any customer-facing material.
