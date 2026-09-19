"""Deterministic generator for the evaluation corpus.

Run with ``python -m evals.datasets.generate``. The output is committed, so the
corpus is a reviewable artefact rather than something that changes under a test
run -- and re-running with the same version must reproduce it byte for byte.

## Why generate rather than collect

Collecting real Baltic business text would give a more faithful corpus and would
also mean this repository contained real personal data. That is not a trade a
privacy product can make. Every identifier below is computed from the published
check-digit algorithm; every name is fictional; every organisation is invented.

The cost is honest and worth stating: **a synthetic corpus over-represents the
patterns we already thought of.** It measures whether the detectors do what we
believe, not whether reality looks like our beliefs. Real-text validation with a
design partner, under a data-processing agreement, is a Phase 7 pilot deliverable
and is not replaced by this.

## Split discipline

``dev`` and ``holdout`` are generated from **disjoint template pools, disjoint
name/organisation/city pools, and different seeds**. The holdout set exists to be
read **once**, after thresholds are frozen. Tuning against it turns the number it
produces into a description of the detectors rather than a measurement of them.

This used to be false. Both splits drew from the same module-level template
lists and differed only in seed, which substituted different digits into
identical sentences: 30 of 66 unique holdout texts were byte-identical to dev,
and `dev-lv-pos-0001` and `hol-lv-pos-0001` were the same sentence with a
different personal code. The docstring claimed disjoint pools, the code did not
implement them, and `test_splits_do_not_share_examples` asserted only on the
positives subset -- so nothing caught it. A holdout that paraphrases dev
measures the same thing twice and reports it as corroboration.

## What this corpus still cannot tell you

The generator computes its identifiers from the same published check-digit
algorithms the detectors validate against. That makes the identifiers genuinely
valid, and it makes a checksum agreement between generator and detector
**circular**: it shows the code agrees with itself. What the corpus does measure
honestly is *segmentation* -- whether a detector finds the right span in the
right place, in the presence of neighbouring text, punctuation, and other
entities -- plus precision against the boundary and negative cases, which are
written by hand and are not derived from any detector.

Real-text validation with a design partner, under a data-processing agreement,
is a Phase 7 pilot deliverable and is not replaced by this.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass
from pathlib import Path

from evals.datasets.schema import (
    DATASETS_ROOT,
    Example,
    GoldSpan,
    to_json_line,
)

# 2.0.0 is a major bump, not a tidy-up: the holdout split is regenerated from
# its own template and value pools, so holdout numbers before and after this
# version are not comparable. Secret, hard-format, and known-gap coverage is new.
CORPUS_VERSION = "2.0.0"

# --------------------------------------------------------------------------
# Fictional entities. No real people, no real companies.
# --------------------------------------------------------------------------

LV_NAMES = ["Ilze Bērziņa", "Jānis Ozols", "Anna Kalniņa", "Mārtiņš Liepa"]
LT_NAMES = ["Rūta Kazlauskaitė", "Tomas Petrauskas", "Eglė Jankauskienė"]
ET_NAMES = ["Kristiina Tamm", "Mart Saar", "Liisa Kask"]
EN_NAMES = ["Sarah Whitfield", "Daniel Okoro", "Priya Raman"]

ORGS = ["Aurora Baltics SIA", "Vilnis Logistika UAB", "Põhjala Tarkvara OÜ", "Northwind Ltd"]
CITIES = ["Rīga", "Liepāja", "Vilnius", "Kaunas", "Tallinn", "Tartu", "Manchester"]

# Holdout pools. No member appears in the dev pools above, so a holdout example
# cannot repeat a dev example even before the templates differ.
HOLDOUT_LV_NAMES = ["Zane Krūmiņa", "Edgars Vītols", "Laima Priede"]
HOLDOUT_LT_NAMES = ["Gintarė Butkutė", "Mindaugas Žilinskas", "Aistė Navickienė"]
HOLDOUT_ET_NAMES = ["Katrin Ilves", "Rein Lepik", "Maarja Oja"]
HOLDOUT_EN_NAMES = ["Thomas Ashcroft", "Amara Nwosu", "Elena Ricci"]

HOLDOUT_ORGS = ["Dzintars Tehnika SIA", "Girios Prekyba UAB", "Rannaküla Systems OÜ", "Halcyon PLC"]
HOLDOUT_CITIES = ["Jelgava", "Ventspils", "Klaipėda", "Panevėžys", "Pärnu", "Narva", "Bristol"]

# --------------------------------------------------------------------------
# Checksum-valid identifier generators
# --------------------------------------------------------------------------


def lv_personal_code(first_ten: str) -> str:
    weights = (1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    check = (1101 - sum(int(first_ten[i]) * weights[i] for i in range(10))) % 11 % 10
    return f"{first_ten[:6]}-{first_ten[6:]}{check}"


def baltic_personal_code(first_ten: str) -> str:
    """LT and EE share this construction, which is exactly the problem."""
    w1 = (1, 2, 3, 4, 5, 6, 7, 8, 9, 1)
    w2 = (3, 4, 5, 6, 7, 8, 9, 1, 2, 3)
    remainder = sum(int(first_ten[i]) * w1[i] for i in range(10)) % 11
    if remainder == 10:
        remainder = sum(int(first_ten[i]) * w2[i] for i in range(10)) % 11
        if remainder == 10:
            remainder = 0
    return first_ten + str(remainder)


def iban(country: str, bban: str) -> str:
    """Build an IBAN with correct ISO 13616 mod-97 check digits."""
    rearranged = bban + country + "00"
    digits = "".join(str(ord(c) - ord("A") + 10) if c.isalpha() else c for c in rearranged.upper())
    check = 98 - int(digits) % 97
    return f"{country}{check:02d}{bban}"


def luhn_card(prefix: str, length: int = 16) -> str:
    body = prefix.ljust(length - 1, "4")[: length - 1]
    total = 0
    for index, char in enumerate(reversed(body)):
        value = int(char)
        if index % 2 == 0:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return body + str((10 - total % 10) % 10)


# --------------------------------------------------------------------------
# Templates
# --------------------------------------------------------------------------

POSITIVE_TEMPLATES = {
    "lv": [
        "Klienta {name} personas kods ir {code}. Lūdzu, sagatavo atbildi.",
        "Nosūti rēķinu uz {email}, klients {name} no {org}.",
        "Maksājums saņemts kontā {iban} no uzņēmuma {org}.",
        "Sazinieties ar {name}, tālr. {phone}, par piegādi uz {city}.",
    ],
    "lt": [
        "Kliento {name} asmens kodas yra {code}. Prašau paruošti atsakymą.",
        "Sąskaitą siųskite adresu {email}, klientas {name}, įmonė {org}.",
        "Mokėjimas gautas į sąskaitą {iban} iš {org}.",
        "Susisiekite su {name}, tel. {phone}, dėl pristatymo į {city}.",
    ],
    "et": [
        "Kliendi {name} isikukood on {code}. Palun koosta vastus.",
        "Saada arve aadressile {email}, klient {name}, ettevõte {org}.",
        "Makse laekus kontole {iban} ettevõttelt {org}.",
        "Võta ühendust: {name}, telefon {phone}, tarne {city}.",
    ],
    "en": [
        "The client {name} can be reached at {email} regarding the {org} account.",
        "Payment was received into {iban} from {org} in {city}.",
        "Charge the card {card} for the {org} subscription.",
        "Phone {phone} to reach {name} at {org} about the {city} delivery.",
    ],
}

# Holdout sentences. Different situations, not reworded dev sentences: a
# delivery note, a support ticket, a payroll query, a contract renewal. If these
# were paraphrases the split would still be measuring the same thing twice.
HOLDOUT_POSITIVE_TEMPLATES = {
    "lv": [
        "Darbinieka {name} personas kods {code} jāpievieno līgumam.",
        "Atbalsta pieteikums no {email}; kontaktpersona {name}, {org}.",
        "Algas pārskaitījums uz {iban} apstiprināts {city} filiālē.",
        "Piegādes kavējums: zvaniet {phone}, atbildīgais {name}.",
    ],
    "lt": [
        "Darbuotojo {name} asmens kodas {code} pridedamas prie sutarties.",
        "Pagalbos užklausa iš {email}; kontaktinis asmuo {name}, {org}.",
        "Atlyginimo pervedimas į {iban} patvirtintas {city} skyriuje.",
        "Pristatymo vėlavimas: skambinkite {phone}, atsakingas {name}.",
    ],
    "et": [
        "Töötaja {name} isikukood {code} tuleb lisada lepingule.",
        "Tugitaotlus aadressilt {email}; kontaktisik {name}, {org}.",
        "Palgaülekanne kontole {iban} kinnitatud {city} kontoris.",
        "Tarne hilineb: helista {phone}, vastutab {name}.",
    ],
    "en": [
        "Renewal notice for {org}: the signatory {name} is at {email}.",
        "Settle the outstanding balance to {iban} before the {city} audit.",
        "Refund the card {card} used for the {org} order.",
        "Escalation: call {phone} and ask for {name} at {org}.",
    ],
}

NEGATIVE_TEMPLATES = {
    "lv": [
        "Lūdzu, apkopo galvenos punktus no VDAR 5. panta.",
        "Kāds ir projekta piegādes grafiks nākamajā ceturksnī?",
        "Sagatavo kopsavilkumu par klientu apkalpošanas rādītājiem.",
    ],
    "lt": [
        "Prašau apibendrinti pagrindinius BDAR 5 straipsnio punktus.",
        "Koks yra projekto pristatymo grafikas kitą ketvirtį?",
        "Paruošk santrauką apie klientų aptarnavimo rodiklius.",
    ],
    "et": [
        "Palun võta kokku GDPR artikli 5 põhipunktid.",
        "Milline on projekti tarnegraafik järgmises kvartalis?",
        "Koosta kokkuvõte klienditeeninduse näitajatest.",
    ],
    "en": [
        "Summarise the key points of GDPR Article 5.",
        "What is the delivery timeline for the next quarter?",
        "Draft a summary of the customer service metrics.",
    ],
}

HOLDOUT_NEGATIVE_TEMPLATES = {
    "lv": [
        "Kādas ir izmaiņas jaunajā atvaļinājumu politikā?",
        "Uzraksti īsu ievadu prezentācijai par mākoņpakalpojumiem.",
        "Salīdzini divus piedāvājumus pēc uzturēšanas izmaksām.",
    ],
    "lt": [
        "Kokie pakeitimai numatyti naujoje atostogų politikoje?",
        "Parašyk trumpą įvadą pristatymui apie debesijos paslaugas.",
        "Palygink du pasiūlymus pagal priežiūros sąnaudas.",
    ],
    "et": [
        "Millised muudatused on uues puhkusepoliitikas?",
        "Kirjuta lühike sissejuhatus pilveteenuste esitlusele.",
        "Võrdle kahte pakkumist hoolduskulude alusel.",
    ],
    "en": [
        "What changes are in the new leave policy?",
        "Write a short introduction for a presentation on cloud services.",
        "Compare the two proposals on maintenance cost.",
    ],
}

# Near-misses. Each one is a specific false-positive source named in
# docs/entity-taxonomy.md, so a regression has a name rather than a number.
BOUNDARY_TEMPLATES = [
    ("Order number 120385-12341 shipped on time.", "invalid LV check digit"),
    ("Reference 39912319990 is the batch identifier.", "11 digits, invalid Baltic checksum"),
    ("Invoice total 4111111111111112 EUR was disputed.", "16 digits, fails Luhn"),
    ("Account LV80BANK0000435195100 is not a real IBAN.", "IBAN shape, bad check digits"),
    ("Timestamp 20240115-09301 marks the export.", "date-like, not a personal code"),
    ("Serial 1234-56789 belongs to the printer.", "hyphenated but wrong lengths"),
    ("Build 38503121231 completed in 4 minutes.", "11 digits, invalid Baltic checksum"),
    ("The article is at https://example.com/a@b/c for reference.", "at-sign, not an email"),
    ("Version 192.168.1.999 is not a valid address.", "IPv4-like, out of range"),
    ("Contact the team at support (at) example dot com.", "obfuscated, not an email"),
    ("Order number 29123456 shipped today.", "8 digits, phone-shaped, no phone context"),
    ("The invoice total was 61234567 cents.", "phone-shaped quantity"),
    ("Part 51234567 is out of stock.", "phone-shaped part number"),
]

HOLDOUT_BOUNDARY_TEMPLATES = [
    ("Ticket 070481-33449 was closed yesterday.", "invalid LV check digit"),
    ("Batch 47705129993 left the warehouse.", "11 digits, invalid Baltic checksum"),
    # 5500000000000004 is a published Mastercard *test* number and passes Luhn;
    # it was in this list as a supposed near-miss until the holdout reported it
    # as a card. A boundary example that is actually a positive teaches the
    # detector the wrong lesson and hides a real false-positive rate.
    ("The quote came to 5500000000000005 EUR.", "16 digits, fails Luhn"),
    ("Account EE382200221020145699 was rejected.", "IBAN shape, bad check digits"),
    ("Export stamp 20231104-11220 recorded.", "date-like, not a personal code"),
    ("Asset 9876-54321 is in the store room.", "hyphenated but wrong lengths"),
    ("Pipeline 29806142228 finished overnight.", "11 digits, invalid Baltic checksum"),
    ("See https://example.org/x@y/z for the archive.", "at-sign, not an email"),
    ("Host 10.300.4.1 could not be resolved.", "IPv4-like, out of range"),
    ("Write to sales [at] example [dot] org instead.", "obfuscated, not an email"),
    ("Consignment 26719004 departed this morning.", "8 digits, phone-shaped, no phone context"),
    ("The rebate was 63400912 cents overall.", "phone-shaped quantity"),
    ("Component 54330871 awaits inspection.", "phone-shaped part number"),
]

# Secrets. Seven entity types carry published thresholds in run_evals.py and
# appeared in **no example**, which meant they could not fail: precision and
# recall both return 1.0 on a zero denominator, and the gate only iterates
# buckets that exist. A threshold guarding nothing reads exactly like a
# threshold being met.
#
# Every value below is structurally valid and deliberately non-functional --
# documentation placeholders and obviously-fake bodies, so nothing here is a
# live credential and gitleaks has nothing real to find.
SECRET_TEMPLATES = [
    ("Deploy with AKIAIOSFODNN7EXAMPLE as the access key.", "AWS_ACCESS_KEY"),
    ("Set OPENAI_API_KEY=sk-proj-EXAMPLEEXAMPLEEXAMPLEEXAMPLE1234 in the env.", "OPENAI_API_KEY"),
    (
        "Set ANTHROPIC_API_KEY=sk-ant-EXAMPLEEXAMPLEEXAMPLEEXAMPLE99 in the env.",
        "ANTHROPIC_API_KEY",
    ),
    ("Use ghp_EXAMPLE0000EXAMPLE0000EXAMPLE0000abc for the checkout.", "GITHUB_TOKEN"),
    ("The bot posts with " + "xoxb-" + "000000000000-EXAMPLEEXAMPLE.", "SLACK_TOKEN"),
    (
        "Authorization: Bearer "
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJleGFtcGxlIn0.c2lnbmF0dXJlLWV4YW1wbGU",
        "JWT",
    ),
]

HOLDOUT_SECRET_TEMPLATES = [
    ("Rotate ASIAY34FZKBOKMUTVV7A before Friday.", "AWS_ACCESS_KEY"),
    ("The staging key is sk-EXAMPLEEXAMPLEEXAMPLEEXAMPLE5678 for now.", "OPENAI_API_KEY"),
    ("Store sk-ant-EXAMPLEEXAMPLEEXAMPLEEXAMPLE42 in the vault.", "ANTHROPIC_API_KEY"),
    ("CI reads gho_EXAMPLE1111EXAMPLE1111EXAMPLE1111wxy at build time.", "GITHUB_TOKEN"),
    (
        "Legacy integration still uses " + "xoxp-" + "111111111111-EXAMPLEEXAMPLE.",
        "SLACK_TOKEN",
    ),
    (
        "Header was eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiZGVtbyJ9.YW5vdGhlci1leGFtcGxl",
        "JWT",
    ),
]

# Formats the product was measured as missing, then fixed. Keeping them in the
# corpus is what stops the fix from silently regressing.
HARD_FORMAT_TEMPLATES = {
    "spaced_iban": (
        "Maksājums saņemts kontā {value} no partnera.",
        "IBAN",
        "space-grouped, the form banks actually print",
    ),
    "plain_lv_code": (
        "Personas kods {value} eksportā no sistēmas.",
        "LV_PERSONAL_CODE",
        "hyphenless, the form a database extract produces",
    ),
}

HOLDOUT_HARD_FORMAT_TEMPLATES = {
    "spaced_iban": (
        "Rēķina apmaksai izmantojiet kontu {value}.",
        "IBAN",
        "space-grouped, the form banks actually print",
    ),
    "plain_lv_code": (
        "CSV rindā atrasts {value} bez atdalītāja.",
        "LV_PERSONAL_CODE",
        "hyphenless, the form a database extract produces",
    ),
}

# Entities the product has decided not to detect. Real gold spans, reported
# separately, never folded into the headline number.
#
# The unlabelled phone number is a deliberate precision trade documented in
# recognizers/baltic/phone_numbers.py: "27 123 456" is a phone number in a
# signature block and a quantity on an invoice line, and nothing in the digits
# separates them. PHONE_NUMBER recall was lowered to 0.90 to pay for that
# concession -- and no example exercised it, so the payment was never made.
KNOWN_GAP_TEMPLATES = [
    ("Anna Kalniņa, 25938547, Rīgas birojs.", "PHONE_NUMBER", "no phone context word"),
    ("Kontakts: 26112233 (birojs).", "PHONE_NUMBER", "no phone context word"),
]

HOLDOUT_KNOWN_GAP_TEMPLATES = [
    ("Edgars Vītols, 29455112, Ventspils noliktava.", "PHONE_NUMBER", "no phone context word"),
    ("Rezerves numurs 27884413 sarakstā.", "PHONE_NUMBER", "no phone context word"),
]

# Evasion attempts. Expected to fail until Phase 4 -- reported separately so a
# known gap does not masquerade as a detection failure, and does not quietly
# improve the headline number either.
# A Lithuanian or Estonian code with **no country context at all** -- the bare
# number in a spreadsheet cell or a database extract. Neither the identifier's
# name nor any country marker is present, so the recogniser cannot say which
# country issued it and must say so rather than guess.
#
# These exist because the ambiguous path would otherwise ship unmeasured: every
# other positive template names the identifier, which is the case where
# disambiguation is easy.
AMBIGUOUS_TEMPLATES = {
    "lt": "Įrašas duomenų bazėje: {code}. Patikrinkite ir atsakykite.",
    "et": "Kirje andmebaasis: {code}. Palun kontrolli ja vasta.",
}

HOLDOUT_AMBIGUOUS_TEMPLATES = {
    "lt": "Eilutė iš eksporto: {code}. Reikia patvirtinimo.",
    "et": "Rida ekspordifailist: {code}. Vajab kinnitust.",
}

ADVERSARIAL_TEMPLATES = [
    ("Kods ir {cyrillic_code}.", "Cyrillic homoglyph in a personal code"),
    ("Kods ir {zwsp_code}.", "zero-width space inside a personal code"),
    ("Kods ir {fullwidth_code}.", "fullwidth digits"),
    ("Mail {zwsp_email} please.", "zero-width space inside an email"),
]

HOLDOUT_ADVERSARIAL_TEMPLATES = [
    ("Klienta identifikators: {cyrillic_code}", "Cyrillic homoglyph in a personal code"),
    ("Ieraksts sistēmā {zwsp_code} jāpārbauda.", "zero-width space inside a personal code"),
    ("Norādītais numurs {fullwidth_code} neatbilst.", "fullwidth digits"),
    ("Raksti uz {zwsp_email} ar apstiprinājumu.", "zero-width space inside an email"),
]

#: PEM blocks, one per split. Both are non-functional example keys; the point of
#: separating them is only that a holdout example must not be a dev example.
PRIVATE_KEY_BLOCKS = {
    "dev": (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
        "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n"
        "-----END RSA PRIVATE KEY-----"
    ),
    "holdout": (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIBOQIBAAJBALRmEXAMPLEONLY0000NotARealKey1111Placeholder2222Zz9w\n"
        "QIDAQABAkAEXAMPLEONLYnotarealprivatekeymaterial3333==\n"
        "-----END RSA PRIVATE KEY-----"
    ),
}

PEM_SENTENCES = {
    "dev": ("Committed by mistake:\n{block}\nPlease rotate."),
    "holdout": ("Found in an old backup:\n{block}\nRevoke it today."),
}


def _cyrillic_digits(text: str) -> str:
    """Replace ASCII '3' with Cyrillic 'З' (U+0417) -- visually identical."""
    return text.replace("3", "З", 1)


def _zero_width(text: str) -> str:
    middle = len(text) // 2
    return text[:middle] + "​" + text[middle:]


def _fullwidth(text: str) -> str:
    return "".join(chr(ord(c) - 0x30 + 0xFF10) if c.isdigit() else c for c in text)


# --------------------------------------------------------------------------
# Generation
# --------------------------------------------------------------------------

_NAMES = {"lv": LV_NAMES, "lt": LT_NAMES, "et": ET_NAMES, "en": EN_NAMES}
_HOLDOUT_NAMES = {
    "lv": HOLDOUT_LV_NAMES,
    "lt": HOLDOUT_LT_NAMES,
    "et": HOLDOUT_ET_NAMES,
    "en": HOLDOUT_EN_NAMES,
}


@dataclass(frozen=True)
class _Pools:
    """Everything a split draws from, so the two splits share nothing.

    Passing this around rather than reading module globals is the point: the
    previous bug was possible precisely because `_build` reached for the same
    module-level lists no matter which split it had been asked for.
    """

    positive: dict[str, list[str]]
    negative: dict[str, list[str]]
    boundary: list[tuple[str, str]]
    secrets: list[tuple[str, str]]
    known_gaps: list[tuple[str, str, str]]
    ambiguous: dict[str, str]
    adversarial: list[tuple[str, str]]
    hard_formats: dict[str, tuple[str, str, str]]
    pem_block: str
    pem_sentence: str
    names: dict[str, list[str]]
    orgs: list[str]
    cities: list[str]


def pools_for(split: str) -> _Pools:
    if split == "holdout":
        return _Pools(
            positive=HOLDOUT_POSITIVE_TEMPLATES,
            negative=HOLDOUT_NEGATIVE_TEMPLATES,
            boundary=HOLDOUT_BOUNDARY_TEMPLATES,
            secrets=HOLDOUT_SECRET_TEMPLATES,
            known_gaps=HOLDOUT_KNOWN_GAP_TEMPLATES,
            ambiguous=HOLDOUT_AMBIGUOUS_TEMPLATES,
            adversarial=HOLDOUT_ADVERSARIAL_TEMPLATES,
            hard_formats=HOLDOUT_HARD_FORMAT_TEMPLATES,
            pem_block=PRIVATE_KEY_BLOCKS["holdout"],
            pem_sentence=PEM_SENTENCES["holdout"],
            names=_HOLDOUT_NAMES,
            orgs=HOLDOUT_ORGS,
            cities=HOLDOUT_CITIES,
        )
    return _Pools(
        positive=POSITIVE_TEMPLATES,
        negative=NEGATIVE_TEMPLATES,
        boundary=BOUNDARY_TEMPLATES,
        secrets=SECRET_TEMPLATES,
        known_gaps=KNOWN_GAP_TEMPLATES,
        ambiguous=AMBIGUOUS_TEMPLATES,
        adversarial=ADVERSARIAL_TEMPLATES,
        hard_formats=HARD_FORMAT_TEMPLATES,
        pem_block=PRIVATE_KEY_BLOCKS["dev"],
        pem_sentence=PEM_SENTENCES["dev"],
        names=_NAMES,
        orgs=ORGS,
        cities=CITIES,
    )


_CODE_BUILDER = {
    "lv": lambda base: lv_personal_code(base),
    "lt": lambda base: baltic_personal_code(base),
    "et": lambda base: baltic_personal_code(base),
    "en": lambda base: lv_personal_code(base),
}
_CODE_ENTITY = {
    "lv": "LV_PERSONAL_CODE",
    "lt": "LT_PERSONAL_CODE",
    "et": "EE_PERSONAL_CODE",
    "en": "LV_PERSONAL_CODE",
}

# Valid subscriber ranges per numbering plan. The Latvian entries are national
# format on purpose -- the template supplies the "tālr." context word, which is
# what the recogniser requires and what the corpus therefore has to exercise.
_PHONE_BUILDER = {
    "lv": lambda rng: f"2{rng.randint(1000000, 9999999)}",
    "lt": lambda rng: f"+370 6{rng.randint(1000000, 9999999)}",
    "et": lambda rng: f"+372 5{rng.randint(100000, 999999)}",
    "en": lambda rng: f"+371 6{rng.randint(1000000, 9999999)}",
}


#: Locates the secret inside its sentence, so the gold span is derived from the
#: text rather than hand-counted. These deliberately mirror the *shapes* the
#: detectors look for; unlike a checksum, a shape is what the corpus is entitled
#: to assume, because there is nothing else that identifies a credential.
_SECRET_VALUE_RE = {
    "AWS_ACCESS_KEY": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "OPENAI_API_KEY": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    "ANTHROPIC_API_KEY": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    "GITHUB_TOKEN": re.compile(r"\b(?:ghp|gho)_[A-Za-z0-9]{36}\b"),
    "SLACK_TOKEN": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
}


def _group_iban(value: str) -> str:
    """Space the IBAN in fours, the way a bank statement prints it."""
    return " ".join(value[index : index + 4] for index in range(0, len(value), 4))


def _fill(template: str, values: dict[str, str]) -> tuple[str, list[GoldSpan]]:
    """Render a template and record a gold span for every substituted entity.

    Offsets come from the rendering itself rather than a post-hoc search, so a
    value that also occurs elsewhere in the sentence cannot produce a wrong span.
    """
    text = ""
    spans: list[GoldSpan] = []
    cursor = 0
    remaining = template

    while True:
        open_at = remaining.find("{")
        if open_at == -1:
            text += remaining
            break
        close_at = remaining.find("}", open_at)
        key = remaining[open_at + 1 : close_at]
        literal = remaining[:open_at]
        text += literal
        cursor += len(literal)

        value, entity = values[key], _ENTITY_FOR_KEY.get(key)
        text += value
        if entity:
            spans.append(GoldSpan(cursor, cursor + len(value), entity))
        cursor += len(value)
        remaining = remaining[close_at + 1 :]

    return text, spans


_ENTITY_FOR_KEY = {
    "email": "EMAIL_ADDRESS",
    "iban": "IBAN",
    "card": "PAYMENT_CARD",
    "phone": "PHONE_NUMBER",
    # name / org / city are contextual entities with no detector yet. They are
    # deliberately NOT gold-labelled: labelling entities nothing can emit would
    # report 0% recall for a capability we have never claimed, which is noise
    # rather than measurement. They become gold spans when ner.py ships.
}


def _build(split: str, seed: int, count_per_language: int) -> list[Example]:
    # Seeded Mersenne Twister, deliberately: the corpus must reproduce byte for
    # byte from a version and a seed. This generates test fixtures, not keys.
    rng = random.Random(seed)  # noqa: S311
    examples: list[Example] = []
    counter = 0

    def next_id(lang: str, kind: str) -> str:
        nonlocal counter
        counter += 1
        return f"{split[:3]}-{lang}-{kind[:3]}-{counter:04d}"

    pools = pools_for(split)

    for lang in ("lv", "lt", "et", "en"):
        for index in range(count_per_language):
            template = pools.positive[lang][index % len(pools.positive[lang])]
            day = rng.randint(1, 28)
            month = rng.randint(1, 12)
            year = rng.randint(50, 99)
            serial = rng.randint(10000, 99999)
            base = f"{day:02d}{month:02d}{year:02d}{serial:05d}"[:10]
            lt_base = f"{rng.randint(3, 6)}{year:02d}{month:02d}{day:02d}{rng.randint(100, 999)}"

            values = {
                "name": rng.choice(pools.names[lang]),
                "org": rng.choice(pools.orgs),
                "city": rng.choice(pools.cities),
                "code": (
                    _CODE_BUILDER[lang](base)
                    if lang in ("lv", "en")
                    else baltic_personal_code(lt_base[:10])
                ),
                "email": f"{rng.choice(['a', 'b', 'c'])}{rng.randint(10, 99)}@example.{lang}",
                "iban": iban("LV", f"BANK{rng.randint(10**12, 10**13 - 1)}"),
                "card": luhn_card(str(rng.randint(4000, 4999))),
                "phone": _PHONE_BUILDER[lang](rng),
            }
            text, spans = _fill(template, values)
            if "{code}" in template:
                start = text.index(values["code"])
                spans.append(GoldSpan(start, start + len(values["code"]), _CODE_ENTITY[lang]))
            examples.append(
                Example(
                    id=next_id(lang, "positive"),
                    lang=lang,
                    kind="positive",
                    text=text,
                    spans=tuple(sorted(spans, key=lambda s: s.start)),
                )
            )

        # The bare-number case: a valid LT/EE code with no country context.
        if lang in pools.ambiguous:
            for _ in range(max(2, count_per_language // 4)):
                code = baltic_personal_code(
                    f"{rng.randint(3, 6)}{rng.randint(10, 99)}"
                    f"{rng.randint(1, 12):02d}{rng.randint(1, 28):02d}{rng.randint(100, 999)}"[:10]
                )
                text = pools.ambiguous[lang].replace("{code}", code)
                start = text.index(code)
                examples.append(
                    Example(
                        id=next_id(lang, "positive"),
                        lang=lang,
                        kind="positive",
                        text=text,
                        spans=(GoldSpan(start, start + len(code), "BALTIC_PERSONAL_CODE"),),
                        note="no country context; the label must admit the ambiguity",
                    )
                )

        for index in range(max(3, count_per_language // 2)):
            examples.append(
                Example(
                    id=next_id(lang, "negative"),
                    lang=lang,
                    kind="negative",
                    text=pools.negative[lang][index % len(pools.negative[lang])],
                )
            )

    for text, note in pools.boundary:
        examples.append(
            Example(id=next_id("en", "boundary"), lang="en", kind="boundary", text=text, note=note)
        )

    # Secrets. One example per thresholded entity, so none of them can pass a
    # gate by being absent from the corpus.
    for text, entity in pools.secrets:
        value = _SECRET_VALUE_RE[entity].search(text)
        if value is None:  # pragma: no cover - guards a template edit
            raise ValueError(f"no {entity} value found in secret template: {text!r}")
        examples.append(
            Example(
                id=next_id("en", "positive"),
                lang="en",
                kind="positive",
                text=text,
                spans=(GoldSpan(value.start(), value.end(), entity),),
                note="secret coverage",
            )
        )

    pem_text = pools.pem_sentence.replace("{block}", pools.pem_block)
    pem_start = pem_text.index("-----BEGIN")
    pem_end = pem_text.index("-----END RSA PRIVATE KEY-----") + len("-----END RSA PRIVATE KEY-----")
    examples.append(
        Example(
            id=next_id("en", "positive"),
            lang="en",
            kind="positive",
            text=pem_text,
            spans=(GoldSpan(pem_start, pem_end, "PRIVATE_KEY"),),
            note="secret coverage; multi-line PEM block",
        )
    )

    # Formats previously missed, now detected. These are the regression guard
    # for the two detector fixes, not new capability claims.
    hard_values = {
        "spaced_iban": _group_iban(iban("LV", f"BANK{rng.randint(10**12, 10**13 - 1)}")),
        "plain_lv_code": lv_personal_code(
            f"{rng.randint(1, 28):02d}{rng.randint(1, 12):02d}{rng.randint(50, 99):02d}"
            f"{rng.randint(1000, 9999)}"
        ).replace("-", ""),
    }
    for key, (template, entity, note) in pools.hard_formats.items():
        value = hard_values[key]
        text = template.replace("{value}", value)
        start = text.index(value)
        examples.append(
            Example(
                id=next_id("lv", "positive"),
                lang="lv",
                kind="positive",
                text=text,
                spans=(GoldSpan(start, start + len(value), entity),),
                note=note,
            )
        )

    # Documented non-detections, scored separately.
    for text, entity, note in pools.known_gaps:
        match = re.search(r"\b\d{8}\b", text)
        if match is None:  # pragma: no cover - guards a template edit
            raise ValueError(f"no national-format number in known-gap template: {text!r}")
        examples.append(
            Example(
                id=next_id("lv", "known_gap"),
                lang="lv",
                kind="known_gap",
                text=text,
                spans=(GoldSpan(match.start(), match.end(), entity),),
                note=note,
            )
        )

    # Drawn from the split's own rng so the evasion and mixed-language examples
    # differ between dev and holdout too. Hard-coding them here was the last
    # place the two splits still shared a literal.
    clean_code = lv_personal_code(
        f"{rng.randint(1, 28):02d}{rng.randint(1, 12):02d}{rng.randint(50, 99):02d}"
        f"{rng.randint(1000, 9999)}"
    )
    clean_email = f"{rng.choice(['a', 'b', 'c'])}{rng.randint(10, 99)}@example.lv"
    substitutions = {
        "cyrillic_code": _cyrillic_digits(clean_code),
        "zwsp_code": _zero_width(clean_code),
        "fullwidth_code": _fullwidth(clean_code),
        "zwsp_email": _zero_width(clean_email),
    }
    for template, note in pools.adversarial:
        key = template[template.index("{") + 1 : template.index("}")]
        value = substitutions[key]
        text = template.replace(f"{{{key}}}", value)
        start = text.index(value)
        entity = "EMAIL_ADDRESS" if "email" in key else "LV_PERSONAL_CODE"
        examples.append(
            Example(
                id=next_id("lv", "adversarial"),
                lang="lv",
                kind="adversarial",
                text=text,
                spans=(GoldSpan(start, start + len(value), entity),),
                note=note,
            )
        )

    mixed_code = lv_personal_code(
        f"{rng.randint(1, 28):02d}{rng.randint(1, 12):02d}{rng.randint(50, 99):02d}"
        f"{rng.randint(1000, 9999)}"
    )
    mixed_ee_code = baltic_personal_code(
        f"{rng.randint(3, 6)}{rng.randint(10, 99)}"
        f"{rng.randint(1, 12):02d}{rng.randint(1, 28):02d}{rng.randint(100, 999)}"[:10]
    )
    mixed_email = f"{rng.choice(['d', 'e', 'f'])}{rng.randint(10, 99)}@example.lv"
    mixed_text = (
        f"Klients no Rīgas, isikukood {mixed_ee_code}, "
        f"personas kods {mixed_code}. Please confirm by email {mixed_email}."
    )
    spans = [
        GoldSpan(
            mixed_text.index(mixed_ee_code),
            mixed_text.index(mixed_ee_code) + len(mixed_ee_code),
            "EE_PERSONAL_CODE",
        ),
        GoldSpan(
            mixed_text.index(mixed_code),
            mixed_text.index(mixed_code) + len(mixed_code),
            "LV_PERSONAL_CODE",
        ),
        GoldSpan(
            mixed_text.index(mixed_email),
            mixed_text.index(mixed_email) + len(mixed_email),
            "EMAIL_ADDRESS",
        ),
    ]
    examples.append(
        Example(
            id=next_id("lv", "mixed"),
            lang="lv",
            kind="mixed",
            text=mixed_text,
            spans=tuple(sorted(spans, key=lambda s: s.start)),
            note="Latvian, Estonian and English in one document",
        )
    )

    return examples


def write_split(split: str, seed: int, count_per_language: int, root: Path | None = None) -> int:
    base = (root or DATASETS_ROOT) / split
    base.mkdir(parents=True, exist_ok=True)
    (base / "VERSION").write_text(CORPUS_VERSION + "\n", encoding="utf-8")

    examples = _build(split, seed, count_per_language)
    by_language: dict[str, list[Example]] = {}
    for example in examples:
        by_language.setdefault(example.lang, []).append(example)

    for lang, items in by_language.items():
        lines = "\n".join(to_json_line(e) for e in items)
        (base / f"{lang}.jsonl").write_text(lines + "\n", encoding="utf-8")

    return len(examples)


def verify_boundaries() -> list[str]:
    """Check that every boundary fixture really is checksum-invalid.

    Written after the first run of ``make evals`` reported a false positive that
    turned out to be a corpus bug: a "batch identifier" chosen by hand happened
    to satisfy the Baltic check digit, so the detector was right and the fixture
    was wrong.

    The check recomputes from the published algorithms rather than asking our
    own detectors, so it cannot rubber-stamp a detector bug -- a fixture that is
    genuinely valid must be relabelled, not silently accepted.
    """
    problems = []
    for text, note in BOUNDARY_TEMPLATES:
        for candidate in re.findall(r"\b[1-6]\d{10}\b", text):
            if baltic_personal_code(candidate[:10]) == candidate:
                problems.append(f"{candidate!r} in {text!r} ({note}) is a VALID Baltic code")
        for whole in re.findall(r"\b(\d{6})-(\d{5})\b", text):
            joined = whole[0] + whole[1]
            if lv_personal_code(joined[:10]) == f"{whole[0]}-{whole[1]}":
                problems.append(f"{joined!r} in {text!r} ({note}) is a VALID LV code")
        for digits in re.findall(r"\b\d{13,19}\b", text):
            if luhn_card(digits[:-1], len(digits)) == digits:
                problems.append(f"{digits!r} in {text!r} ({note}) passes Luhn")
    return problems


def main() -> int:
    problems = verify_boundaries()
    if problems:
        print("refusing to write: boundary fixtures are not actually invalid")
        for problem in problems:
            print(f"  {problem}")
        return 1

    # Disjoint seeds and pools: the holdout set must not be a paraphrase of dev.
    dev = write_split("dev", seed=20260803, count_per_language=12)
    holdout = write_split("holdout", seed=99180245, count_per_language=8)
    print(f"corpus v{CORPUS_VERSION}: dev={dev} examples, holdout={holdout} examples")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
