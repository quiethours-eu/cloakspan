"""Detector correctness, especially checksum validation and false positives."""

from __future__ import annotations

import pytest

from gateway.detectors.deterministic import (
    EmailDetector,
    IbanDetector,
    PaymentCardDetector,
    iban_valid,
    luhn_valid,
)
from recognizers.baltic.personal_codes import (
    BalticPersonalCodeDetector,
    detect_lv_personal_code,
)
from recognizers.custom.customer_rules import (
    CustomRegexDetector,
    DictionaryDetector,
    UnsafePatternError,
)
from recognizers.secrets.detectors import SecretDetector

from .conftest import VALID_EE_CODE, VALID_LT_CODE, VALID_LV_CODE


class TestBalticChecksums:
    def test_valid_lv_code_is_detected(self):
        spans = detect_lv_personal_code(f"Code {VALID_LV_CODE} here")
        assert len(spans) == 1
        assert spans[0].entity_type == "LV_PERSONAL_CODE"
        assert spans[0].score == 1.0

    def test_invalid_lv_checksum_is_rejected(self):
        """This is the whole point of a checksum detector.

        Without it the pattern fires on order numbers and dates, the customer
        drowns in false positives, and disables the detector.
        """
        digits = VALID_LV_CODE.replace("-", "")
        wrong_check = str((int(digits[-1]) + 1) % 10)
        broken = f"{digits[:6]}-{digits[6:10]}{wrong_check}"
        assert detect_lv_personal_code(f"Code {broken}") == []

    def test_implausible_date_is_rejected(self):
        assert detect_lv_personal_code("Code 999999-12345") == []

    def test_post_2017_form_is_detected_at_lower_confidence(self):
        """The 32xxxx form carries no date and no comparable checksum.

        We report it, but honestly -- at MEDIUM, not CERTAIN.
        """
        spans = detect_lv_personal_code("Code 321234-56789")
        assert len(spans) == 1
        assert spans[0].score == pytest.approx(0.6)

    def test_a_bare_lt_ee_code_is_detected_but_not_attributed(self):
        """No country context, so the label must admit that.

        This assertion used to read ``"LT_PERSONAL_CODE" in types`` and passed
        for the wrong reason: both recognisers fired and conflict resolution
        happened to keep one. The digits genuinely cannot say which country
        issued the code -- Lithuania and Estonia share the construction *and*
        the check digit -- so claiming either is a coin flip dressed as a
        finding.
        """
        detector = BalticPersonalCodeDetector()
        spans = detector.detect(f"Code {VALID_LT_CODE}")
        assert [s.entity_type for s in spans] == ["BALTIC_PERSONAL_CODE"]
        assert spans[0].score == pytest.approx(1.0), (
            "the detection is certain even though the label is not; scoring it "
            "lower would let a min_score policy skip it"
        )

    def test_random_11_digit_number_is_not_detected(self):
        detector = BalticPersonalCodeDetector()
        # Deliberately fails the check digit.
        assert detector.detect("Order number 12345678901 shipped") == []


class TestCountryContext:
    """Disambiguating Lithuanian from Estonian personal codes.

    The two share the construction *and* the check digit, so the digits alone
    cannot say which country issued one. Everything here is about reading the
    surrounding text -- and about refusing to guess when it says nothing.
    """

    @staticmethod
    def _types(text: str) -> list[str]:
        return [s.entity_type for s in BalticPersonalCodeDetector().detect(text)]

    @pytest.mark.parametrize(
        "text",
        [
            "Kliento asmens kodas yra {code}.",
            "Asmens kodas: {code}",
            "Nurodykite asmens kodą {code} sąskaitoje.",
            "Klientas, a.k. {code}, pateikė prašymą.",
        ],
    )
    def test_the_lithuanian_term_attributes_the_code(self, text):
        """The strongest signal: a document that contains a personal code
        almost always names it, in the issuing country's language."""
        assert self._types(text.replace("{code}", VALID_LT_CODE)) == ["LT_PERSONAL_CODE"]

    @pytest.mark.parametrize(
        "text",
        [
            "Kliendi isikukood on {code}.",
            "Isikukood: {code}",
            "Palun kontrolli isikukoodi {code} andmebaasis.",
        ],
    )
    def test_the_estonian_term_attributes_the_code(self, text):
        assert self._types(text.replace("{code}", VALID_EE_CODE)) == ["EE_PERSONAL_CODE"]

    @pytest.mark.parametrize(
        ("marker", "expected"),
        [
            ("Klientas iš Vilniaus.", "LT_PERSONAL_CODE"),
            ("Lietuvos pilietis.", "LT_PERSONAL_CODE"),
            ("Tel. +370 61234567.", "LT_PERSONAL_CODE"),
            ("Sąskaita LT121000011101001000.", "LT_PERSONAL_CODE"),
            ("El. paštas a1@imone.lt.", "LT_PERSONAL_CODE"),
            ("Klient Tallinnast.", "EE_PERSONAL_CODE"),
            ("Eesti kodanik.", "EE_PERSONAL_CODE"),
            ("Tel. +372 5123456.", "EE_PERSONAL_CODE"),
            ("Konto EE382200221020145685.", "EE_PERSONAL_CODE"),
            ("E-post a1@firma.ee.", "EE_PERSONAL_CODE"),
        ],
    )
    def test_document_markers_attribute_an_unnamed_code(self, marker, expected):
        """Weaker than the identifier's name, so used only when it is absent."""
        assert self._types(f"{marker} Kodas {VALID_LT_CODE}.") == [expected]

    def test_a_bare_code_is_not_attributed(self):
        assert self._types(f"Record: {VALID_LT_CODE}") == ["BALTIC_PERSONAL_CODE"]

    def test_conflicting_document_markers_do_not_attribute(self):
        """A document mentioning both countries proves nothing about a number
        that names neither. Picking one would be a coin flip presented as a
        finding."""
        text = f"Vilnius ja Tallinn koostöös. Kood {VALID_LT_CODE}."
        assert self._types(text) == ["BALTIC_PERSONAL_CODE"]

    def test_the_local_term_beats_a_conflicting_document_marker(self):
        """A Lithuanian code in an otherwise Estonian document is still
        Lithuanian if it is labelled as one."""
        text = f"Eesti partneri kiri. Kliento asmens kodas yra {VALID_LT_CODE}."
        assert self._types(text) == ["LT_PERSONAL_CODE"]

    def test_two_codes_in_one_document_are_judged_independently(self):
        """The reason the local window matters: a shared document-level signal
        would label both the same way."""
        text = f"Kliendi isikukood on {VALID_EE_CODE}, o kliento asmens kodas yra {VALID_LT_CODE}."
        assert self._types(text) == ["EE_PERSONAL_CODE", "LT_PERSONAL_CODE"]

    def test_a_term_far_from_the_number_does_not_claim_it(self):
        """Beyond the window, a term belongs to a different sentence."""
        filler = "x" * 90
        text = f"Asmens kodas nežinomas. {filler} Kodas {VALID_LT_CODE}."
        assert self._types(text) == ["BALTIC_PERSONAL_CODE"]

    def test_attribution_never_changes_whether_a_code_is_detected(self):
        """The protection claim must not depend on the label.

        Every variant below is detected; only the name differs. If context
        inference ever gated detection, an attacker could suppress it by
        removing a word.
        """
        for text in (
            f"Kodas {VALID_LT_CODE}",
            f"asmens kodas {VALID_LT_CODE}",
            f"isikukood {VALID_LT_CODE}",
            f"Vilnius. {VALID_LT_CODE}",
        ):
            spans = BalticPersonalCodeDetector().detect(text)
            assert len(spans) == 1
            assert spans[0].text == VALID_LT_CODE

    def test_an_invalid_checksum_is_not_rescued_by_context(self):
        """Context names a code; it does not make a number into one."""
        assert self._types("Kliento asmens kodas yra 38812211600.") == []

    def test_every_label_the_detector_emits_is_routed_by_the_shipped_policy(self):
        """The gap that would make disambiguation *cost* protection.

        Adding BALTIC_PERSONAL_CODE without adding it to the policy would send
        exactly the codes we are least sure about to the external provider.
        """
        from pathlib import Path

        import yaml

        policy = yaml.safe_load(
            (
                Path(__file__).resolve().parent.parent / "deployment" / "policies" / "default.yaml"
            ).read_text(encoding="utf-8")
        )
        routed = {
            entity
            for rule in policy["rules"]
            for entity in rule.get("match", {}).get("entities", [])
            if rule["action"]["type"] == "route_local"
        }
        emitted = {
            "LV_PERSONAL_CODE",
            "LT_PERSONAL_CODE",
            "EE_PERSONAL_CODE",
            "BALTIC_PERSONAL_CODE",
        }
        assert emitted <= routed, f"not routed locally: {sorted(emitted - routed)}"


class TestHyphenlessLatvianCode:
    """The form that comes out of a database extract rather than a printout.

    Eleven bare digits is also the Lithuanian and Estonian shape, so every case
    here is really about *which* national rule gets to claim the digits.

    The three constants below are load-bearing and were each found by search
    rather than invented:

    * ``LV_ONLY`` satisfies the Latvian check digit and fails the LT/EE one.
    * ``AMBIGUOUS`` satisfies **both**. Roughly one Latvian code in eleven does,
      so this is an ordinary case, not a contrived one.
    * ``LT_EE_ONLY`` satisfies only the LT/EE rule, and pins that this change
      did not disturb the existing detector.
    """

    LV_ONLY = "12038512342"
    AMBIGUOUS = "22010300890"
    LT_EE_ONLY = "62907038711"

    def test_hyphenless_code_is_detected(self):
        spans = BalticPersonalCodeDetector().detect(f"Personas kods {self.LV_ONLY} sistēmā.")
        assert [(s.entity_type, s.text) for s in spans] == [("LV_PERSONAL_CODE", self.LV_ONLY)]

    def test_hyphenless_code_needs_no_context_when_only_latvia_accepts_it(self):
        """Rule 1: the LT/EE detector cannot claim it, so context is redundant."""
        spans = BalticPersonalCodeDetector().detect(f"Value {self.LV_ONLY} in the export.")
        assert [s.entity_type for s in spans] == ["LV_PERSONAL_CODE"]

    def test_ambiguous_code_without_context_admits_the_ambiguity(self):
        """Rule 4. Naming a country here would be a coin flip dressed as a finding."""
        spans = BalticPersonalCodeDetector().detect(f"Value {self.AMBIGUOUS} in the export.")
        assert [s.entity_type for s in spans] == ["BALTIC_PERSONAL_CODE"]

    def test_ambiguous_code_with_latvian_context_is_latvian(self):
        """Rule 3."""
        spans = BalticPersonalCodeDetector().detect(
            f"Klients no Rīgas. Personas kods {self.AMBIGUOUS}."
        )
        assert [s.entity_type for s in spans] == ["LV_PERSONAL_CODE"]

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("Kliento asmens kodas {code} yra.", "LT_PERSONAL_CODE"),
            ("Kliendi isikukood {code} on.", "EE_PERSONAL_CODE"),
        ],
    )
    def test_ambiguous_code_yields_to_a_named_country(self, text, expected):
        """Rule 2: an explicitly named identifier outranks the Latvian reading."""
        spans = BalticPersonalCodeDetector().detect(text.format(code=self.AMBIGUOUS))
        assert [s.entity_type for s in spans] == [expected]

    def test_exactly_one_span_is_emitted_for_an_ambiguous_code(self):
        """Both recognisers see these digits; only one may survive.

        Two spans over identical offsets would be reduced by `resolve_conflicts`
        on an alphabetical tiebreak -- which is how every ambiguous code would
        silently become ``BALTIC_PERSONAL_CODE`` regardless of the evidence.
        """
        for context in (
            f"Value {self.AMBIGUOUS} here.",
            f"Personas kods {self.AMBIGUOUS} Rīgā.",
            f"Asmens kodas {self.AMBIGUOUS} yra.",
        ):
            assert len(BalticPersonalCodeDetector().detect(context)) == 1

    def test_lithuanian_and_estonian_detection_is_unchanged(self):
        detector = BalticPersonalCodeDetector()
        assert [s.entity_type for s in detector.detect(f"Value {self.LT_EE_ONLY} here.")] == [
            "BALTIC_PERSONAL_CODE"
        ]
        assert [
            s.entity_type for s in detector.detect(f"Asmens kodas {self.LT_EE_ONLY} klientui.")
        ] == ["LT_PERSONAL_CODE"]

    @pytest.mark.parametrize("number", ["99999999999", "20240115001", "12345678901"])
    def test_ordinary_eleven_digit_numbers_are_not_flagged(self, number):
        """The precision bar the module docstring sets: no bare-regex firing.

        Order numbers, references, and timestamps are eleven digits often
        enough that failing this would make the detector something a customer
        switches off.
        """
        assert BalticPersonalCodeDetector().detect(f"Reference {number} logged.") == []

    def test_the_hyphenated_form_still_wins_where_both_could_match(self):
        text = "Personas kods 120385-12342 ir klienta."
        spans = BalticPersonalCodeDetector().detect(text)
        assert [(s.entity_type, s.text) for s in spans] == [("LV_PERSONAL_CODE", "120385-12342")]


class TestChecksumHelpers:
    @pytest.mark.parametrize("number", ["4111111111111111", "5500005555555559", "378282246310005"])
    def test_luhn_accepts_known_test_cards(self, number):
        assert luhn_valid(number)

    @pytest.mark.parametrize("number", ["4111111111111112", "1234567890123456"])
    def test_luhn_rejects_invalid(self, number):
        assert not luhn_valid(number)

    @pytest.mark.parametrize(
        "iban", ["GB82WEST12345698765432", "DE89370400440532013000", "LV80BANK0000435195001"]
    )
    def test_iban_accepts_valid(self, iban):
        assert iban_valid(iban)

    def test_iban_rejects_bad_check_digits(self):
        assert not iban_valid("GB82WEST12345698765433")


class TestIbanDetection:
    """The grouped form is the one banks actually print.

    `iban_valid` always stripped spaces, but the pattern was contiguous, so a
    statement pasted out of a finance system went undetected. These tests pin
    the grouped form and the trimming that keeps it from over-reaching.
    """

    def test_contiguous_iban_is_detected(self):
        spans = IbanDetector().detect("Payment to LV49BANK2081351354829 received.")
        assert [s.text for s in spans] == ["LV49BANK2081351354829"]

    def test_space_grouped_iban_is_detected(self):
        text = "Payment to LV80 BANK 0000 4351 9500 1 received."
        spans = IbanDetector().detect(text)
        assert [s.text for s in spans] == ["LV80 BANK 0000 4351 9500 1"]

    def test_grouped_iban_does_not_swallow_following_words(self):
        """The pattern is greedy across spaces; the trim has to pull it back.

        Without trimming, the uppercase words after the IBAN are absorbed into
        the match and the whole thing fails mod-97, losing the detection
        entirely -- a false negative caused by neighbouring text.
        """
        text = "IBAN LV80 BANK 0000 4351 9500 1 PLEASE PAY BY FRIDAY"
        spans = IbanDetector().detect(text)
        assert [s.text for s in spans] == ["LV80 BANK 0000 4351 9500 1"]

    def test_reported_offsets_address_the_reported_text(self):
        """A span whose offsets do not match its text corrupts replacement."""
        text = "Konto EE38 2200 2210 2014 5685 palun."
        for span in IbanDetector().detect(text):
            assert text[span.start : span.end] == span.text

    def test_grouped_iban_with_bad_checksum_is_not_flagged(self):
        assert IbanDetector().detect("Account LV80 BANK 0000 4351 9500 2 is wrong.") == []

    def test_grouped_non_iban_is_not_flagged(self):
        assert IbanDetector().detect("Order ABCD 1234 5678 9012 3456 shipped.") == []


class TestPaymentCards:
    def test_luhn_invalid_number_is_not_flagged(self):
        assert PaymentCardDetector().detect("Reference 1234567890123456") == []

    @pytest.mark.parametrize(
        "text",
        [
            "Export stamp 20231104-11220 recorded.",
            "Timestamp 20240115-09301 marks the export.",
        ],
    )
    def test_a_date_stamp_is_not_a_payment_card(self, text):
        """Found by the holdout split, not by review.

        The old pattern allowed a separator at any position, so an eight-digit
        date followed by a hyphen and five more digits matched -- and roughly
        one such string in ten also satisfies Luhn. Luhn cannot prevent this: it
        checks that a digit string is well-formed, not that it is a card, so the
        precision has to come from the grouping.
        """
        assert PaymentCardDetector().detect(text) == []

    @pytest.mark.parametrize(
        "text",
        [
            "Charge 4111111111111111 today.",
            "Card 4111 1111 1111 1111 ok",
            "Card 4111-1111-1111-1111 ok",
            "Card 3782 822463 10005 ok",
        ],
    )
    def test_real_card_groupings_are_still_detected(self, text):
        """The shapes cards are actually written in: contiguous, fours, Amex."""
        assert len(PaymentCardDetector().detect(text)) == 1

    def test_separated_card_is_detected(self):
        spans = PaymentCardDetector().detect("Card 4111 1111 1111 1111 ok")
        assert len(spans) == 1
        assert spans[0].text == "4111 1111 1111 1111"


class TestEmail:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("mail alice@acme.lv now", "alice@acme.lv"),
            ("a.b+tag@sub.example.co.uk", "a.b+tag@sub.example.co.uk"),
        ],
    )
    def test_detects(self, text, expected):
        spans = EmailDetector().detect(text)
        assert len(spans) == 1
        assert spans[0].text == expected

    @pytest.mark.parametrize("text", ["not-an-email", "@nope.com", "a@b", "user@.com"])
    def test_rejects_non_emails(self, text):
        assert EmailDetector().detect(text) == []


class TestSecrets:
    @pytest.mark.parametrize(
        "text,entity",
        [
            ("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY"),
            ("ASIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY"),
            ("ghp_1234567890abcdefghijklmnopqrstuvwxyz", "GITHUB_TOKEN"),
            ("xoxb-" + "1234567890-abcdefghij", "SLACK_TOKEN"),
        ],
    )
    def test_detects_credential(self, text, entity):
        spans = SecretDetector().detect(f"value: {text}")
        assert entity in {s.entity_type for s in spans}

    def test_detects_private_key_block(self):
        key = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQE\n-----END EC PRIVATE KEY-----"
        spans = SecretDetector().detect(key)
        assert len(spans) == 1
        assert spans[0].entity_type == "PRIVATE_KEY"

    def test_does_not_flag_ordinary_text(self):
        assert SecretDetector().detect("The AKIA prefix identifies AWS keys.") == []


class TestCustomerRules:
    def test_dictionary_matches_case_insensitively(self):
        spans = DictionaryDetector(["Project Aurora"]).detect("about PROJECT aurora today")
        assert len(spans) == 1

    def test_dictionary_does_not_match_inside_words(self):
        """Substring matching would corrupt unrelated text."""
        assert DictionaryDetector(["Ada"]).detect("Canada and Adapter") == []

    def test_longest_term_wins(self):
        detector = DictionaryDetector(["Acme", "Acme Latvia SIA"])
        spans = detector.detect("contract with Acme Latvia SIA signed")
        assert len(spans) == 1
        assert spans[0].text == "Acme Latvia SIA"

    def test_empty_dictionary_is_safe(self):
        assert DictionaryDetector([]).detect("anything") == []

    def test_custom_regex_matches(self):
        spans = CustomRegexDetector(r"AUR-[0-9]{6}", "PROJECT_CODE").detect("ref AUR-123456 ok")
        assert len(spans) == 1
        assert spans[0].entity_type == "PROJECT_CODE"

    def test_rejects_catastrophic_backtracking_pattern(self):
        for pattern in [r"(a+)+", r"(a*)*", r"(x+)*"]:
            with pytest.raises(UnsafePatternError, match="nested unbounded"):
                CustomRegexDetector(pattern, "X")

    def test_rejects_invalid_regex(self):
        with pytest.raises(UnsafePatternError, match="invalid regular expression"):
            CustomRegexDetector(r"([unclosed", "X")

    def test_rejects_oversized_pattern(self):
        with pytest.raises(UnsafePatternError, match="exceeds"):
            CustomRegexDetector("a" * 600, "X")

    def test_zero_width_match_produces_no_span(self):
        assert CustomRegexDetector(r"x*", "X").detect("yyy") == []


class TestConflictResolution:
    def test_email_is_not_split_into_person_and_domain(self):
        from gateway.detectors.base import resolve_conflicts
        from gateway.domain import Span

        email = Span(0, 13, "EMAIL_ADDRESS", "alice@acme.lv", 1.0)
        person = Span(0, 5, "PERSON", "alice", 0.8)
        resolved = resolve_conflicts([person, email])
        assert resolved == [email]

    def test_higher_score_wins_a_partial_overlap(self):
        from gateway.detectors.base import resolve_conflicts
        from gateway.domain import Span

        strong = Span(0, 10, "IBAN", "x" * 10, 1.0)
        weak = Span(5, 15, "PERSON", "y" * 10, 0.5)
        assert resolve_conflicts([weak, strong]) == [strong]
