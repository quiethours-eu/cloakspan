"""Detection baseline — a regression guard, not a release gate.

The release gate is ``make evals``, which fails when any entity/language pair is
below its published threshold. As of corpus v2.0.0 it **passes** on both the dev
and the holdout split. It previously failed on Lithuanian personal codes, which
scored 0% recall under strict labelling until the recogniser learned to read
country context; several documents still described that failure long after it
was fixed, so the state is recorded here rather than in prose.

This file exists for the other direction. It pins the numbers we have measured
so that a change which quietly makes detection *worse* fails in CI, rather than
being noticed the next time somebody runs the harness by hand.

The assertions are lower bounds. Improving a detector never breaks a test here;
regressing one always does.
"""

from __future__ import annotations

import re

import pytest

from evals.datasets.schema import load_corpus
from evals.run_evals import THRESHOLDS, build_predictor
from evals.scoring import score_corpus

#: Measured on corpus v2.0.0, dev split, 2026-08-04. Lower bounds.
#:
#: The seven secret types were added in v2.0.0. Before that they carried
#: published thresholds and appeared in no example, so they scored a permanent
#: silent pass -- see ``test_every_thresholded_entity_appears_in_the_corpus``,
#: which now makes that state impossible to re-enter.
BASELINE = {
    "EMAIL_ADDRESS": (1.0, 1.0),
    "IBAN": (1.0, 1.0),
    "PAYMENT_CARD": (1.0, 1.0),
    "LV_PERSONAL_CODE": (1.0, 1.0),
    "PHONE_NUMBER": (1.0, 1.0),
    "LT_PERSONAL_CODE": (1.0, 1.0),
    "EE_PERSONAL_CODE": (1.0, 1.0),
    "BALTIC_PERSONAL_CODE": (1.0, 1.0),
    "AWS_ACCESS_KEY": (1.0, 1.0),
    "PRIVATE_KEY": (1.0, 1.0),
    "JWT": (1.0, 1.0),
    "OPENAI_API_KEY": (1.0, 1.0),
    "ANTHROPIC_API_KEY": (1.0, 1.0),
    "GITHUB_TOKEN": (1.0, 1.0),
    "SLACK_TOKEN": (1.0, 1.0),
}

#: Entity/language pairs known to be below threshold, with the reason. A pair
#: that leaves this list must be removed from it; a pair that joins it needs a
#: written, dated risk acceptance with a named owner first.
#:
#: **Empty as of corpus v1.2.0.** It held the LT/EE label collapse until the
#: recogniser learned to read country context. ``test_known_failures_have_not_
#: silently_been_fixed`` fired the moment that landed, which is the entry's
#: whole purpose: an exception list nobody prunes becomes a place where real
#: regressions hide behind a comment about a different problem.
KNOWN_FAILING: dict[str, str] = {}


@pytest.fixture(scope="module")
def dev_report():
    return score_corpus(load_corpus("dev"), build_predictor())


@pytest.fixture(scope="module")
def dev_report_aliased():
    return score_corpus(load_corpus("dev"), build_predictor(), aliased=True)


class TestCorpusIntegrity:
    def test_both_splits_load(self):
        dev, holdout = load_corpus("dev"), load_corpus("holdout")
        assert len(dev) > 0 and len(holdout) > 0
        assert dev.version == holdout.version

    def test_splits_do_not_share_examples(self):
        """A holdout set that overlaps dev measures nothing.

        This assertion used to compute the full overlap and then assert only on
        the positives subset, with a comment authorising the rest as "expected
        and harmless". It was not harmless: 30 of 66 unique holdout texts were
        byte-identical to dev, including every boundary, negative, adversarial
        and mixed example, and the test passed the whole time. A test that
        measures the thing it is excusing is the shape a real gap hides in.

        As of corpus v2.0.0 the two splits are built from disjoint template and
        value pools, so **no** example may be shared, of any kind.
        """
        dev_texts = {e.text for e in load_corpus("dev").examples}
        holdout_texts = {e.text for e in load_corpus("holdout").examples}
        shared = dev_texts & holdout_texts
        assert not shared, f"{len(shared)} example(s) appear in both splits: {sorted(shared)[:3]}"

    def test_splits_do_not_share_sentence_shapes(self):
        """Disjoint text is not enough if the sentences are the same mould.

        Substituting a different personal code into an identical sentence
        produces a "different" example that tests nothing new, which is exactly
        how the previous holdout passed the text-equality check while still
        being a paraphrase. Comparing with digits masked catches that.
        """

        def shape(text: str) -> str:
            return re.sub(r"\d", "#", text)

        dev_shapes = {shape(e.text) for e in load_corpus("dev").examples}
        holdout_shapes = {shape(e.text) for e in load_corpus("holdout").examples}
        shared = dev_shapes & holdout_shapes
        assert not shared, f"{len(shared)} sentence shape(s) shared between splits"

    def test_every_thresholded_entity_appears_in_the_corpus(self):
        """A threshold on an absent entity cannot fail.

        `Counts.precision`/`recall` return 1.0 on a zero denominator and the
        gate only iterates buckets that exist, so an entity with no examples
        scores a silent, permanent pass. Seven of fifteen entities were in that
        state -- every secret type -- which meant the published table showed
        thresholds being met for detectors the corpus never exercised.
        """
        covered = {
            span.entity_type
            for split in ("dev", "holdout")
            for example in load_corpus(split).examples
            for span in example.spans
        }
        missing = sorted(set(BASELINE) - covered)
        assert not missing, f"thresholded but absent from the corpus: {missing}"

    def test_every_gold_span_matches_its_text(self):
        for split in ("dev", "holdout"):
            for example in load_corpus(split).examples:
                for span in example.spans:
                    assert example.gold_text(span).strip(), (
                        f"{example.id}: gold span {span} selects whitespace"
                    )

    def test_boundary_examples_have_no_gold_spans(self):
        for split in ("dev", "holdout"):
            for example in load_corpus(split).examples:
                if example.kind in ("negative", "boundary"):
                    assert not example.spans


class TestBaselineIsNotRegressed:
    @pytest.mark.parametrize("entity", sorted(BASELINE))
    def test_entity_meets_its_measured_baseline(self, dev_report, entity):
        expected_precision, expected_recall = BASELINE[entity]
        counts = dev_report.by_entity.get(entity)
        assert counts is not None, f"{entity} disappeared from the corpus or the detectors"
        assert counts.precision >= expected_precision, (
            f"{entity} precision regressed: {counts.precision:.1%} < {expected_precision:.1%}"
        )
        assert counts.recall >= expected_recall, (
            f"{entity} recall regressed: {counts.recall:.1%} < {expected_recall:.1%}"
        )

    def test_no_new_failing_pairs(self, dev_report):
        """Every below-threshold pair must already be a known, explained failure."""
        from evals.run_evals import CONTEXTUAL_THRESHOLD
        from evals.scoring import failing_pairs

        failing = {key for key, *_ in failing_pairs(dev_report, THRESHOLDS, CONTEXTUAL_THRESHOLD)}
        unexplained = failing - set(KNOWN_FAILING)
        assert not unexplained, (
            f"new below-threshold pairs with no entry in KNOWN_FAILING: {sorted(unexplained)}"
        )

    def test_known_failures_have_not_silently_been_fixed(self, dev_report):
        """If a known failure is fixed, this list must be updated in the same change.

        A stale exception list is how a real regression hides behind a comment
        about a different problem.
        """
        from evals.run_evals import CONTEXTUAL_THRESHOLD
        from evals.scoring import failing_pairs

        failing = {key for key, *_ in failing_pairs(dev_report, THRESHOLDS, CONTEXTUAL_THRESHOLD)}
        stale = set(KNOWN_FAILING) - failing
        assert not stale, f"these pairs now pass; remove them from KNOWN_FAILING: {sorted(stale)}"


class TestPhoneNumbersDoNotFloodOnBoundaryCases:
    def test_phone_shaped_non_phones_produce_no_false_positives(self, dev_report):
        """The number that decides whether customers keep this detector on.

        The corpus carries order numbers, quantities, and part numbers in
        phone-number shape. Any of them firing means every invoice line in a
        real prompt gets pseudonymised.
        """
        counts = dev_report.by_entity.get("PHONE_NUMBER")
        assert counts is not None, "PHONE_NUMBER vanished from the corpus"
        assert counts.false_positive == 0


class TestBalticAttribution:
    """Lithuanian and Estonian codes are now attributed, not collapsed.

    This class previously asserted the *consolation*: that merging the two
    labels showed every code was detected even though Lithuanian recall was 0%.
    The recogniser now reads country context, so it asserts the real thing.
    """

    def test_lithuanian_and_estonian_are_each_attributed(self, dev_report):
        for entity in ("LT_PERSONAL_CODE", "EE_PERSONAL_CODE"):
            counts = dev_report.by_entity.get(entity)
            assert counts is not None, f"{entity} is no longer emitted"
            assert counts.precision == 1.0 and counts.recall == 1.0

    def test_the_ambiguous_class_is_measured_not_hypothetical(self, dev_report):
        """A bare code with no country context must be labelled and scored.

        Without corpus coverage the ambiguous path would ship unmeasured, which
        is how a fallback quietly becomes the common case.
        """
        counts = dev_report.by_entity.get("BALTIC_PERSONAL_CODE")
        assert counts is not None, "the ambiguous path has no corpus coverage"
        assert counts.support >= 4
        assert counts.precision == 1.0 and counts.recall == 1.0

    def test_merging_the_labels_still_accounts_for_every_code(self, dev_report_aliased):
        """Attribution must not have cost detection.

        Merged, the class must hold every Baltic code -- if attribution ever
        gated detection rather than naming, this is where it would show.
        """
        counts = dev_report_aliased.by_entity.get("BALTIC_PERSONAL_CODE")
        assert counts is not None
        assert counts.recall == 1.0 and counts.precision == 1.0


class TestAdversarialGapIsClosed:
    """R-04 / SI-17, closed by Phase 4.

    The previous version of this class asserted the *opposite* — that evasion
    still worked — so that closing the gap would be a visible, deliberate test
    change rather than a silent improvement nobody noticed. It fired on the
    first run after the offset map landed, which is the tripwire working.
    """

    def test_every_documented_evasion_technique_is_now_detected(self):
        report = score_corpus(load_corpus("dev"), build_predictor(), kinds=("adversarial",))
        assert report.examples_scored > 0, "the adversarial slice must not be empty"

        detected = sum(c.true_positive for c in report.by_entity.values())
        gold = sum(c.support for c in report.by_entity.values())
        assert gold > 0
        assert detected == gold, (
            f"Unicode evasion regressed: {detected}/{gold} detected. The corpus "
            "covers Cyrillic homoglyphs, zero-width insertion, fullwidth digits, "
            "and zero-width inside an email."
        )

    def test_closing_the_gap_introduced_no_false_positives(self):
        """Folding buys recall by loosening matching. Check the bill.

        The boundary corpus is the control: order numbers, quantities, and
        invalid-checksum near-misses must still not fire now that a wider set of
        characters maps onto digits and letters.
        """
        report = score_corpus(load_corpus("dev"), build_predictor())
        boundary = report.by_kind.get("boundary")
        if boundary is not None:
            assert boundary.false_positive == 0

    @pytest.mark.parametrize(
        "word", ["Bērziņa", "Šiauliai", "Jõgeva", "Kazlauskaitė", "Põhjala", "Ozoliņš"]
    )
    def test_baltic_words_are_not_treated_as_deceptive(self, word):
        """The false positive that would block the target market's own language.

        Latin-with-diacritics is Latin. If mixed-script screening ever counts
        these as multi-script, legitimate Baltic traffic gets refused — worse
        than the evasion the screening prevents.
        """
        from gateway.normalization import fold_confusables
        from gateway.normalization.screening import mixed_script_words, screen_text

        assert mixed_script_words(word) == 0
        assert fold_confusables(word) == word
        assert not screen_text(word, block_mixed_script=True).is_blocking
