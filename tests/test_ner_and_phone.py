"""Contextual detection: the NER adapter and the phone recogniser.

The NER tests use a stub backend rather than a real model. That is deliberate:
what needs testing here is our contract -- verification, label mapping, bounds
checking, and fail-closed behaviour -- not spaCy's accuracy. Model quality is
measured by ``make evals`` against the corpus, which is the only place a number
about detection quality should come from.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from gateway.detectors.ner import (
    LABEL_MAP,
    MANIFEST_NAME,
    NerDetector,
    NerUnavailableError,
    build_ner_detector,
    describe_availability,
    verify_model,
)
from gateway.domain import RequestContext
from recognizers.baltic.phone_numbers import PhoneNumberDetector

# ---------------------------------------------------------------------------
# Phone numbers
# ---------------------------------------------------------------------------


@pytest.fixture
def phones() -> PhoneNumberDetector:
    return PhoneNumberDetector()


class TestInternationalFormat:
    @pytest.mark.parametrize(
        "text",
        [
            "Zvaniet +371 29123456 lai apstiprinātu.",
            "Call +37129123456 to confirm.",
            "Kontakts: +371-2912-3456.",
            "Skambinkite +370 61234567 dėl patvirtinimo.",
            "Helista +372 5123456 kinnituseks.",
            "Reach the desk on +44 2071234567 during office hours.",
        ],
    )
    def test_detects_with_country_code(self, phones, text):
        spans = phones.detect(text)
        assert len(spans) == 1, f"expected one number in {text!r}, got {spans}"
        assert spans[0].entity_type == "PHONE_NUMBER"
        assert text[spans[0].start : spans[0].end] == spans[0].text

    @pytest.mark.parametrize(
        "text",
        [
            "Reference +371 123 is the ticket.",  # too short for the LV plan
            "Order +371 91234567 was placed.",  # 9x is not an LV subscriber range
            "Version +370 9123456789012345678 released.",  # beyond E.164 length
        ],
    )
    def test_rejects_numbers_that_break_the_numbering_plan(self, phones, text):
        assert phones.detect(text) == []


class TestNationalFormatRequiresContext:
    def test_detects_with_a_context_word(self, phones):
        spans = phones.detect("Tālr. 29123456, jautājiet Ilzei.")
        assert len(spans) == 1
        assert spans[0].text == "29123456"

    @pytest.mark.parametrize("prefix", ["Tel.", "Mob.", "Telefonas", "Phone:", "Mobile", "Telefon"])
    def test_context_words_across_the_languages(self, phones, prefix):
        assert len(phones.detect(f"{prefix} 29123456")) == 1

    @pytest.mark.parametrize(
        "text",
        [
            "Order number 29123456 shipped today.",
            "The invoice total was 61234567 cents.",
            "Batch 51234567 completed successfully.",
            "Serial 29123456.",
        ],
    )
    def test_bare_digit_runs_are_not_phone_numbers(self, phones, text):
        """The precision case that decides whether this detector stays enabled.

        Any 8-digit run is structurally a Baltic phone number. Without the
        context requirement, every order reference in every prompt is
        pseudonymised and the customer switches the detector off -- at which
        point protection is zero.
        """
        assert phones.detect(text) == []

    def test_a_context_word_far_away_does_not_license_a_match(self, phones):
        text = "Tālr. numuru nezinu, bet pasūtījuma numurs ir 29123456."
        assert phones.detect(text) == []

    def test_national_match_scores_below_international(self, phones):
        national = phones.detect("Tālr. 29123456")[0]
        international = phones.detect("Zvaniet +371 29123456")[0]
        assert national.score < international.score


class TestPhoneInteraction:
    def test_a_number_is_not_reported_twice(self, phones):
        """The international match must claim the span the national one would."""
        spans = phones.detect("Tālr. +371 29123456 darba laikā.")
        assert len(spans) == 1
        assert spans[0].text.startswith("+371")

    def test_spans_are_within_bounds(self, phones):
        text = "Tālr. 29123456 un +371 61234567."
        for span in phones.detect(text):
            assert 0 <= span.start < span.end <= len(text)
            assert text[span.start : span.end] == span.text


# ---------------------------------------------------------------------------
# NER adapter
# ---------------------------------------------------------------------------


class StubBackend:
    def __init__(self, entities):
        self._entities = entities

    def entities(self, text: str):
        return self._entities


class ExplodingBackend:
    def entities(self, text: str):
        raise RuntimeError("model exploded, and the prompt was SECRET-CANARY")


def write_model(directory, contents: dict[str, bytes], **overrides):
    for name, payload in contents.items():
        (directory / name).write_bytes(payload)
    manifest = {
        "name": "test-ner",
        "version": "0.0.1",
        "licence": "MIT",
        "languages": ["lv", "lt", "et", "en"],
        "sha256": {name: hashlib.sha256(payload).hexdigest() for name, payload in contents.items()},
    }
    manifest.update(overrides)
    (directory / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    return directory


class TestModelVerification:
    def test_verifies_a_matching_manifest(self, tmp_path):
        write_model(tmp_path, {"weights.bin": b"abc", "config.cfg": b"def"})
        manifest = verify_model(tmp_path)
        assert manifest.licence == "MIT"
        assert manifest.languages == ("lv", "lt", "et", "en")

    def test_refuses_a_modified_artefact(self, tmp_path):
        """Detection output is evidence. Evidence from an unreviewed artefact
        is not evidence."""
        write_model(tmp_path, {"weights.bin": b"abc"})
        (tmp_path / "weights.bin").write_bytes(b"tampered")
        with pytest.raises(NerUnavailableError, match="checksum mismatch"):
            verify_model(tmp_path)

    def test_refuses_a_missing_file(self, tmp_path):
        write_model(tmp_path, {"weights.bin": b"abc"})
        (tmp_path / "weights.bin").unlink()
        with pytest.raises(NerUnavailableError, match="missing"):
            verify_model(tmp_path)

    def test_refuses_a_model_with_no_manifest(self, tmp_path):
        (tmp_path / "weights.bin").write_bytes(b"abc")
        with pytest.raises(NerUnavailableError, match=MANIFEST_NAME):
            verify_model(tmp_path)

    def test_refuses_a_manifest_with_no_digests(self, tmp_path):
        write_model(tmp_path, {}, sha256={})
        with pytest.raises(NerUnavailableError, match="no file digests"):
            verify_model(tmp_path)


class TestEnablingAndDisabling:
    def test_unset_path_means_disabled_not_broken(self):
        assert build_ner_detector(None) is None
        assert build_ner_detector("") is None
        assert describe_availability(None)["enabled"] is False

    def test_a_bad_path_is_a_startup_failure(self, tmp_path):
        """Enabled-but-unusable must never degrade to silently-off.

        The operator has said they want PERSON detected. Serving requests
        without it, while they believe it is on, is worse than refusing to
        start.
        """
        with pytest.raises(NerUnavailableError, match="not a directory"):
            build_ner_detector(tmp_path / "nope")

    def test_availability_report_carries_no_model_internals(self, tmp_path):
        write_model(tmp_path, {"weights.bin": b"abc"})
        report = describe_availability(tmp_path)
        assert report["usable"] is True
        assert report["licence"] == "MIT"
        assert "sha256" not in report


class TestLabelMappingAndBounds:
    def test_maps_upstream_labels_to_our_taxonomy(self):
        text = "Ilze works at Acme in Riga."
        detector = NerDetector(
            StubBackend(
                [
                    (0, 4, "PER", 0.9),
                    (14, 18, "ORG", 0.9),
                    (22, 26, "GPE", 0.9),
                ]
            )
        )
        found = {(s.entity_type, s.text) for s in detector.detect(text)}
        assert found == {("PERSON", "Ilze"), ("ORG", "Acme"), ("LOCATION", "Riga")}

    def test_unknown_labels_are_dropped_not_passed_through(self):
        """A model that gains a label must not introduce a new entity type
        into policy evaluation without anyone deciding to."""
        detector = NerDetector(StubBackend([(0, 4, "WORK_OF_ART", 0.9)]))
        assert detector.detect("Ilze works here.") == []

    def test_every_mapped_label_lands_in_the_supported_set(self):
        from gateway.detectors.ner import SUPPORTED_ENTITY_TYPES

        assert set(LABEL_MAP.values()) == set(SUPPORTED_ENTITY_TYPES)

    @pytest.mark.parametrize(
        "entity", [(0, 500, "PER", 0.9), (-3, 4, "PER", 0.9), (6, 2, "PER", 0.9)]
    )
    def test_out_of_bounds_spans_are_dropped_not_clamped(self, entity):
        """A silently adjusted span is a silently wrong span.

        The transformation stage replaces exactly the bytes a span selects, so a
        clamped span would replace the wrong ones -- and a span past the end
        would raise inside Span's own validation, failing the whole request for
        a model bug.
        """
        detector = NerDetector(StubBackend([entity]))
        assert detector.detect("Ilze works here.") == []

    def test_low_confidence_entities_are_filtered(self):
        detector = NerDetector(StubBackend([(0, 4, "PER", 0.01)]), min_score=0.35)
        assert detector.detect("Ilze works here.") == []

    def test_backend_failure_raises_and_names_no_content(self):
        detector = NerDetector(ExplodingBackend())
        with pytest.raises(NerUnavailableError) as caught:
            detector.detect("Ilze works here.")
        assert "SECRET-CANARY" not in str(caught.value)
        assert "RuntimeError" in str(caught.value)


class TestNerFailsClosedInThePipeline:
    async def test_a_failing_ner_detector_blocks_the_request(
        self, policy, vault, minter, mock_provider, audit_sink
    ):
        from gateway.inspection.pipeline import DetectionError, SecurityPipeline
        from gateway.restoration.engine import RestorationEngine
        from gateway.transformations.engine import TransformationEngine

        pipeline = SecurityPipeline(
            detectors=[NerDetector(ExplodingBackend())],
            policy=policy,
            transformer=TransformationEngine(minter, vault),
            restorer=RestorationEngine(vault),
            providers={"mock": mock_provider, "local": mock_provider},
            audit_sink=audit_sink,
        )
        payload = {"model": "m", "messages": [{"role": "user", "content": "Ilze"}]}
        ctx = RequestContext("tenant-a", "conv-1", "req-1", "key-1")

        with pytest.raises(DetectionError):
            await pipeline.process(ctx, payload)
        assert mock_provider.received == [], "nothing may be forwarded when detection fails"
