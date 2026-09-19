"""Contextual entity recognition (PERSON, ORG, LOCATION, ADDRESS).

Optional, behind the ``[ner]`` extra. The Community Edition core stays
dependency-light and fully offline; installing NER is a deliberate act with a
model artefact attached to it.

## Three rules this module exists to enforce

**1. No runtime download, ever.** A security gateway that fetches a model on
first request has an outbound dependency on the request path, a supply-chain
surface nobody reviewed, and a different detection surface on every host. The
model path is configured, the artefact is present or it is not, and there is no
third case. This is why ``spacy.load("xx_ent_wiki_sm")`` by name is *not* what
this module does: that resolves through an installed package whose version
nobody pinned.

**2. Checksum-verified.** Detection output is evidence a customer shows a
regulator. An artefact that changed since it was reviewed produces different
evidence, silently. The manifest is compared before the model is loaded.

**3. Fail closed when enabled but unavailable.** If NER is switched on and the
model cannot be loaded, every request is refused (security invariant SI-10). The
alternative -- carrying on with deterministic detectors only -- means the
customer believes PERSON is being caught while it silently is not, which is
worse than an outage because they will not find out.

## Status

`REQUIRES_MODEL_PROVISIONING`. The adapter, the verification, and the failure
semantics are implemented and tested. **No model artefact ships with this
repository**, so with the default configuration this detector is disabled and
PERSON, ORG, LOCATION, and ADDRESS are not detected. ``docs/entity-taxonomy.md``
records them as Absent, and they must not appear in any support matrix until
``make evals`` measures them.

Choosing the model is a Detection-owner decision with a licence review attached
(the candidate multilingual spaCy models are MIT or CC BY-SA, and the difference
matters to a customer redistributing a container).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from gateway.domain import Confidence, Span

logger = logging.getLogger("gateway.detectors.ner")

#: Entity labels this detector may emit, mapped from the upstream model's own
#: label set. Anything outside this map is dropped rather than passed through --
#: a model that gains a label in a later version must not silently introduce a
#: new entity type into policy evaluation.
LABEL_MAP = {
    "PER": "PERSON",
    "PERSON": "PERSON",
    "ORG": "ORG",
    "LOC": "LOCATION",
    "GPE": "LOCATION",
    "FAC": "LOCATION",
    "ADDRESS": "ADDRESS",
}

SUPPORTED_ENTITY_TYPES = ("PERSON", "ORG", "LOCATION", "ADDRESS")

MANIFEST_NAME = "model-manifest.json"


class NerUnavailableError(RuntimeError):
    """NER is enabled but the model cannot be used. Always fails the request."""


class NerBackend(Protocol):
    """The minimum surface a model adapter must offer.

    Deliberately tiny: it keeps spaCy, Presidio, or anything else replaceable,
    and it keeps the security-relevant logic -- verification, label mapping,
    bounds checking -- in this file rather than in a vendor adapter.
    """

    def entities(self, text: str) -> list[tuple[int, int, str, float]]:
        """Return (start, end, label, score) over the text given."""
        ...


@dataclass(frozen=True, slots=True)
class ModelManifest:
    """What a reviewed model artefact is, recorded next to it."""

    name: str
    version: str
    licence: str
    sha256: dict[str, str]
    languages: tuple[str, ...]

    @classmethod
    def load(cls, directory: Path) -> ModelManifest:
        path = directory / MANIFEST_NAME
        if not path.is_file():
            raise NerUnavailableError(
                f"no {MANIFEST_NAME} in {directory}. A model without a manifest has "
                "no recorded licence and no verifiable contents, so it is not usable."
            )
        raw = json.loads(path.read_text(encoding="utf-8"))
        missing = {"name", "version", "licence", "sha256", "languages"} - set(raw)
        if missing:
            raise NerUnavailableError(f"{path} is missing required keys: {sorted(missing)}")
        return cls(
            name=raw["name"],
            version=raw["version"],
            licence=raw["licence"],
            sha256=dict(raw["sha256"]),
            languages=tuple(raw["languages"]),
        )


def verify_model(directory: Path) -> ModelManifest:
    """Check every file listed in the manifest before the model is loaded.

    Verification is a precondition of loading, not a report produced afterwards:
    a mismatched artefact must never be given a chance to run.
    """
    manifest = ModelManifest.load(directory)
    if not manifest.sha256:
        raise NerUnavailableError(
            f"{directory / MANIFEST_NAME} lists no file digests; nothing to verify"
        )

    for relative, expected in sorted(manifest.sha256.items()):
        target = directory / relative
        if not target.is_file():
            raise NerUnavailableError(f"model file listed in the manifest is missing: {relative}")
        digest = hashlib.sha256()
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        actual = digest.hexdigest()
        if actual != expected:
            raise NerUnavailableError(
                f"checksum mismatch for {relative}: manifest says {expected[:16]}..., "
                f"file is {actual[:16]}.... Refusing to load an artefact that has "
                "changed since it was reviewed."
            )

    logger.info(
        "NER model verified: %s %s (%s), languages=%s",
        manifest.name,
        manifest.version,
        manifest.licence,
        ",".join(manifest.languages),
    )
    return manifest


class SpacyBackend:
    """Adapter for a spaCy pipeline loaded from a local directory.

    Imported lazily so the core never requires spaCy, and loaded **by path**
    rather than by model name -- loading by name resolves through whatever
    version happens to be installed, which is exactly the unpinned behaviour
    rule 1 above exists to prevent.
    """

    def __init__(self, directory: Path) -> None:
        try:
            import spacy
        except ImportError as exc:  # pragma: no cover - depends on the extra
            raise NerUnavailableError(
                "NER is enabled but spaCy is not installed. Install the [ner] extra."
            ) from exc

        try:
            self._nlp = spacy.load(directory)
        except Exception as exc:
            raise NerUnavailableError(f"failed to load the NER model from {directory}") from exc

    def entities(self, text: str) -> list[tuple[int, int, str, float]]:
        doc = self._nlp(text)
        # spaCy's default pipelines do not expose per-entity confidence, so a
        # fixed score is used and documented rather than a fabricated one. It
        # feeds policy `min_score`, so inventing a number here would be
        # inventing a policy input.
        return [
            (ent.start_char, ent.end_char, ent.label_, Confidence.MEDIUM.value) for ent in doc.ents
        ]


class NerDetector:
    """Contextual entity detector behind the standard ``Detector`` protocol."""

    name = "ner"

    def __init__(
        self,
        backend: NerBackend,
        manifest: ModelManifest | None = None,
        min_score: float = Confidence.LOW.value,
    ) -> None:
        self._backend = backend
        self._manifest = manifest
        self._min_score = min_score

    @property
    def manifest(self) -> ModelManifest | None:
        return self._manifest

    @classmethod
    def from_directory(cls, directory: Path) -> NerDetector:
        manifest = verify_model(directory)
        return cls(backend=SpacyBackend(directory), manifest=manifest)

    def detect(self, text: str) -> list[Span]:
        try:
            raw = self._backend.entities(text)
        except Exception as exc:
            # Fails closed via the pipeline's detector error handling. The
            # message names the detector and the exception type, never the text
            # (SI-11).
            raise NerUnavailableError(f"NER backend failed: {type(exc).__name__}") from exc

        spans: list[Span] = []
        for start, end, label, score in raw:
            entity_type = LABEL_MAP.get(label.upper())
            if entity_type is None:
                continue
            if score < self._min_score:
                continue
            # A model returning an out-of-bounds or inverted offset would make
            # the transformation stage replace the wrong bytes. Drop rather than
            # clamp: a silently adjusted span is a silently wrong span.
            if not 0 <= start < end <= len(text):
                logger.warning(
                    "NER returned a span outside input bounds; dropping (label=%s)", label
                )
                continue
            spans.append(
                Span(
                    start=start,
                    end=end,
                    entity_type=entity_type,
                    text=text[start:end],
                    score=score,
                    detector=self.name,
                )
            )
        return spans


def build_ner_detector(directory: str | os.PathLike[str] | None) -> NerDetector | None:
    """Construct the detector, or return None when NER is switched off.

    ``None`` means "not enabled". It never means "enabled but broken" -- that
    case raises, so a misconfigured deployment fails at startup rather than
    serving requests with a silently missing detector.
    """
    if not directory:
        return None
    path = Path(directory)
    if not path.is_dir():
        raise NerUnavailableError(
            f"SAG_NER_MODEL_PATH is set to {path}, which is not a directory. "
            "NER is enabled, so this is a startup failure rather than a warning: "
            "running without it would mean PERSON and ORG are silently undetected."
        )
    return NerDetector.from_directory(path)


def describe_availability(directory: str | os.PathLike[str] | None) -> dict[str, Any]:
    """Operator-facing status. Contains no text and no model internals."""
    if not directory:
        return {"enabled": False, "reason": "SAG_NER_MODEL_PATH is not set"}
    try:
        manifest = verify_model(Path(directory))
    except NerUnavailableError as exc:
        return {"enabled": True, "usable": False, "reason": str(exc)}
    return {
        "enabled": True,
        "usable": True,
        "model": manifest.name,
        "version": manifest.version,
        "licence": manifest.licence,
        "languages": list(manifest.languages),
        "entity_types": list(SUPPORTED_ENTITY_TYPES),
    }
