# Known limitations

This list describes the current alpha, not the intended product. A limitation
stays here until code, tests, and operational evidence all agree that it is
closed.

## Detection and privacy

- Detection is incomplete. Automated detectors will miss some sensitive data.
- The gateway pseudonymizes; it does not anonymize. Deterministic tokens reveal
  repeated values within one conversation, the entity type, and the number of
  distinct values. Pseudonymized data remains personal data.
- PERSON, ORG, LOCATION, and ADDRESS require an operator-supplied NER model. No
  model artifact ships with the repository.
- National-format phone numbers require a nearby context word such as `tel.` or
  `phone`. This reduces false positives but misses unlabeled numbers.
- Lithuanian and Estonian personal codes share a construction and checksum.
  Without surrounding country context, the detector reports the broader
  `BALTIC_PERSONAL_CODE` type.
- Multi-character confusables such as `œ -> oe` are not folded. The 1:1 map does
  handle relevant single-character homoglyphs, fullwidth digits, zero-width
  insertion, and common dash substitutions while preserving offsets.

## API and runtime

- Only a strict text subset of `POST /v1/chat/completions` is supported.
  Streaming, tool calls, structured output, `stop`, `user`, multimodal content,
  and unknown fields are refused.
- Provider responses are buffered. Streaming is not silently downgraded because
  a sensitive value can cross chunk boundaries.
- The default vault is in memory. It is single-node, loses mappings on restart,
  and cannot support restoration across replicas.
- Detector execution has no hard timeout. Customer regular expressions use
  Python's backtracking engine and must be reviewed as trusted configuration; a
  pathological pattern can consume unbounded CPU within the request worker.
- Provider destinations are validated at startup and per request, but the HTTP
  transport resolves DNS again when it connects. Fast DNS rebinding is not
  fully prevented.
- Upstream response bytes and restored content are capped separately before the
  final response is assembled.
- Error responses and provider failures do not currently write audit events.
- Cancellation releases the client connection but cannot interrupt synchronous
  detector work already running in a worker thread.

## Evidence and release engineering

- The synthetic evaluation corpora are small. Some generated identifiers use
  the same published checksum algorithms as the detectors, so the reported
  scores primarily test segmentation and known boundary cases.
- Performance numbers are machine-local regression signals, not an SLO or a
  published capacity claim.
- No independent security review has been performed.
- This checkout has no Git remote and no published Actions run to cite.
  Container SBOM, Trivy image scanning, hardening tests, signing, and provenance
  therefore lack public release evidence.
- The base image is still referenced without a release digest, so the release
  image gate intentionally refuses to publish.

See [security invariants](security-invariants.md) for enforcement points. Open
risks and planned mitigations are summarized below.
