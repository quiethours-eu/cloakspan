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

## GDPR mode (`SAG_LOCAL_ROUTING`)

- `detected` is only as good as detection. Personal data that no detector
  finds still reaches the external provider in clear: dates of birth, health
  details, identifiers from countries without a recognizer, names in languages
  the NER model does not cover, and values deliberately spelled to avoid
  detection. Only `all` does not depend on detection.
- The NER model's languages come from its manifest and are printed in the
  startup line. The gateway does not check them against the traffic.
- NER, dictionary, filter, and custom-pattern detectors see the normalised
  text but not the confusable-folded view that the built-in structured
  detectors use, so a homoglyph substitution inside a name or a custom term can
  go undetected.
- The local destination is checked by address, not by who runs it. A proxy on
  a private address that relays to a cloud API passes the check.
- When two detections partly overlap, conflict resolution keeps one span and
  drops the other, so the part of the dropped value outside the kept span is
  sent to the local model unchanged.
- The `model` field is not inspected. Under `detected`, a clean request
  forwards the client's model name to the external provider unless
  `SAG_EXTERNAL_MODEL` replaces it.
- A request that fails, for example because the local model is unreachable,
  on the Chat Completions path writes no audit event, so its audit stream cannot show on its own that
  failed requests never went external.
- Chat Completions has no detector timeout. A detector that hangs holds that request, and
  nothing is forwarded until it returns.

## API and runtime

- The default API supports a strict text subset of `POST /v1/chat/completions`.
  Streaming, tool calls, structured output, `stop`, `user`, multimodal content,
  and unknown fields are refused.
- Chat Completions provider responses are buffered. Streaming is not silently downgraded because
  a sensitive value can cross chunk boundaries.
- The default vault is in memory. It is single-node, loses mappings on restart,
  and cannot support restoration across replicas.
- Chat Completions detector execution has no hard timeout. Customer regular expressions use
  Python's backtracking engine and must be reviewed as trusted configuration; a
  pathological pattern can consume unbounded CPU within the request worker.
- Provider destinations are validated at startup and per request, but the HTTP
  transport resolves DNS again when it connects. Fast DNS rebinding is not
  fully prevented.
- Upstream response bytes and restored content are capped separately before the
  final response is assembled.
- Chat Completions error responses and provider failures do not currently write audit events.
- Chat Completions cancellation releases the client connection but cannot interrupt synchronous
  detector work already running in a worker thread.

## Experimental coding-agent adapters

- Responses and native Messages are opt-in, disabled by default, and separate
  from Chat Completions. Public CLI profiles pin Codex 0.161.0 and Claude Code
  2.1.293 without requiring private versions/captures. See the
  [versioned matrix](agent-compatibility.md) for actual CLI workflow evidence;
  production deployments, desktop configurations and optional bridges need
  their own qualification.
- Registered function tools and a parser-backed shell/patch subset are accepted.
  Local search and registered todo/control shapes are explicit extensions;
  interactive stdin commands, PDF reads, alternate execution environments,
  network permission requests and sandbox-disable true remain refused.
  Both pinned CLI profiles pass actual synthetic read/edit/test/follow-up,
  automatic compaction and resume. Broader tools/formats and live/desktop
  deployments need their own qualification.
- Executable tool schemas support bounded basic assertions and combinations;
  references, patterns, format, conditionals and unknown assertions are refused
  before egress. Declared arguments remain registered typed formats; emitted
  calls must satisfy current tool names/types, choices, parallelism, maximum
  batch size and restored schema validation. Broader real-client schemas may
  need a reviewed extension.
- Sensitive arbitrary JSON numbers cannot be replaced without changing their
  type, so numeric detections are rejected. Agent requests declaring tools
  reject different originals sharing one canonical identity within that request,
  because exact edits cannot safely choose between them. Concurrent requests
  select their own provenance original only after authenticated unexpired vault
  and canonical-identity checks. Chat Completions within-request behavior stays
  unchanged.
- Opaque reasoning/continuation, opaque compaction endpoints, provider-stored history,
  `store: true`, `previous_response_id`, retrieval and WebSockets are disabled.
  The public custom-provider Codex profile uses ordinary requests for inspectable
  local summaries. Actual automatic compaction/resume evidence is distinct from
  short replay demos and does not enable opaque continuation.
- Streams restore surrogate tokens incrementally and withhold executable calls
  until a valid terminal state, clean SSE EOF and complete batch validation.
  Raw/restored text stays in bounded memory for snapshot comparison; withholding
  only an incomplete token suffix does not imply constant total memory.
  This is not arbitrary output DLP. Idle/total
  deadlines and output/event/concurrency limits can reject long model runs.
- Agent inspection runs in a terminable detector process with a wall-clock
  deadline. Optional NER model memory/startup costs and detector serialization on
  platforms without fork require measurement on the actual deployment. Forking
  inside a threaded ASGI host and platform start-method behavior also require
  qualification. Child process limits do not constitute measured cgroup-wide
  memory capacity; measure parent/child/native RSS under concurrency and use
  deployment container memory/CPU controls.
- Workspace checks are a gateway control; clients must repeat symlink checks at
  execution time and retain their sandbox/approvals. The gateway does not execute
  tools or prevent independent shell/MCP network exfiltration.
- Synthetic protocol fixtures, preflight and benchmarks are not actual client
  recordings, live-model evidence or pilot approval. Parent Python memory and
  whitespace token estimates are not full deployment memory/token measurements.
- Client telemetry, web requests, downloads, MCP and executed commands can bypass
  the configured inference endpoint. Separate deployment egress controls are
  required for broader coverage. Detection misses remain possible in every adapter.

## Evidence and release engineering

- The synthetic evaluation corpora are small. Some generated identifiers use
  the same published checksum algorithms as the detectors, so the reported
  scores primarily test segmentation and known boundary cases.
- Performance numbers are machine-local regression signals, not an SLO or a
  published capacity claim.
- Release preparation pins the base image and verifies hashes for runtime
  dependencies. A passing build does not establish operational readiness:
  the staging install/upgrade/rollback rehearsal is still outstanding.

See [security invariants](security-invariants.md) for enforcement points. Open
risks and planned mitigations are summarized below.
