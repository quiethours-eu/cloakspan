# ADR-0019: Validate SSE and withhold executable tool batches

**Status:** experimental implementation decision · 2026-10-08 ·
`REQUIRES_SECURITY_REVIEW`. **Owner:** Technical lead (implementation), Security
owner (review). No invariant waiver or production qualification is granted.

## Context

Streaming splits UTF-8 and surrogate tokens at arbitrary byte boundaries, and
provider tool deltas become executable actions at clients. A line-by-line proxy
can leak part of a token, accept truncated completion or expose unsafe arguments.

## Decision

Use incremental UTF-8/SSE parsing and protocol-specific state machines. Bound
event bytes, item counts, total restored output, idle time, total time and
concurrent requests. Validate identity/index associations, legal transitions,
terminal events and final snapshots. Reject oversized, malformed, duplicate,
mismatched or truncated streams.

Text restoration withholds only the bounded suffix that may still be an
incomplete token according to the supported token grammar. Completed safe text
can flow incrementally. Raw and restored text remain in bounded memory for final
snapshot comparison, within the configured output limit; this is not a claim
of constant total stream memory. Refused prose tokens preserve existing refusal behavior; this
does not implement semantic/full-output DLP. Policies requiring complete-output
analysis need a separate buffering and latency contract.

Assemble arguments and completed snapshots privately, apply ADR-0018 to the
entire executable batch after a successful provider terminal state and clean SSE
EOF, then encode valid client events. Emit one complete validated argument delta
per call, preserve IDs/indexes and reissue monotonically increasing Responses
sequence numbers. No argument fragment or completed executable call is
released earlier. Emit usage and failure/terminal semantics consistently with
the protocol, without treating restored local text as provider-generated tokens.
Native Messages `stop_sequence` must match an exact current sanitized requested
stop sequence; it is never an arbitrary provider-controlled content sink.

Disconnect cancels provider work and releases resources. Failures after client
output cannot restart generation; retries must be restricted to explicitly safe
pre-delivery conditions and reuse the same transformed payload. A downstream
failure is an error, never a fabricated successful completion.

## Consequences and release evidence

Test all surrogate split positions, split UTF-8, interleaved item identities,
delta/snapshot consistency, missing terminal states, cancellation, limits and
later-call batch rejection. This preserves SI-01, SI-02, SI-03, SI-10, SI-16 and
SI-17. Generated protocol fixtures provide regression evidence only. Actual
client event encoding, long thinking periods and backpressure behavior require
qualification on pinned versions before usable client support is advertised.
