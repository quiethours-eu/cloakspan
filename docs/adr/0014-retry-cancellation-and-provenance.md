# ADR-0014: Retry, cancellation, concurrency, and provenance isolation

**Status:** PROPOSED · 2026-08-03
**Invariants:** [SI-16](../security-invariants.md#si-16--retry-and-concurrency-safety),
[SI-03](../security-invariants.md#si-03--current-request-restoration-only)

## Context

Provenance is the primary restoration control: a token is restored only if **this
pipeline run** minted it. Any mechanism that lets a provenance set outlive its
request, merge with another, or be reconstructed defeats
[SI-03](../security-invariants.md#si-03--current-request-restoration-only) without
touching a line of restoration code.

Today the property holds — and holds for a reason that will not survive the next
feature. There is **no retry logic at all**: `chat_completion` issues one POST and
maps failure to `ProviderError`
([routing/base.py:131](../../gateway/routing/base.py)). `TokenProvenance` is
created inside `process` and never escapes
([pipeline.py:180](../../gateway/inspection/pipeline.py)).

So SI-16 is satisfied by absence. There is no test that would fail if someone
added a retry loop that reused a provenance set across attempts, or a cache that
keyed provenance by conversation instead of request. Specifying the behaviour
*before* implementing retries is the entire point of this ADR.

The plan requires retry and backoff "that preserves request provenance and
idempotency" as a Phase 5 deliverable. This defines what that means.

## Decision

### 1 · Provenance is created once per `process` call and never shared

Not per attempt, not per conversation, not per connection. The set accumulates
across every message and every field of **one** request, which is what makes the
same value map to the same token throughout a prompt.

This is a structural rule, enforceable by review: `TokenProvenance` is
constructed in exactly one place and passed down. Any second construction site,
or any storage of a provenance set in a longer-lived object, is a defect.

### 2 · Retries reuse the same provenance set, and never re-mint

A retry re-sends the **already-transformed** payload. It does not re-run
detection, does not re-mint, and does not create a new provenance set.

This is the safe direction, and it is worth being explicit about why the obvious
alternative is wrong. Re-running the pipeline per attempt would be *deterministic*
— the same value yields the same token — so it looks harmless. It is not: it
doubles the vault writes, it makes the audit event's entity counts ambiguous
(were three entities detected, or one entity detected three times?), and it makes
detection latency a multiplier on the retry budget. Transform once, send many.

### 3 · Retries are bounded, idempotent, and only on safe failures

| Failure | Retry | Why |
|---|---|---|
| Connection error before any bytes sent | **Yes** | The provider never saw the request |
| Timeout with no response | **No** | The provider may have processed it. Retrying risks a duplicate billed completion, and there is no idempotency key in the OpenAI API to prevent it |
| HTTP 429 | **Yes**, honouring `Retry-After` | |
| HTTP 5xx | **Yes**, except 501 | |
| HTTP 4xx other than 429 | **No** | The request is wrong; retrying it is wrong again |

Maximum 2 retries, exponential backoff with full jitter, and a **total** deadline
of `SAG_REQUEST_TIMEOUT_SECONDS` across all attempts rather than per attempt —
otherwise a 120 s timeout becomes a 360 s worst case and the client has already
disconnected.

### 4 · Cancellation

If the client disconnects, or the total deadline elapses, after the vault has
been written but before the provider responds:

- The provenance set is discarded with the request.
- **Vault records are not deleted.** They expire on TTL like any other record.
- No audit event is written for a cancelled request today; a `cancelled` outcome
  is added to the audit schema.

Deleting vault records on cancellation was considered and rejected: cancellation
is exactly when a client retries at the application layer, and a deleted mapping
would turn a retry into an unrestorable response. Leaving orphaned records to
expire costs one hour of retention for records nobody will read.

**The security-relevant claim is that an orphaned vault record is not
restorable by anyone.** Restoration requires provenance, the provenance set died
with the request, and no new request can recreate it — a later request in the same
conversation that detects the same value mints the same token and records it in
*its own* provenance, which is the legitimate path, not a replay.

### 5 · Concurrency

Concurrent requests in the same conversation are safe by construction and must be
tested rather than assumed:

- Each has its own provenance set.
- Both may mint the same token for the same value — deterministic by design — and
  both write it to the vault. The writes are **idempotent**: same key, same
  plaintext, different nonce. Last write wins and the value is identical.
- Neither can restore the other's tokens, because provenance is per request.

The vault backend must be safe for concurrent access. `InMemoryBackend` uses a
plain `dict` ([vault/store.py:73](../../gateway/vault/store.py)); under CPython
individual `dict` operations are atomic under the GIL, so this is currently
correct **by accident of the interpreter**. A file or PostgreSQL backend has no
such guarantee. The `VaultBackend` protocol is therefore documented as requiring
thread-safe `put`/`get`/`delete`, and `InMemoryBackend` gets an explicit lock so
the requirement is visible rather than inherited.

## Required tests

None of these exist today. Each maps to SI-16 in the security invariants.

1. Two concurrent requests, same tenant and conversation, same value → same
   token, both restore correctly, neither restores the other's tokens.
2. Two concurrent requests, different tenants, same value → different tokens.
3. Retry after a connection error → one detection pass, one set of vault writes,
   provenance unchanged, correct restoration.
4. Cancellation after a vault write, before the provider responds → the record
   exists, is not restorable, and expires on TTL.
5. A provenance set is never reachable from any object that outlives `process` —
   asserted structurally.
6. Retry does not re-run detection — asserted by counting detector invocations.

## Alternatives considered

| Option | Rejected because |
|---|---|
| Retry by re-running the whole pipeline | Doubles vault writes, makes audit counts ambiguous, multiplies detection latency by the retry budget |
| Provenance keyed by conversation | Directly defeats SI-03. This is the design the rest of the field ships |
| Delete vault records on cancellation | Turns an application-layer retry into an unrestorable response |
| Retry timeouts | Risks duplicate billed completions with no idempotency key available |

## Consequences

**Security.** SI-16 moves from "true by absence" to "true by design, with tests
that fail if it stops being true". That is the difference the invariant is for.

**Delivery.** ~1.5 engineer-days for the retry implementation, ~1 for the
concurrency and cancellation tests. The tests are the valuable half and should
land first — they pass today, and they are what stops the retry work from
regressing the property.

**Reversal cost.** Low.

---

## Amendment, 2026-08-04: the HTTP client is now shared across requests

Accepted. This ADR assumed, without ever stating it, that a client is
constructed and discarded per request — `async with httpx.AsyncClient(...)`
inside the retry loop. That assumption made cancellation trivially safe: the
client died with the request, so nothing could survive it.

It also cost, per request:

* **~400 ms** rebuilding the TLS trust store, because `verify=True` makes httpx
  construct an `SSLContext` from scratch. Measured on **loopback**, with no
  network involved, so this was CPU, not latency.
* **+53 ms** against a public HTTPS provider for a TCP and TLS handshake a pool
  would not have needed (+11 ms over a LAN-like link, +2 ms on loopback).

End to end against a real 30B model — identical payload, identical upstream,
interleaved sampling, no entities detected so no pipeline work at all:

| | overhead vs calling the model directly |
|---|---|
| per-request client | **+410.5 ms** |
| shared trust store | +16.5 ms |
| shared trust store **and** pooled client | **+3.1 ms** |

### What changes for this ADR

The provider now holds one `httpx.AsyncClient`, created lazily on first use and
closed from the application lifespan. **A connection outlives the request that
opened it.** Everything this ADR actually specifies is unaffected, because none
of it lives in the transport:

* **Provenance** is created in `process` and never escapes it. It has no
  relationship to the connection, and pooling cannot extend its lifetime.
* **Retries** still re-send the already-transformed payload under the same
  provenance set, and still share one deadline across attempts. That deadline
  moved from the client to the request when the client became shared —
  `build_request(..., timeout=remaining)` — pinned by
  `test_the_per_request_deadline_still_shrinks_across_retries`.
* **Timeouts are still not retried.** Unchanged.

### What genuinely changed, and the argument for accepting it

**Cancellation no longer destroys the client.** httpx returns the connection to
the pool instead. The `finally: aclose()` around the response already guarantees
a half-consumed body is closed, and
`test_a_cancelled_request_leaves_the_provider_usable` asserts the provider still
works afterwards.

**Pools are per provider instance**, so a `local` connection is never reachable
from `external`. They are different objects carrying different egress policies,
and `test_two_providers_do_not_share_a_pool` fixes that.

**DNS is re-resolved less often**, because a live connection is reused. This
*narrows* the rebinding window described in `gateway/routing/egress.py` rather
than widening it — but it does not close it, and should not be presented as a
fix. Egress is still validated per request before any connection is used, and a
new connection still resolves again afterwards.

### The honest caveat

The mutation check that validated the deadline test first showed it passing
against deliberately broken code: httpx falls back to its own client-default
timeout, a constant, and the original assertions ("not None", "non-increasing")
could not tell a constant from a shrinking deadline. The default happened to
equal the value the test configured, which is what made it look right. The test
now uses a timeout no default can imitate and asserts a strict decrease.
Recorded because a test that cannot fail is worse than no test — it is a claim
of coverage.
