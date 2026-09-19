# ADR-0013: Vault record lifetime, deletion, and restart semantics

**Status:** PROPOSED · 2026-08-03
**Extends ADR-0005 and ADR-0010.**
**Invariants:** [SI-03](../security-invariants.md#si-03--current-request-restoration-only),
[SI-10](../security-invariants.md#si-10--fail-closed),
[SI-13](../security-invariants.md#si-13--security-critical-actions-produce-audit-evidence)

## Context

The vault is the only place customer data is written outside process memory. How
long a record lives, what deletes it, and what happens across a restart are
therefore privacy commitments, not implementation details — and they are the
questions a DPO asks first.

Current behaviour:

- TTL defaults to 3600 s, configurable via `SAG_VAULT_TTL_SECONDS`.
- TTL is enforced **on read** as well as by sweep
  ([vault/store.py:83](../../gateway/vault/store.py),
  [:175](../../gateway/vault/store.py)) — a sweeper that fails cannot silently
  extend the lifetime of real PII. This is right and is retained.
- `purge_expired` exists but **nothing calls it**. There is no scheduled sweep.
- The default backend is in-memory, so a restart discards everything.
- `delete` exists but is never called by the pipeline.

Three things are unspecified: what TTL *means* for a multi-turn conversation,
what deletion a customer can actually request, and what a restart looks like from
the client's side.

## Decision

### 1 · TTL is scoped to the conversation, and one hour is the default

A record's lifetime starts at `put` and is not extended by reads. One hour is the
default because it is roughly the useful life of a conversation and because it is
short enough to make key rotation cheap
([ADR-0012](0012-vault-record-envelope-and-key-rotation.md) depends on this).

**The consequence must be stated plainly in the quickstart:** a conversation
resumed after the TTL has elapsed will find its tokens unrestorable. The response
contains `<PERSON:v1:...>` verbatim instead of a name. This is the correct
failure — the alternative is retaining personal data for as long as anyone might
come back — but it is surprising, and a customer who meets it without warning
will file it as a bug.

Operators who need longer conversations raise `SAG_VAULT_TTL_SECONDS` knowing
they are extending how long personal data is retained. The setting is a privacy
control, and the deployment guide must say so where the setting is documented,
not in a footnote.

### 2 · A sweep runs, and it is not the enforcement mechanism

A background task calls `purge_expired` every 60 s, emitting a **count** of
purged records as a metric. Read-time expiry remains the enforcement mechanism;
the sweep exists to bound memory, not to bound lifetime.

If the sweep task dies, the gateway logs an error and continues. It does not fail
requests — read-time expiry still holds the privacy line, and failing every
request because a memory-management task stopped would be a self-inflicted
outage.

### 3 · Deletion

Three deletion paths, in increasing scope:

| Trigger | Scope | Mechanism |
|---|---|---|
| TTL elapsed | One record | Read-time expiry + sweep |
| Conversation ended | Every record for (tenant, conversation) | `DELETE /v1/conversations/{id}` — **not yet implemented** |
| Erasure request | Every record for a tenant | Operator procedure, documented in `docs/data-retention.md` |

The conversation-scoped endpoint is required for GDPR Article 17 to be answerable
with anything other than "wait an hour". It is small — the backend already keys
records by `tenant\x00conversation\x00token`, so it is a prefix delete — and it
belongs in the Community Edition, not behind a paywall: a customer who cannot
delete data cannot use the product in a regulated context.

**Deletion is audited** as a count of records removed, with tenant and
conversation ids and no values.

### 4 · Restart semantics

The default in-memory backend loses every mapping on restart. This is stated as a
property, not hidden:

- **Tokens minted before a restart do not restore afterwards.** They are left
  verbatim, counted as `refused_unknown`, and surfaced in `X-Tokens-Refused`.
- **This is indistinguishable, in the audit trail, from an attacker probing
  tokens.** Both increment the same counter. An operator alerting on
  `tokens_refused` will get a spike on every deploy.

That ambiguity is a defect in the observability, not in the security model. The
fix is a distinct refusal reason: `refused_vault_miss` already exists internally
as `refused_unknown`, and the audit event must carry the breakdown by reason
rather than a single total, so "vault is empty after a restart" and "someone is
guessing tokens" are separable. Required before any alert is written against this
signal.

An operator who needs mappings to survive restart configures the file backend
(plan Phase 1) and accepts that personal data is now at rest on disk, encrypted
under `SAG_VAULT_KEY`, with all the key-management consequences in
[ADR-0012](0012-vault-record-envelope-and-key-rotation.md).

### 5 · What is never persisted

Unchanged from ADR-0010, restated because this is the document people read:

- Raw prompts: never, anywhere.
- Response text: never.
- Provenance sets: never — they are per-request by construction, and persisting
  one would defeat [SI-03](../security-invariants.md#si-03--current-request-restoration-only).
- Audit events: yes, and they structurally cannot contain content.

## Alternatives considered

| Option | Rejected because |
|---|---|
| No TTL; mappings live until deleted | Turns the vault into a permanent index of exactly the data customers gave us to protect. The opposite of the product |
| TTL extended on read | A conversation someone keeps open retains personal data indefinitely, and the retention period becomes unpredictable — impossible to state in a DPA |
| Sweep as the only expiry mechanism | A failed sweeper silently extends PII lifetime, and nothing surfaces it |
| Persist mappings by default | Makes the default deployment one with personal data at rest, which every self-hosted evaluation would then have to reason about |

## Consequences

**Privacy.** Retention becomes a number that can be written into a DPA and
demonstrated. Erasure becomes answerable in seconds rather than an hour.

**Operational.** Deploys cause a visible `tokens_refused` spike until the
refusal-reason breakdown lands. Note it in the deployment runbook now.

**Delivery.** ~1.5 engineer-days: sweep task, conversation delete endpoint,
refusal-reason breakdown in the audit event, and the restart test.

**Reversal cost.** Low throughout.
