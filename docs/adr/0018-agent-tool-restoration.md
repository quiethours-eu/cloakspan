# ADR-0018: Restoring tokens into registered agent tool sinks

**Status:** experimental implementation decision · 2026-10-08 ·
`REQUIRES_SECURITY_REVIEW`. **Owner:** Technical lead (implementation), Security
owner (review). No invariant waiver or production qualification is granted.

## Context

A provider-controlled argument can become code or a filesystem action. A valid
current-request token proves origin, not authority to place that value in every
argument. Chat Completions prose restoration is insufficient for this boundary.

## Decision

Use an explicit registry of function tool names, argument formats and eligible
sinks. `read_file`, `write_file`, `edit_file`, `apply_patch`, and `shell` plus
registered client aliases, local `Grep`/`Glob`, typed `TodoWrite` and restricted
`write_stdin` are the experimental formats. Inspect incoming tool
descriptions, schemas, replayed arguments and results before any provider call.
Sensitive structural schema strings that cannot preserve meaning are refused.

Bind emitted calls to the current request's declared tool names and native
function/custom type, then enforce `tool_choice`, `parallel_tool_calls`, native
`disable_parallel_tool_use`, and `max_tool_calls` against the entire batch,
including an empty batch. Declaring a registered name alone does not authorize
different arguments or a different native tool type.

Executable argument schemas use a bounded assertion subset: `type`,
`properties`, `required`, `additionalProperties`, `enum`, `const`, simple
string/numeric/object/array bounds, and `allOf`/`anyOf`/`oneOf`. Refuse references,
patterns, `format`, conditionals/dependencies, unevaluated assertions,
`multipleOf` and unknown assertions before egress. Registered argument formats
follow registered typed shapes; unregistered nested shapes or properties are refused.
Inspect annotations as content without treating them as assertions. Validate
restored arguments against the declared schema as well as the registry. The
structured-output schema visitor has a separate, broader contract.

Registered nested shapes cover todo items and Codex prefix/permission controls;
they do not authorize arbitrary objects. The exact supported Draft 2020-12
schema URI and pinned apply_patch grammar are constrained declarations, not
permission to follow references or accept arbitrary grammars. A `Read.pages`
declaration or execution-environment identifier does not permit a PDF/alternate
environment call before the missing inspection/workspace contract exists.

Inspect arbitrary JSON content numbers in their decimal representation as
structural locations. If detection finds a sensitive numeric value, reject it
rather than changing its JSON type or forwarding it uninspected.

Only registered argument values may be restored. Tool names, call IDs, JSON
keys, model identifiers and control fields never undergo restoration. Reparse
and validate JSON, registered path fields, patches and the defined shell subset
after restoration. Do not use unrestricted command string replacement. Refuse
network/external payload sinks by default and reject unsupported formats with
placeholders. Tokens and malformed placeholder lookalikes must either resolve
under the current request's provenance and destination policy or fail the call.

Local search has grammar-specific restoration: regex token replacements are
escaped, fixed-string replacements preserve exact text, and glob token values
cannot add operators. Shell `rg`/`grep` and `find` accept only defined flags;
preprocessors, arbitrary type additions, `-exec` and `-delete` are refused.
Codex permission hints cannot restore placeholders into controls or grant network
access; filesystem permissions stay within the workspace and an approval prefix
must match the validated argv. The client retains the requested approval flow.
`write_stdin` accepts polling or a literal interrupt only. Bash background
execution remains subject to its validated command; sandbox-disable true fails.

Validate every executable call in the completed response before exposing any
call. Failure of one call fails the whole batch; do not emit partial executable
arguments, half-restored strings or successful completion after refusal.

For agent requests declaring tools, reject distinct originals that share an
entity type and canonical token identity within that request. Choosing one of
those spellings could break an exact edit or path. Across concurrent requests,
restoration first requires an authentic, scoped, unexpired vault record matching
the token's canonical identity, then selects the original bound to this request's
provenance. A concurrent vault refresh must not select another request's spelling.
Chat Completions retains its existing behavior for variants within one request.

Workspace paths must remain under `SAG_AGENT_WORKSPACE_ROOT`. Gateway checks
do not replace execution-time symlink checks, the client's sandbox, approvals or
egress policy. Cloakspan never executes or auto-approves provider tools. Tool
restoration cannot prevent a separate MCP server or an executed program from
transmitting data outside the configured inference path.

## Consequences and release evidence

SI-01/SI-02 inspection and SI-03 request provenance remain requirements; no
session-wide or vault-wide restoration allowlist is introduced. SI-17 protects
non-target text and serialization structure. Tests must exercise paths, edit
matching, patch syntax, shell quoting/operators, disallowed sinks, unresolved
tokens, cross-session replay and failure of a later call in a batch.

The restricted registry is an experimental subset. Normal read, edit, patch and
test commands of the actual clients are release gates. Add formats only through
explicit grammar/sink rules and adversarial tests. Real client versions remain
unqualified until complete workflows pass the versioned matrix.
