# Public coding client profiles

These experimental examples target **Codex CLI 0.161.0** and **Claude Code CLI
2.1.293**, using their public documentation and pinned public contracts. Private
client versions or captures are not needed to implement these profiles. The
[support matrix](../../docs/agent-compatibility.md) distinguishes documented
compatibility, actual CLI runs against synthetic providers, and production
qualification. Desktop configurations are separate public surfaces.

Copy `codex-config.example.toml` into Codex's documented configuration location
and replace its catalog path with the absolute path to `codex-models.example.json`.
The original minimal catalog follows the pinned public
[ModelInfo schema](https://github.com/openai/codex/blob/979011409de0a60b52f179721948e65531d26144/codex-rs/protocol/src/openai_models.rs#L405),
using GPT-5.1 with `reasoning_effort=none`, which
[OpenAI documents for tool workflows without reasoning](https://openai.com/index/gpt-5-1-for-developers/).
It selects text, unified execution and custom freeform patches; its 16,384-token
context cap, 12,000-token local compaction threshold and 10,000-byte tool-output
truncation are conservative client controls, not measured capacity claims.
The custom provider name avoids the pinned client's OpenAI/Azure remote
compaction path. Ordinary local summary requests stay inspectable; the opaque
compact endpoint remains disabled.

`env_key` references a revocable gateway key, while provider keys stay at the
gateway. HTTP/SSE, disabled WebSockets, disabled summaries, disabled web search
and client retry controls follow the
[official configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference).
Use loopback locally or an approved private HTTPS gateway. A model/upstream that
returns opaque reasoning still fails closed; changing its catalog metadata does
not make that content inspectable.

Source `claude-code-env.example.sh` in the shell launching the CLI. It selects
native Messages, with the gateway key in `ANTHROPIC_API_KEY` for the public bare
CLI profile, and pins the main/small-model aliases to `claude-sonnet-4-6`.
Launch with the restricted tools:

```sh
claude --bare -p --tools 'Bash,Read,Write,Edit,Glob,Grep' --disallowedTools 'mcp__*' \
  'Read the synthetic repository and describe its tests.'
```

Retain the client's approval and sandbox settings. The environment template
disables experimental capabilities, thinking request parameters, interleaved
thinking, deferred MCP tool search and nonessential traffic using
[official environment controls](https://code.claude.com/docs/en/env-vars).
Beta-disable retains effort and some headers, as the
[protocol guide](https://code.claude.com/docs/en/llm-gateway-protocol) explains;
only explicit supported values may reach the provider. Omitting thinking does
not guarantee that every model omits opaque output. Subscription/OAuth forwarding
is unsupported. Claude Desktop uses its third-party inference configuration,
described in the [connection guide](https://code.claude.com/docs/en/llm-gateway-connect),
and does not acquire gateway routing from this CLI shell template.

For a desktop connection, apply the public surface-specific configuration below.
These settings provide a starting configuration; the CLI tests do not qualify
desktop tool declarations, automatic compaction or resume.

| Surface | Public configuration example |
|---|---|
| Codex macOS app | Merge the provider/catalog profile into `~/.codex/config.toml`, deliver the gateway key to the app process, then restart |
| Codex Windows app | Use `%USERPROFILE%\\.codex\\config.toml`, a Windows absolute catalog path and a gateway key available to the app process |
| Claude Desktop on 3P | Set inferenceProvider=gateway, inferenceGatewayBaseUrl to the gateway origin, inferenceGatewayAuthScheme=x-api-key and inferenceGatewayApiKey to an independently revocable gateway credential through protected desktop configuration |

The [Codex connection guide](https://learn.chatgpt.com/docs/enterprise/connect-to-a-gateway)
defines desktop paths and credential delivery. Claude's
[desktop gateway guide](https://claude.com/docs/third-party/claude-desktop/gateway)
defines its separate third-party inference keys; use its local configuration form
or managed-device deployment. Keep credentials out of source files. Gateway OIDC
validation is not implemented, so select gateway-key authentication for this profile.

Enable the matching gateway capability and set its real upstream settings:

```sh
export SAG_ENABLE_RESPONSES=true
export SAG_EXTERNAL_BASE_URL=https://api.openai.com/v1
# Supply SAG_EXTERNAL_API_KEY from operator secrets.
export SAG_EXTERNAL_MODEL=gpt-5.1
export SAG_ENABLE_MESSAGES=true
export SAG_MESSAGES_BASE_URL=https://api.anthropic.com/v1
# Supply SAG_MESSAGES_API_KEY from operator secrets.
export SAG_MESSAGES_MODEL=claude-sonnet-4-6
export SAG_AGENT_WORKSPACE_ROOT=/srv/synthetic-agent-workspace
export SAG_MAX_INPUT_CHARS=1000000
export SAG_MAX_REQUEST_BYTES=4194304
```

The public CLI tool definitions plus long replay can exceed the default 65,536
inspected-character cap. This profile explicitly raises it to one million and
keeps the body bounded at 4 MiB. It does not establish that the reference node can
serve those sizes at the proposed latency or concurrency budget. Measure complete
parent/child/native memory and detector time before deploying that workload.
The inspected-character bound produces a native 400 context_length_exceeded
error with a safe compaction hint. Detector/privacy failures retain their own
errors and cannot be treated as permission to bypass inspection.

Keep stable `SAG_TOKEN_KEY`/vault keys and gateway authentication configuration.
The workspace must match the client's execution workspace, including any mount
translation. Local routing requires a private endpoint implementing the selected
native protocol and tools; there is no external fallback.

The optional network preflight sends synthetic model requests (which may incur
provider cost) and creates/deletes a disposable file under the specified workspace:

```sh
python scripts/agent_preflight.py --network --protocol responses \
  --gateway-url http://127.0.0.1:8080 --model YOUR_CONFIGURED_MODEL \
  --workspace /srv/synthetic-agent-workspace
python scripts/agent_preflight.py --network --protocol messages \
  --gateway-url http://127.0.0.1:8080 --model YOUR_CONFIGURED_MESSAGES_MODEL \
  --workspace /srv/synthetic-agent-workspace
```

Set `CLOAKSPAN_GATEWAY_KEY` using your secret manager. Preflight validates one
complete native stream and a read-only tool round trip, not edits, test commands,
real client behavior, compaction, or resume. Offline invocation makes no request.
Do not redirect a blocked client around the gateway. Disable the capability to
roll back and recover with inspectable history and compatible keys.

For actual pinned CLI regression checks against a local synthetic provider, use
the installed binary paths and a new output directory:

```sh
python scripts/public_client_check.py --mode gateway --workflow --compact --timeout 120 \
  --codex-binary /absolute/path/to/codex --claude-binary /absolute/path/to/claude \
  --output-dir /tmp/cloakspan-public-client-check
```

The harness uses isolated client configuration, a synthetic gateway key and
disposable source/test files. It records actual native requests and verifies
file changes, test execution, resumed follow-up and upstream canary absence.
With --compact it also reads 1,000 synthetic note lines, triggers automatic
inspectable summaries and verifies native compaction evidence, summary replay
and post-compaction resume. The harness lowers public client thresholds and
uses request-length token estimates, as recorded in the support matrix. This
tests actual CLI behavior; it does not qualify live tokenization, caching,
capacity or desktop deployments.
