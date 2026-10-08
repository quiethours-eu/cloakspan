# Connect Claude Code or Codex CLI

Use these macOS/Linux shell steps with an existing configured Cloakspan gateway.
The pinned profiles are Claude Code **2.1.293** and Codex **0.161.0**.

The gateway operator must enable `SAG_ENABLE_MESSAGES` for Claude or
`SAG_ENABLE_RESPONSES` for Codex, configure the matching upstream/model and allow
your gateway key to use it. `SAG_AGENT_WORKSPACE_ROOT` must match the repository
paths the client uses; container deployments need the same absolute workspace
mount. Configure `SAG_MAX_INPUT_CHARS=1000000` at the gateway to fit CLI tool
definitions and history. Upstream OpenAI/Anthropic keys stay at the gateway.

Set your gateway URL, its separately issued gateway key, and two local paths:

```bash
export CLOAKSPAN_GATEWAY_URL='http://127.0.0.1:8080'
export CLOAKSPAN_GATEWAY_KEY='sgw_live_your_gateway_key'
export CLOAKSPAN_CHECKOUT='/absolute/path/to/cloakspan'
export CLOAKSPAN_WORKSPACE='/absolute/path/to/your/repository'
```

Use an HTTPS gateway URL for a remote deployment. Claude takes the gateway
**origin**, such as `https://gateway.example.com`; Codex takes that URL **plus
`/v1`**. The steps below set the correct form for each client.

## Claude Code

Install the pinned CLI, load the restricted profile and send a first read request:

```bash
npm install -g @anthropic-ai/claude-code@2.1.293
source "$CLOAKSPAN_CHECKOUT/deployment/clients/claude-code-env.example.sh"
export ANTHROPIC_BASE_URL="${CLOAKSPAN_GATEWAY_URL%/}"
cd "$CLOAKSPAN_WORKSPACE"
claude --bare -p --model claude-sonnet-4-6 --effort low \
  --tools 'Bash,Read,Write,Edit,Glob,Grep' --disallowedTools 'mcp__*' \
  'Read README.md and explain how to run this repository’s tests.'
```

The template puts your gateway key in `ANTHROPIC_API_KEY`, disables thinking
parameters and nonessential traffic, and selects native Messages. Keep the
client's permission controls. Print mode cannot prompt for approval; use explicit
`--allowedTools` rules for operations you authorize, keeping command permissions
narrow. The recorded qualification uses `--bare -p`.

## Codex

Install the pinned CLI and create a separate configuration directory so your
existing Codex configuration stays intact:

```bash
npm install -g @openai/codex@0.161.0
export CLOAKSPAN_CODEX_DIR="$HOME/.codex-cloakspan"
python3 - <<'PY'
import json
import os
import shutil
from pathlib import Path

source = Path(os.environ['CLOAKSPAN_CHECKOUT']) / 'deployment/clients'
target = Path(os.environ['CLOAKSPAN_CODEX_DIR']).resolve()
catalog = target / 'codex-models.json'
target.mkdir(parents=True, exist_ok=True)
if (target / 'config.toml').exists() or catalog.exists():
    raise SystemExit('Existing profile: reuse it or choose another CLOAKSPAN_CODEX_DIR.')
shutil.copyfile(source / 'codex-models.example.json', catalog)
config = (source / 'codex-config.example.toml').read_text()
config = config.replace(
    '"REPLACE_WITH_ABSOLUTE_PATH/codex-models.example.json"',
    json.dumps(str(catalog), ensure_ascii=False),
)
config = config.replace(
    '"http://127.0.0.1:8080/v1"',
    json.dumps(os.environ['CLOAKSPAN_GATEWAY_URL'].rstrip('/') + '/v1', ensure_ascii=False),
)
(target / 'config.toml').write_text(config)
PY
```

If this profile already exists, reuse it or choose another directory; the setup
refuses to overwrite it. Send your first request with the isolated profile:

```bash
env CODEX_HOME="$CLOAKSPAN_CODEX_DIR" codex exec \
  --sandbox workspace-write --cd "$CLOAKSPAN_WORKSPACE" \
  'Read README.md and explain how to run this repository’s tests.'
```

The profile uses Responses, the local GPT-5.1 catalog and effort `none`. Keep
this persistent directory for later sessions. `exec` runs within its workspace
sandbox and denies actions that need approval escalation.

If authentication fails, check the gateway key and model permission. If tools
fail workspace checks, compare the client's absolute repository path with the
gateway mount and `SAG_AGENT_WORKSPACE_ROOT`. See the
[operator settings](operations.md#experimental-agent-deployment) and
[full client examples](../deployment/clients/README.md).

Both pinned CLIs passed synthetic read/edit/test/follow-up, automatic inspectable
compaction and resume. Live providers, desktop clients and production capacity
need separate qualification; opaque continuation stays disabled. The
[compatibility matrix](agent-compatibility.md) records the evidence and limits.
