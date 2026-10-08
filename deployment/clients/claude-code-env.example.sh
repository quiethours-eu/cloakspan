# Public native Messages profile pinned to Claude Code CLI 2.1.293.
# Supply CLOAKSPAN_GATEWAY_KEY through your secret manager, never an upstream key.
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080
export ANTHROPIC_API_KEY="${CLOAKSPAN_GATEWAY_KEY:?Set a revocable gateway key}"
export ANTHROPIC_MODEL=claude-sonnet-4-6
export ANTHROPIC_DEFAULT_HAIKU_MODEL=claude-sonnet-4-6
export ANTHROPIC_DEFAULT_SONNET_MODEL=claude-sonnet-4-6
export ANTHROPIC_DEFAULT_OPUS_MODEL=claude-sonnet-4-6
export CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1
export CLAUDE_CODE_DISABLE_THINKING=1
export MAX_THINKING_TOKENS=0
export DISABLE_INTERLEAVED_THINKING=1
export ENABLE_TOOL_SEARCH=false
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
export CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL=1
export CLAUDE_CODE_DISABLE_TERMINAL_TITLE=1
export CLAUDE_CODE_DISABLE_NONSTREAMING_FALLBACK=1
export ENABLE_CLAUDEAI_MCP_SERVERS=false
export DISABLE_AUTOUPDATER=1
export API_TIMEOUT_MS=660000
unset ANTHROPIC_AUTH_TOKEN ANTHROPIC_BETAS
unset CLAUDE_CODE_USE_BEDROCK CLAUDE_CODE_USE_VERTEX CLAUDE_CODE_USE_FOUNDRY
# --bare requires API-key authentication. Retain client approval/sandbox controls.
# claude --bare -p --tools 'Bash,Read,Write,Edit,Glob,Grep' --disallowedTools 'mcp__*'
# Opaque output remains refused even when the thinking parameter is omitted.
# Desktop third-party inference configuration is separate from this CLI profile.
