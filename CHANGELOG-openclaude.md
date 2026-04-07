# Changelog: Replace Claude Agent SDK with OpenClaude

## Summary

Replaced `@anthropic-ai/claude-agent-sdk` and `@anthropic-ai/claude-code` with [openclaude](https://gitlawb.com/z6MkqDnb7Siv3Cwj7pGJq4T5EsUisECqR8KpnDLwcaZq5TPr/openclaude) — an open-source Claude Code fork with an OpenAI-compatible provider shim. The NanoClaw agent container can now run **any OpenAI-compatible model** (GPT-4o, Ollama, DeepSeek, Groq, etc.) instead of being locked to Anthropic's API.

## New Files

| File | Description |
|------|-------------|
| `container/agent-runner/src/openclaude-query.ts` | Drop-in `query()` replacement — spawns openclaude CLI as a subprocess and yields SDK-compatible NDJSON messages |
| `container/vendor/openclaude-cli.mjs` | Vendored openclaude CLI (19.5 MB, built from source with `bun run build`) |
| `container/vendor/package.json` | External dependencies for the vendored CLI (OpenTelemetry, AWS SDK, Azure, Google auth) |

## Modified Files

### `container/Dockerfile`
- Removed `npm install -g @anthropic-ai/claude-code`
- Added `COPY vendor/` step + `npm install` for openclaude's external deps
- Added `ENV` declarations for OpenAI provider config: `CLAUDE_CODE_USE_OPENAI`, `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL`

### `container/agent-runner/package.json`
- Removed `@anthropic-ai/claude-agent-sdk` dependency

### `container/agent-runner/src/index.ts`
- Replaced `import { query, HookCallback, PreCompactHookInput } from '@anthropic-ai/claude-agent-sdk'` with `import { query } from './openclaude-query.js'`
- Removed `createPreCompactHook()` function (~40 lines) — no CLI equivalent for hooks
- Removed `hooks` option from `query()` call
- Added type cast for `message.session_id` (shim returns `Record<string, unknown>`)

### `container/agent-runner/src/ipc-mcp-stdio.ts`
- Added consecutive `send_message` rate limiter to prevent model looping on status messages
- Updated tool description to discourage "please wait" messages

### `groups/wazuh_soc/CLAUDE.md`
- Added critical instructions for tool-first response pattern
- Replaced curl-based MCP access with native MCP tool calls (no auth needed)

## Architecture

```
Before:
  agent-runner → @anthropic-ai/claude-agent-sdk (query()) → bundled cli.js → Anthropic API

After:
  agent-runner → openclaude-query.ts (query()) → spawns vendor/openclaude-cli.mjs → OpenAI-compatible API
```

The shim builds CLI flags from the same options the Agent SDK accepted:
- `--print --output-format stream-json --verbose` for NDJSON streaming
- `--resume <sessionId>` / `--resume-session-at <uuid>` for session continuation
- `--mcp-config '{"mcpServers":{...}}'` for MCP server injection
- `--dangerously-skip-permissions` for sandbox bypass
- `--append-system-prompt <text>` for global CLAUDE.md injection
- Working directory set via `spawn()` `cwd` option (no `--cwd` flag in openclaude)
- `--` separator before positional prompt (avoids variadic `--mcp-config` consuming it)

## Dropped Features (Acceptable Tradeoffs)

| Feature | Reason |
|---------|--------|
| `PreCompact` hook (transcript archiving) | No CLI equivalent |
| `allowedTools` whitelist | Rely on `.claude/settings.json` in workspace |
| `settingSources` | openclaude uses its own settings discovery |
| Mid-query IPC message injection | Simplified — outer IPC loop handles multi-turn |
| OTel LLM-level spans | Lost because openclaude runs as subprocess |

## Runtime Configuration

Set these environment variables at container runtime (via OneCLI, `.env`, or `docker run -e`):

```bash
CLAUDE_CODE_USE_OPENAI=1        # Required — enables OpenAI provider in openclaude
OPENAI_API_KEY=sk-...           # Required (except for local endpoints)
OPENAI_BASE_URL=https://...     # Defaults to https://api.openai.com/v1
OPENAI_MODEL=gpt-4o             # Model to use
```

## Updating OpenClaude

```bash
cd ~/Documents/amine759/openclaude
git pull
bun install && bun run build
cp dist/cli.mjs ~/Documents/amine759/nanoclaw/container/vendor/openclaude-cli.mjs
cd ~/Documents/amine759/nanoclaw && ./container/build.sh
```
