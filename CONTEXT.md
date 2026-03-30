# NanoClaw SOC Autopilot — Session Context

> Handoff document for the Claude session that ran out of context (~356 messages, 3.8MB).
> Written 2026-03-30. Open a fresh `claude` session from this directory.

---

## What This Is

A Wazuh SOC autopilot rewritten to use NanoClaw instead of OpenClaw.

The previous OpenClaw version ran every alert through a 7-agent webhook chain automatically. This rewrite:
- Uses **one NanoClaw container agent** instead of 7 chained agents
- Uses an **analyst-in-the-loop model** — the analyst decides what to investigate, not an automatic trigger
- Everything is fully mocked for local dev (no real Wazuh infrastructure required yet)

This code lives in `~/Documents/amine759/nanoclaw/` (this repo).
The autopilot parent repo lives at `~/Documents/amine759/naoris/AI-PoCs/threat-detection/wazuh-openclaw-autpilot/` (on branch `nano-claw`).

---

## Architecture

```
Analyst
  │  POST http://127.0.0.1:3001/chat  { jid: "local:wazuh_soc", text: "investigate 203.0.113.44" }
  ▼
NanoClaw local HTTP channel  (src/channels/local.ts, port 3001)
  │  routes to wazuh_soc group
  ▼
NanoClaw container runner  (spawns Docker container)
  │  mounts groups/wazuh_soc/ as /workspace/group
  │  CLAUDE.md is the agent's brain
  ▼
Agent (Claude Code inside container)
  │  calls MCP tools via curl
  ▼
Mock Wazuh MCP Server  (Wazuh-Openclaw-Autopilot/mock-mcp/, port 3000)
  │  48 tools, 3 attack scenarios, 58 alerts, JWT auth
  ▼
Agent response → SSE stream → analyst
  GET http://127.0.0.1:3001/chat/stream?jid=local:wazuh_soc
```

---

## How to Run

### Prerequisites check

```bash
# NanoClaw service should be running (enabled on boot via systemd)
systemctl --user status nanoclaw

# If it's not running, start it:
systemctl --user start nanoclaw

# Verify the local HTTP channel is up
curl -s http://127.0.0.1:3001/health
```

### Step 1 — Start the mock Wazuh MCP server

Open a dedicated terminal and leave it running. You'll see live tool call logs here.

```bash
cd ~/Documents/amine759/naoris/AI-PoCs/threat-detection/wazuh-openclaw-autpilot/Wazuh-Openclaw-Autopilot/mock-mcp
node index.js
# Expected output:
#   Mock Wazuh MCP Server listening on :3000
#   API Key: wazuh_test123456789012345678901234567890123
#   Tools: 48
#   Alerts loaded: 58 (51 brute force + 4 malware + 3 noise)
```

### Step 2 — Open the agent response stream

Open a second terminal and leave it running. Agent responses appear here as SSE events.

```bash
curl -N "http://127.0.0.1:3001/chat/stream?jid=local:wazuh_soc"
# Expected: data: {"type":"connected","jid":"local:wazuh_soc"}
```

### Step 3 — Send messages as the analyst

In a third terminal, send investigation requests:

```bash
# Alert summary — good starting point
curl -s -X POST http://127.0.0.1:3001/chat \
  -H 'Content-Type: application/json' \
  -d '{"jid":"local:wazuh_soc","text":"give me a summary of high severity alerts from the last 24 hours"}'

# Full investigation — scenario 1 (SSH brute force → lateral movement)
curl -s -X POST http://127.0.0.1:3001/chat \
  -H 'Content-Type: application/json' \
  -d '{"jid":"local:wazuh_soc","text":"investigate the 203.0.113.44 attack chain"}'

# Full investigation — scenario 2 (malware on prod-app-01)
curl -s -X POST http://127.0.0.1:3001/chat \
  -H 'Content-Type: application/json' \
  -d '{"jid":"local:wazuh_soc","text":"investigate the malware on prod-app-01"}'
```

The POST returns immediately with `{"ok":true,"id":"..."}`. Watch terminal 2 for the agent's response (takes 20–60s while the agent runs tool calls).

### Useful diagnostics

```bash
# Watch agent container logs live (run while agent is processing)
docker logs -f $(docker ps -q --filter name=nanoclaw-wazuh) 2>&1

# Check if agent container is currently running
docker ps --filter name=nanoclaw-wazuh

# NanoClaw service logs
journalctl --user -u nanoclaw -f

# Rebuild the agent container image (needed after changing instrumentation.ts or index.ts)
cd ~/Documents/amine759/nanoclaw && bash container/build.sh
```

---

## Key Files

| File | Purpose |
|------|---------|
| `groups/wazuh_soc/CLAUDE.md` | Agent brain — SOC knowledge, pipeline, policy rules, approval workflow |
| `src/channels/local.ts` | Local HTTP channel (added — no Telegram/Discord needed) |
| `container/agent-runner/src/instrumentation.ts` | Arize Phoenix OTel tracing (new file, untracked) |
| `container/agent-runner/src/index.ts` | Agent runner — modified to add manual OTel spans |
| `container/Dockerfile` | Uses `node --import instrumentation.js` for ESM-safe OTel loading |
| `data/sessions/wazuh_soc/.claude/settings.json` | Per-group env vars: model, Phoenix config, MCP URL/key |
| `scripts/soc-chat.sh` | Analyst helper CLI (untracked) |

**In the autopilot repo:**
| File | Purpose |
|------|---------|
| `Wazuh-Openclaw-Autopilot/mock-mcp/index.js` | Mock MCP server — 48 tools, JWT auth |
| `Wazuh-Openclaw-Autopilot/mock-mcp/scenarios.js` | 3 attack scenarios + 58 realistic alerts |

---

## Mock MCP Scenarios

All data is in `Wazuh-Openclaw-Autopilot/mock-mcp/scenarios.js`:

1. **SSH Brute Force → Lateral Movement** — 47 failed SSH logins from `203.0.113.44` → 1 successful login → payload exec → lateral move to `prod-db-01` → `pg_dump` exfiltration
2. **Malware on prod-app-01** — Suspicious binary download, persistence via cron, C2 beaconing
3. **Low-noise routine alerts** — Baseline noise on `dev-staging-01` (true negatives)

Agents: `prod-web-01`, `prod-db-01`, `dev-staging-01`, `prod-app-01`, `dc-win-01`
Mock MCP key: `wazuh_test123456789012345678901234567890123`

---

## Phoenix Tracing (Arize)

**Status: Code is complete and correct — API key was returning 401 at end of last session.**

The instrumentation uses `@arizeai/openinference-instrumentation-anthropic` which patches `Anthropic.prototype.messages` (works in Node 22 ESM, unlike the Claude Agent SDK instrumentation which fails on read-only ESM exports).

**What you get in Phoenix:**
- One LLM span per `messages.create` call with full system prompt + conversation history
- Tool use spans with input/output
- Root `agent.session` span with the analyst's prompt and final response

**Config in `data/sessions/wazuh_soc/.claude/settings.json`:**
```json
{
  "env": {
    "PHOENIX_COLLECTOR_ENDPOINT": "https://app.phoenix.arize.com/s/salah",
    "PHOENIX_API_KEY": "<your fresh API key here>",
    "PHOENIX_PROJECT_NAME": "wazuh-soc"
  }
}
```

**To fix the 401:** Generate a new API key at `https://app.phoenix.arize.com` → Profile → API Keys. No rebuild needed — just update `settings.json` and restart the container.

The OTLP endpoint is built as `${PHOENIX_COLLECTOR_ENDPOINT}/v1/traces`. The auth header is `Authorization: Bearer <key>`. This was confirmed working via curl (the header format fix from `api_key:` to `Authorization: Bearer` was the last fix made).

---

## Uncommitted Changes in This Repo

These are modified but not committed (run `git status` to confirm):

| File | Status | What changed |
|------|--------|-------------|
| `container/Dockerfile` | modified | Entrypoint uses `--import instrumentation.js`; added `--fix-missing` to apt-get |
| `container/agent-runner/src/index.ts` | modified | Added OTel `agent.session` root span + tool call spans |
| `container/agent-runner/package.json` | modified | Added OTel packages + `@anthropic-ai/sdk` + `@arizeai/*` |
| `src/channels/index.ts` | modified | Registered `local` channel |
| `container/agent-runner/src/instrumentation.ts` | **new (untracked)** | Full OTel/Phoenix instrumentation |
| `src/channels/local.ts` | **new (untracked)** | Local HTTP channel |
| `scripts/soc-chat.sh` | **new (untracked)** | Analyst CLI helper |

Also new (not yet committed):
- `groups/wazuh_soc/` — entire directory (CLAUDE.md, cases/, reports/, logs/)
- `data/sessions/wazuh_soc/` — NanoClaw runtime data for the group

---

## Architectural Decisions Made

1. **One agent, not seven** — Replaced the 7-agent OpenClaw webhook chain with a single agent that has all SOC knowledge in its CLAUDE.md. Simpler, no stalled pipeline recovery needed.

2. **Analyst-in-the-loop** — Agent doesn't process every alert automatically. The analyst reviews and decides what to investigate. Rationale: LLM inference on every alert is expensive and most alerts are noise; the analyst's judgment about what's worth investigating is the right filter.

3. **Local HTTP channel** — NanoClaw normally requires Discord/Telegram/etc. Added a minimal local HTTP channel so no external messaging platform is needed for this SOC use case. The analyst interacts via curl or any HTTP client.

4. **Mock-first** — Full mock MCP server (48 tools, same JSON-RPC 2.0 API, same tool names as the real Wazuh MCP). Real infrastructure can be swapped in later with zero agent code changes.

5. **ESM-safe instrumentation** — Node 22 makes ESM module namespace bindings read-only. `AnthropicInstrumentation.manuallyInstrument(Anthropic)` patches the class prototype (mutable), not the module export binding — this is why it works while `claude-agent-sdk` instrumentation fails.

---

## What Still Needs Doing

- [ ] Fix Phoenix API key (401 issue — generate a fresh key)
- [ ] Verify Phoenix traces appear in `wazuh-soc` project after key fix
- [ ] Commit all uncommitted changes in nanoclaw repo
- [ ] Update parent autopilot repo (`nano-claw` branch) with the mock-mcp additions
- [ ] Eventually: swap mock MCP for real Wazuh MCP server (real alerts, real active response)
