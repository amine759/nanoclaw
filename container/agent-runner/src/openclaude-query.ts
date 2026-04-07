/**
 * openclaude-query.ts
 *
 * Drop-in replacement for `query()` from `@anthropic-ai/claude-agent-sdk`.
 * Spawns openclaude (vendored CLI) as a subprocess and yields SDK-compatible
 * NDJSON messages from its stdout.
 *
 * Supported options (from Agent SDK query options):
 *   cwd, resume (sessionId), resumeSessionAt, systemPrompt,
 *   permissionMode (bypassPermissions), mcpServers, env
 *
 * Not supported (dropped):
 *   allowedTools, settingSources, hooks, additionalDirectories
 */

import { spawn } from 'child_process';
import { createInterface } from 'readline';
// Vendored openclaude CLI — copied into the image at /app/vendor/ by the Dockerfile
const OPENCLAUDE_CLI = '/app/vendor/openclaude-cli.mjs';

interface McpServerConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

interface SystemPromptConfig {
  type?: string;
  preset?: string;
  append?: string;
}

interface QueryOptions {
  cwd?: string;
  resume?: string;
  resumeSessionAt?: string;
  systemPrompt?: SystemPromptConfig | string;
  permissionMode?: string;
  allowDangerouslySkipPermissions?: boolean;
  mcpServers?: Record<string, McpServerConfig>;
  env?: Record<string, string | undefined>;
  additionalDirectories?: string[];
  [key: string]: unknown;
}

interface SDKUserMessage {
  type: 'user';
  message: { role: 'user'; content: string };
  parent_tool_use_id: null;
  session_id: string;
}

type PromptInput = string | AsyncIterable<SDKUserMessage>;

/**
 * Extract the initial prompt text from either a plain string or an
 * AsyncIterable<SDKUserMessage> (NanoClaw's MessageStream).
 * Only the first message is consumed — follow-up messages are handled
 * by the outer IPC loop in index.ts which starts a new runQuery() call.
 */
async function extractPrompt(prompt: PromptInput): Promise<string> {
  if (typeof prompt === 'string') return prompt;
  for await (const msg of prompt) {
    const content = msg.message?.content;
    if (typeof content === 'string') return content;
  }
  return '';
}

/**
 * Serialize the Agent SDK mcpServers map into the JSON array format
 * that openclaude's --mcp-config flag expects.
 */
function buildMcpConfig(mcpServers: Record<string, McpServerConfig>): string {
  const servers: Record<string, { command: string; args: string[]; env: Record<string, string> }> = {};
  for (const [name, server] of Object.entries(mcpServers)) {
    servers[name] = {
      command: server.command,
      args: server.args ?? [],
      env: server.env ?? {},
    };
  }
  return JSON.stringify({ mcpServers: servers });
}

/**
 * query() — yields NDJSON messages from openclaude, matching the message
 * shapes that NanoClaw's agent-runner index.ts already consumes:
 *   { type: 'system', subtype: 'init', session_id }
 *   { type: 'assistant', uuid, message: { content: [...] } }
 *   { type: 'result', subtype, result }
 *   { type: 'user', message: { content: [...] } }
 */
export async function* query({
  prompt,
  options = {},
}: {
  prompt: PromptInput;
  options?: QueryOptions;
}): AsyncGenerator<Record<string, unknown>> {
  const initialPrompt = await extractPrompt(prompt);

  const args: string[] = [
    '--print',
    '--output-format', 'stream-json',
    '--verbose',
  ];

  if (options.resume) {
    args.push('--resume', options.resume);
  }

  if (options.resumeSessionAt) {
    args.push('--resume-session-at', options.resumeSessionAt);
  }

  if (
    options.permissionMode === 'bypassPermissions' ||
    options.allowDangerouslySkipPermissions
  ) {
    args.push('--dangerously-skip-permissions');
  }

  if (options.mcpServers && Object.keys(options.mcpServers).length > 0) {
    args.push('--mcp-config', buildMcpConfig(options.mcpServers));
  }

  if (options.systemPrompt) {
    const appendText =
      typeof options.systemPrompt === 'string'
        ? options.systemPrompt
        : options.systemPrompt.append;
    if (appendText) {
      args.push('--append-system-prompt', appendText);
    }
  }

  // Separate options from the positional prompt with --
  args.push('--', initialPrompt);

  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(options.env ?? process.env)) {
    if (v !== undefined) env[k] = v;
  }

  const proc = spawn('node', [OPENCLAUDE_CLI, ...args], {
    cwd: options.cwd,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  // Forward stderr to our own stderr for debugging
  proc.stderr?.on('data', (chunk: Buffer) => {
    process.stderr.write(`[openclaude] ${chunk}`);
  });

  const rl = createInterface({ input: proc.stdout!, crlfDelay: Infinity });

  for await (const line of rl) {
    if (!line.trim()) continue;
    try {
      yield JSON.parse(line) as Record<string, unknown>;
    } catch {
      // skip non-JSON lines (e.g. startup noise)
    }
  }

  await new Promise<void>((resolve) => proc.on('close', () => resolve()));
}
