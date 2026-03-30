/**
 * OpenTelemetry instrumentation for the NanoClaw agent runner.
 *
 * Uses @arizeai/openinference-instrumentation-anthropic which patches the
 * Anthropic SDK class prototype — works in Node 22 ESM unlike the Claude
 * Agent SDK instrumentation which tries to reassign a read-only module export.
 *
 * Every messages.create call (LLM turn) becomes an LLM span with:
 *   - system prompt + full message history (input)
 *   - model response text (output)
 *   - token counts, model name, tool use details
 *
 * Configuration (data/sessions/wazuh_soc/.claude/settings.json env block):
 *   PHOENIX_COLLECTOR_ENDPOINT  — e.g. https://app.phoenix.arize.com/s/salah
 *   PHOENIX_API_KEY             — Phoenix Cloud API key
 *   PHOENIX_PROJECT_NAME        — project name (default: nanoclaw)
 */

import fs from 'fs';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-proto';
import { SimpleSpanProcessor } from '@opentelemetry/sdk-trace-node';
import { Resource } from '@opentelemetry/resources';
import { SEMRESATTRS_PROJECT_NAME } from '@arizeai/openinference-semantic-conventions';
import { AnthropicInstrumentation } from '@arizeai/openinference-instrumentation-anthropic';
import Anthropic from '@anthropic-ai/sdk';

function loadEnvFromSettings(): Record<string, string> {
  try {
    const raw = fs.readFileSync('/home/node/.claude/settings.json', 'utf-8');
    const settings = JSON.parse(raw);
    return settings?.env ?? {};
  } catch {
    return {};
  }
}

const settingsEnv = loadEnvFromSettings();
const get = (key: string) => process.env[key] ?? settingsEnv[key];

const endpoint    = get('PHOENIX_COLLECTOR_ENDPOINT');
const apiKey      = get('PHOENIX_API_KEY');
const projectName = get('PHOENIX_PROJECT_NAME') ?? 'nanoclaw';

if (!endpoint) {
  console.error('[telemetry] PHOENIX_COLLECTOR_ENDPOINT not set — tracing disabled');
} else {
  const otlpUrl = `${endpoint.replace(/\/$/, '')}/v1/traces`;

  const exporter = new OTLPTraceExporter({
    url: otlpUrl,
    headers: {
      ...(apiKey ? { 'Authorization': `Bearer ${apiKey}` } : {}),
    },
    timeoutMillis: 10_000,
  });

  const instrumentation = new AnthropicInstrumentation();

  // Patches Anthropic.prototype.messages — works in Node 22 ESM because
  // we mutate object properties, not module namespace bindings.
  instrumentation.manuallyInstrument(Anthropic);

  const sdk = new NodeSDK({
    spanProcessors: [new SimpleSpanProcessor(exporter)],
    resource: new Resource({
      'service.name':              'nanoclaw-soc-agent',
      [SEMRESATTRS_PROJECT_NAME]:  projectName,
      'nanoclaw.group':            process.env.GROUP_FOLDER ?? 'unknown',
    }),
    instrumentations: [instrumentation],
  });

  sdk.start();

  const shutdown = async () => {
    try { await sdk.shutdown(); } catch { /* best-effort */ }
  };
  process.on('SIGTERM', shutdown);
  process.on('beforeExit', shutdown);

  console.error(`[telemetry] Anthropic instrumentation registered → ${endpoint} (project: ${projectName})`);
}
