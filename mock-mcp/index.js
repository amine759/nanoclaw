'use strict';

/**
 * Mock Wazuh MCP Server
 *
 * Implements the same JSON-RPC 2.0 interface as the real Wazuh MCP Server.
 * Use this for local development — no real Wazuh infrastructure needed.
 *
 * Auth:   POST /auth/token  { "api_key": "..." }  →  { "access_token": "..." }
 * Tools:  POST /mcp         Authorization: Bearer <token>  +  JSON-RPC 2.0 body
 * List:   POST /mcp         method: "tools/list"
 *
 * Usage:
 *   node index.js
 *
 * Env overrides:
 *   PORT=3000  API_KEY=wazuh_test...
 */

const http = require('http');
const crypto = require('crypto');
const { ALERTS, AGENTS, PROCESSES, FIM, BACKDOOR_KEY } = require('./scenarios.js');

const PORT = Number(process.env.PORT ?? 3000);
const API_KEY = process.env.API_KEY ?? 'wazuh_test123456789012345678901234567890123';
const JWT_SECRET = 'mock-mcp-secret-not-for-production';

// ─── Stateful action tracking ─────────────────────────────────────────────────

const blockedIPs     = new Set();
const isolatedHosts  = new Set();
const disabledUsers  = new Set();  // "agent_id:username"
const quarantined    = new Set();  // file paths

// ─── JWT helpers (minimal — not cryptographically validated on verify) ─────────

function issueToken(apiKey) {
  const header  = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify({ sub: apiKey, iat: Date.now(), exp: Date.now() + 50 * 60 * 1000 }));
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${sig}`;
}

function b64url(str) {
  return Buffer.from(str).toString('base64url');
}

function validAuth(req) {
  const h = req.headers['authorization'] ?? '';
  // Accept any well-formed Bearer JWT
  return h.startsWith('Bearer ') && h.split('.').length === 3;
}

// ─── Tool implementations ─────────────────────────────────────────────────────

const TOOLS = {

  validate_wazuh_connection: () => ({
    status: 'connected',
    wazuh_version: '4.14.0',
    manager: 'wazuh.manager',
    indexer: 'wazuh.indexer',
    cluster: 'enabled',
    agents_active: AGENTS.filter(a => a.status === 'active').length,
  }),

  // ── Alert queries ────────────────────────────────────────────────────────────

  get_wazuh_alerts: (a) => {
    let results = [...ALERTS];
    if (a.rule_id)    results = results.filter(al => al.rule.id === String(a.rule_id));
    if (a.level)      results = results.filter(al => al.rule.level >= Number(a.level));
    if (a.agent_id)   results = results.filter(al => al.agent.id === a.agent_id || al.agent.name === a.agent_id);
    if (a.srcip)      results = results.filter(al => al.data?.srcip === a.srcip);
    if (a.limit)      results = results.slice(0, Number(a.limit));
    if (a.compact)    return results.map(compactAlert);
    return results;
  },

  get_wazuh_alert_summary: (a) => ({
    total: ALERTS.length,
    time_range: a.time_range ?? '24h',
    by_severity: {
      critical: ALERTS.filter(al => al.rule.level >= 13).length,
      high:     ALERTS.filter(al => al.rule.level >= 10 && al.rule.level < 13).length,
      medium:   ALERTS.filter(al => al.rule.level >= 7  && al.rule.level < 10).length,
      low:      ALERTS.filter(al => al.rule.level >= 4  && al.rule.level < 7).length,
      info:     ALERTS.filter(al => al.rule.level < 4).length,
    },
    by_agent: AGENTS.reduce((acc, agent) => {
      acc[agent.name] = ALERTS.filter(al => al.agent.name === agent.name).length;
      return acc;
    }, {}),
    top_rules: [
      { rule_id: '5710', count: 47, description: 'Multiple authentication failures' },
      { rule_id: '87106', count: 1,  description: 'Malware detected' },
      { rule_id: '87105', count: 1,  description: 'Shell script download and execution' },
      { rule_id: '100002', count: 1, description: 'Sensitive data exfiltration detected' },
    ],
    top_source_ips: [
      { ip: '203.0.113.44',  count: 48, label: 'Attacker — brute force + intrusion' },
      { ip: '198.51.100.22', count: 12, label: 'C2 server — malware beacon' },
    ],
  }),

  search_security_events: (a) => {
    const q = (a.query ?? '').toLowerCase();
    let results = [...ALERTS];

    // Simple keyword matching across serialized alert
    if (q) results = results.filter(al => JSON.stringify(al).toLowerCase().includes(q));

    if (a.limit) results = results.slice(0, Number(a.limit));
    if (a.compact) return results.map(compactAlert);
    return results;
  },

  analyze_alert_patterns: () => ({
    patterns: [
      { type: 'brute_force',       confidence: 0.98, source_ip: '203.0.113.44', target: 'prod-web-01', alert_count: 47, duration_minutes: 240 },
      { type: 'lateral_movement',  confidence: 0.91, src: 'prod-web-01', dst: 'prod-db-01', user: 'dbadmin' },
      { type: 'data_exfiltration', confidence: 0.89, host: 'prod-db-01', indicator: 'pg_dump to /tmp' },
      { type: 'persistence',       confidence: 0.85, host: 'prod-app-01', indicator: 'cron modification' },
    ],
    anomalies: [
      { host: 'prod-web-01', description: '47 auth failures then successful login from same IP — classic brute force' },
      { host: 'prod-app-01', description: 'Hidden binary in /tmp beaconing to 198.51.100.22:4444' },
      { host: 'prod-web-01', description: 'authorized_keys modified + .env.bak staged + outbound exfil to 203.0.113.77 — backdoor key + credential theft' },
    ],
  }),

  // ── Agent queries ────────────────────────────────────────────────────────────

  get_wazuh_agents: (a) => {
    let agents = [...AGENTS];
    if (a.agent_id) agents = agents.filter(ag => ag.id === a.agent_id || ag.name === a.agent_id);
    if (a.status)   agents = agents.filter(ag => ag.status === a.status);
    if (a.limit)    agents = agents.slice(0, Number(a.limit));
    return agents;
  },

  check_agent_health: (a) => {
    const agent = findAgent(a.agent_id);
    if (!agent) return { error: 'Agent not found', agent_id: a.agent_id };
    return { agent_id: agent.id, name: agent.name, status: 'active', last_keepalive: new Date().toISOString(), connectivity: 'ok' };
  },

  get_agent_processes: (a) => {
    const agent = findAgent(a.agent_id);
    if (!agent) return { error: 'Agent not found' };
    const procs = PROCESSES[agent.id] ?? [];
    return a.limit ? procs.slice(0, Number(a.limit)) : procs;
  },

  get_wazuh_syscheck: (a) => {
    const agent = findAgent(a.agent_id);
    if (!agent) return { error: 'Agent not found' };
    const events = FIM[agent.id] ?? [];
    const filtered = a.file_path
      ? events.filter(e => e.path.includes(a.file_path))
      : events;
    return { agent_id: agent.id, total: filtered.length, events: filtered };
  },

  get_agent_ports: (a) => {
    const agent = findAgent(a.agent_id);
    if (!agent) return { error: 'Agent not found' };
    const base = [
      { port: 22,   protocol: 'tcp', state: 'LISTEN',      process: 'sshd' },
      { port: 1514, protocol: 'tcp', state: 'ESTABLISHED', process: 'wazuh-agent' },
    ];
    if (agent.name === 'prod-app-01') {
      base.push({ port: 4444, protocol: 'tcp', state: 'ESTABLISHED', process: '.hidden_bin', remote: '198.51.100.22:4444' });
    }
    if (agent.name === 'prod-db-01') {
      base.push({ port: 5432, protocol: 'tcp', state: 'LISTEN', process: 'postgres' });
    }
    return base;
  },

  // ── Vulnerability / threat intel ─────────────────────────────────────────────

  get_wazuh_vulnerabilities: (a) => ({
    agent_id: a.agent_id,
    total: 12, critical: 1, high: 3, medium: 5, low: 3,
    vulnerabilities: [
      { cve: 'CVE-2023-4911',  severity: 'critical', package: 'glibc',   version: '2.35',    title: 'Looney Tunables — local privilege escalation' },
      { cve: 'CVE-2023-38408', severity: 'high',     package: 'openssh', version: '8.9p1',   title: 'ssh-agent remote code execution' },
      { cve: 'CVE-2023-0466',  severity: 'medium',   package: 'openssl', version: '3.0.2',   title: 'Certificate policy verification bypass' },
    ].slice(0, a.severity === 'critical' ? 1 : undefined),
  }),

  analyze_security_threat: (a) => iocLookup(a.indicator, a.indicator_type),
  check_ioc_reputation:    (a) => iocLookup(a.indicator, a.indicator_type),

  // ── Reports / statistics ─────────────────────────────────────────────────────

  generate_security_report: (a) => ({
    report_type: a.report_type ?? 'daily',
    generated_at: new Date().toISOString(),
    period: '24h',
    summary: { total_alerts: ALERTS.length, active_incidents: 2, actions_taken: 0, false_positives: 3 },
    top_threats: ['SSH Brute Force from 203.0.113.44', 'Malware C2 beacon on prod-app-01'],
    mitre_coverage: ['T1110 Brute Force', 'T1021 Remote Services', 'T1041 Exfiltration over C2'],
  }),

  get_wazuh_statistics: () => ({
    alerts_24h: ALERTS.length,
    agents_active: 5,
    agents_total: 5,
    rules_fired_24h: 12,
    events_per_second: 42,
    top_agents: [{ name: 'prod-web-01', alerts: 51 }, { name: 'prod-app-01', alerts: 4 }],
  }),

  get_wazuh_cluster_health: () => ({
    status: 'green',
    manager: { name: 'wazuh.manager', version: '4.14.0', status: 'active' },
    indexer:  { status: 'green', active_shards: 5, nodes: 1 },
    agents:   { total: 5, active: 5, disconnected: 0, never_connected: 0 },
  }),

  // ── Action tools ─────────────────────────────────────────────────────────────

  wazuh_block_ip: (a) => {
    blockedIPs.add(a.ip);
    console.log(`[ACTION] Block IP: ${a.ip}`);
    return { status: 'success', ip: a.ip, action: 'blocked', message: `${a.ip} added to blocklist on all active agents` };
  },
  wazuh_check_blocked_ip: (a) => ({
    ip: a.ip, blocked: blockedIPs.has(a.ip), checked_at: new Date().toISOString(),
  }),

  wazuh_isolate_host: (a) => {
    isolatedHosts.add(a.agent_id);
    console.log(`[ACTION] Isolate host: ${a.agent_id}`);
    return { status: 'success', agent_id: a.agent_id, action: 'isolated', message: `Host isolated from network — only Wazuh manager traffic allowed` };
  },
  wazuh_check_agent_isolation: (a) => ({
    agent_id: a.agent_id, isolated: isolatedHosts.has(a.agent_id),
  }),
  wazuh_unisolate_host: (a) => {
    isolatedHosts.delete(a.agent_id);
    console.log(`[ACTION] Unisolate host: ${a.agent_id}`);
    return { status: 'success', agent_id: a.agent_id, action: 'unisolated' };
  },

  wazuh_kill_process: (a) => {
    console.log(`[ACTION] Kill process pid=${a.pid} on ${a.agent_id}`);
    return { status: 'success', agent_id: a.agent_id, pid: a.pid, action: 'killed', signal: 'SIGKILL' };
  },
  wazuh_check_process: (a) => ({
    agent_id: a.agent_id, pid: a.pid,
    // .hidden_bin (pid 9999) is running until explicitly killed
    running: String(a.pid) === '9999',
  }),

  wazuh_disable_user: (a) => {
    disabledUsers.add(`${a.agent_id}:${a.username}`);
    console.log(`[ACTION] Disable user ${a.username} on ${a.agent_id}`);
    return { status: 'success', agent_id: a.agent_id, username: a.username, action: 'disabled' };
  },
  wazuh_check_user_status: (a) => ({
    agent_id: a.agent_id, username: a.username,
    disabled: disabledUsers.has(`${a.agent_id}:${a.username}`),
  }),
  wazuh_enable_user: (a) => {
    disabledUsers.delete(`${a.agent_id}:${a.username}`);
    return { status: 'success', agent_id: a.agent_id, username: a.username, action: 'enabled' };
  },

  wazuh_quarantine_file: (a) => {
    quarantined.add(a.path);
    console.log(`[ACTION] Quarantine file ${a.path} on ${a.agent_id}`);
    return { status: 'success', agent_id: a.agent_id, path: a.path, action: 'quarantined', backup: `/var/ossec/quarantine${a.path}` };
  },
  wazuh_check_file_quarantine: (a) => ({
    path: a.path, quarantined: quarantined.has(a.path),
  }),
  wazuh_restore_file: (a) => {
    quarantined.delete(a.path);
    return { status: 'success', path: a.path, action: 'restored' };
  },

  wazuh_firewall_drop: (a) => {
    blockedIPs.add(a.ip);
    console.log(`[ACTION] Firewall DROP: ${a.ip}`);
    return { status: 'success', ip: a.ip, action: 'firewall_drop', rule: `iptables -A INPUT -s ${a.ip} -j DROP` };
  },
  wazuh_firewall_allow: (a) => {
    blockedIPs.delete(a.ip);
    return { status: 'success', ip: a.ip, action: 'firewall_allow' };
  },

  wazuh_host_deny: (a) => {
    console.log(`[ACTION] Host deny: ${a.hostname}`);
    return { status: 'success', hostname: a.hostname, action: 'host_deny', message: `${a.hostname} added to /etc/hosts.deny` };
  },
  wazuh_host_allow: (a) => ({
    status: 'success', hostname: a.hostname, action: 'host_allow',
  }),
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function findAgent(id) {
  return AGENTS.find(a => a.id === id || a.name === id);
}

function compactAlert(al) {
  return {
    id: al.id, ts: al.timestamp,
    rule: al.rule.id, level: al.rule.level, desc: al.rule.description,
    agent: al.agent.name, srcip: al.data?.srcip,
  };
}

function iocLookup(indicator, type) {
  const known = {
    '203.0.113.44':  { reputation: 'malicious', score: 92, tags: ['brute-force', 'scanner', 'known-attacker'], reports: 47 },
    '198.51.100.22': { reputation: 'malicious', score: 88, tags: ['c2', 'malware-distribution', 'botnet'],     reports: 23 },
  };
  const hit = known[indicator];
  if (hit) return { indicator, type, ...hit, first_seen: '2024-01-15', last_seen: new Date().toISOString() };
  return { indicator, type, reputation: 'unknown', score: 0, message: 'No threat intelligence data found' };
}

// ─── JSON-RPC handler ─────────────────────────────────────────────────────────

function handleRpc(body) {
  const { method, params, id } = body;

  if (method === 'tools/list') {
    return rpcOk(id, {
      tools: Object.keys(TOOLS).map(name => ({
        name,
        description: `Wazuh MCP: ${name}`,
        inputSchema: { type: 'object', properties: {} },
      })),
    });
  }

  if (method === 'tools/call') {
    const toolName = params?.name;
    const args     = params?.arguments ?? {};
    const handler  = TOOLS[toolName];

    if (!handler) {
      return rpcError(id, -32601, `Unknown tool: ${toolName}`);
    }

    console.log(`[CALL] ${toolName}(${JSON.stringify(args)})`);

    try {
      const result = handler(args);
      return rpcOk(id, { content: [{ type: 'text', text: JSON.stringify(result) }] });
    } catch (err) {
      return rpcError(id, -32603, err.message);
    }
  }

  return rpcError(id, -32601, `Unknown method: ${method}`);
}

function rpcOk(id, result)           { return { jsonrpc: '2.0', id, result }; }
function rpcError(id, code, message) { return { jsonrpc: '2.0', id, error: { code, message } }; }

// ─── HTTP server ──────────────────────────────────────────────────────────────

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end',  () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}

function send(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) });
  res.end(payload);
}

const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];

  // ── Auth endpoint ────────────────────────────────────────────────────────────
  if (req.method === 'POST' && url === '/auth/token') {
    const raw  = await readBody(req);
    const body = JSON.parse(raw);
    if (body.api_key !== API_KEY) {
      return send(res, 401, { error: 'Invalid API key' });
    }
    return send(res, 200, { access_token: issueToken(body.api_key), token_type: 'Bearer', expires_in: 3000 });
  }

  // ── MCP endpoint ─────────────────────────────────────────────────────────────
  if (req.method === 'POST' && url === '/mcp') {
    if (!validAuth(req)) {
      return send(res, 401, { error: 'Unauthorized — provide Authorization: Bearer <token>' });
    }
    const raw  = await readBody(req);
    const body = JSON.parse(raw);
    return send(res, 200, handleRpc(body));
  }

  // ── Health ───────────────────────────────────────────────────────────────────
  if (req.method === 'GET' && url === '/health') {
    return send(res, 200, { status: 'ok', tools: Object.keys(TOOLS).length, alerts: ALERTS.length });
  }

  send(res, 404, { error: 'Not found' });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Mock Wazuh MCP Server listening on :${PORT}`);
  console.log(`API Key:  ${API_KEY}`);
  console.log(`Tools:    ${Object.keys(TOOLS).length}`);
  console.log(`Alerts:   ${ALERTS.length} (${ALERTS.filter(a=>a.id.startsWith('alert-bf')).length} brute-force, ${ALERTS.filter(a=>a.id.startsWith('alert-mal')).length} malware, ${ALERTS.filter(a=>a.id.startsWith('alert-noise')).length} noise, ${ALERTS.filter(a=>a.id.startsWith('alert-bkd')).length} backdoor)`);
  console.log(`Agents:   ${AGENTS.map(a => a.name).join(', ')}`);
  console.log('');
  console.log('Scenarios:');
  console.log('  1. SSH Brute Force → Login → Lateral Movement (203.0.113.44 → prod-web-01 → prod-db-01)  [Wazuh AR path]');
  console.log('  2. Malware: hidden binary + cron persistence + C2 beacon (prod-app-01)                   [Wazuh AR path]');
  console.log('  3. Low-noise routine alerts (dev-staging-01)                                             [no action]');
  console.log('  4. Backdoor SSH key + credential exfil (203.0.113.77 → prod-web-01)                     [mixed: Wazuh AR + custom script]');
});
