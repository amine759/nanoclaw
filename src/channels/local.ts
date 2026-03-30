/**
 * Local HTTP channel — no external messaging platform required.
 *
 * Inbound:  POST http://localhost:<PORT>/chat
 *           Body: { "jid": "local:wazuh_soc", "text": "..." }
 *
 * Outbound: GET  http://localhost:<PORT>/chat/stream?jid=local:wazuh_soc
 *           Server-Sent Events stream of agent responses.
 *
 * Utility:  GET  http://localhost:<PORT>/health
 *           GET  http://localhost:<PORT>/chat/groups  (registered groups)
 *
 * Set LOCAL_HTTP_PORT in .env to change the port (default: 3001).
 * All listeners bind to 127.0.0.1 only.
 */

import http from 'http';
import { randomUUID } from 'crypto';

import { logger } from '../logger.js';
import { registerChannel } from './registry.js';
import type { ChannelOpts } from './registry.js';
import type { Channel, NewMessage } from '../types.js';

const DEFAULT_PORT = 3001;

class LocalHttpChannel implements Channel {
  name = 'local';
  private server: http.Server;
  // Map from jid (or 'all') → open SSE response objects
  private sseClients = new Map<string, Set<http.ServerResponse>>();
  private opts: ChannelOpts;
  private connected = false;
  private port: number;

  constructor(opts: ChannelOpts, port: number) {
    this.opts = opts;
    this.port = port;
    this.server = http.createServer((req, res) => {
      this.handleRequest(req, res).catch((err) => {
        logger.error({ err }, 'Local channel request error');
        if (!res.headersSent) {
          res.writeHead(500);
          res.end();
        }
      });
    });
  }

  private cors(res: http.ServerResponse): void {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }

  private async handleRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    const url = new URL(req.url ?? '/', `http://localhost:${this.port}`);
    this.cors(res);

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // POST /chat — analyst sends a message to a registered group
    if (req.method === 'POST' && url.pathname === '/chat') {
      const body = await readBody(req);
      let payload: { jid?: string; text?: string };
      try {
        payload = JSON.parse(body);
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
        return;
      }

      const { jid, text } = payload;
      if (!jid || !text) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: '"jid" and "text" are required' }));
        return;
      }

      const msg: NewMessage = {
        id: randomUUID(),
        chat_jid: jid,
        sender: 'analyst',
        sender_name: 'Analyst',
        content: text,
        timestamp: new Date().toISOString(),
        is_from_me: false,
      };

      // Ensure the chat exists in the chats table before storing a message.
      // messages.chat_jid is a FK to chats.jid, so onChatMetadata must run first.
      this.opts.onChatMetadata(jid, msg.timestamp, undefined, 'local', false);
      this.opts.onMessage(jid, msg);
      res.writeHead(202, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, id: msg.id }));
      return;
    }

    // GET /chat/stream?jid=local:wazuh_soc — SSE stream of agent responses
    if (req.method === 'GET' && url.pathname === '/chat/stream') {
      const jid = url.searchParams.get('jid') ?? 'all';

      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
      });
      res.write(`data: ${JSON.stringify({ type: 'connected', jid })}\n\n`);

      if (!this.sseClients.has(jid)) this.sseClients.set(jid, new Set());
      this.sseClients.get(jid)!.add(res);

      req.on('close', () => {
        this.sseClients.get(jid)?.delete(res);
      });
      return;
    }

    // GET /chat/groups — list registered groups (convenience for analysts)
    if (req.method === 'GET' && url.pathname === '/chat/groups') {
      const groups = this.opts.registeredGroups();
      const local = Object.entries(groups)
        .filter(([jid]) => jid.startsWith('local:'))
        .map(([jid, g]) => ({ jid, name: g.name, folder: g.folder }));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ groups: local }));
      return;
    }

    // GET /health
    if (req.method === 'GET' && url.pathname === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, channel: 'local', port: this.port }));
      return;
    }

    res.writeHead(404);
    res.end();
  }

  async sendMessage(jid: string, text: string): Promise<void> {
    const event = `data: ${JSON.stringify({ type: 'message', jid, text, timestamp: new Date().toISOString() })}\n\n`;
    for (const client of this.sseClients.get(jid) ?? []) {
      client.write(event);
    }
    for (const client of this.sseClients.get('all') ?? []) {
      client.write(event);
    }
  }

  async connect(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.server.listen(this.port, '127.0.0.1', () => {
        logger.info(
          { port: this.port },
          'Local HTTP channel listening — POST /chat to send, GET /chat/stream to receive',
        );
        resolve();
      });
      this.server.on('error', reject);
    });
    this.connected = true;
  }

  async disconnect(): Promise<void> {
    this.connected = false;
    for (const clients of this.sseClients.values()) {
      for (const c of clients) c.end();
    }
    this.sseClients.clear();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  isConnected(): boolean {
    return this.connected;
  }

  ownsJid(jid: string): boolean {
    return jid.startsWith('local:');
  }
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

registerChannel('local', (opts: ChannelOpts) => {
  const port = parseInt(process.env.LOCAL_HTTP_PORT ?? String(DEFAULT_PORT), 10);
  return new LocalHttpChannel(opts, port);
});
