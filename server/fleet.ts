import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { Hono } from 'hono';
import {
  FLEET_ENFORCEMENT_ACTIONS,
  isFleetAction,
  isFleetTag,
  validateFleetCommand,
  type FleetAction,
  type FleetAlert,
  type FleetBouncer,
  type FleetCommand,
  type FleetCommandHostStatus,
  type FleetCommandParams,
  type FleetDecision,
  type FleetHostDetail,
  type FleetHostStatus,
  type FleetHostSummary,
  type FleetHubItem,
  type FleetMachine,
  type FleetOverview,
  type FleetResponse,
  type FleetSnapshot,
  type FleetSourceAggregate,
} from '../shared/fleet';
import type { DashboardAuth } from './app-auth';
import type { AuditLogger } from './audit-log';
import type { CrowdsecDatabase } from './database';

type HonoContext = any;

export const FLEET_ENROLLMENT_TOKEN_META_KEY = 'fleet_enrollment_token';
export const FLEET_COMMAND_EXPIRY_MS = 24 * 60 * 60 * 1000;
export const FLEET_STALE_BOUNCER_MS = 60 * 60 * 1000;
const MAX_COMMAND_HISTORY = 500;
const COMMAND_LIST_LIMIT = 100;
const TOP_SOURCE_LIMIT = 25;
const DEFAULT_INTERVAL_SECONDS = 15;
const LIMITS = {
  decisions: 1000,
  alerts: 100,
  bouncers: 200,
  machines: 200,
  collections: 500,
  errors: 20,
  tags: 20,
  text: 512,
  output: 4000,
};

interface HostRow {
  id: string;
  hostname: string;
  tags: string;
  instance_id: string | null;
  enrolled_at: string;
  last_seen_at: string | null;
  remote_addr: string | null;
  agent_version: string | null;
  interval_seconds: number;
  snapshot: string | null;
  snapshot_at: string | null;
  pending_commands: number;
}

interface CommandRow {
  id: string;
  action: FleetAction;
  params: string;
  targets: string;
  created_at: string;
  created_by: string | null;
}

export function hashFleetKey(key: string): string {
  return createHash('sha256').update(key).digest('hex');
}

function text(value: unknown, max = LIMITS.text): string {
  if (typeof value !== 'string') return typeof value === 'number' ? String(value) : '';
  const trimmed = value.trim();
  return trimmed.length > max ? `${trimmed.slice(0, max)}…` : trimmed;
}

function int(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? Math.max(0, Math.trunc(value)) : 0;
}

function list<T>(value: unknown, max: number, map: (item: Record<string, unknown>) => T): T[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === 'object' && !Array.isArray(item))
    .slice(0, max)
    .map(map);
}

function sanitizeTags(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const tags = value.filter((tag): tag is string => typeof tag === 'string').map((tag) => tag.trim()).filter(isFleetTag);
  return [...new Set(tags)].slice(0, LIMITS.tags);
}

/** Agents run on hosts we only partly trust, so every field is coerced and bounded. */
export function sanitizeSnapshot(value: unknown): FleetSnapshot | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const raw = value as Record<string, unknown>;
  const decision = (item: Record<string, unknown>): FleetDecision => ({
    id: int(item.id),
    origin: text(item.origin),
    type: text(item.type),
    scope: text(item.scope),
    value: text(item.value),
    duration: text(item.duration),
    scenario: text(item.scenario),
  });
  const decisions = list(raw.decisions, LIMITS.decisions, decision);
  const errors: Record<string, string> = {};
  if (raw.errors && typeof raw.errors === 'object' && !Array.isArray(raw.errors)) {
    for (const [key, message] of Object.entries(raw.errors).slice(0, LIMITS.errors)) {
      errors[text(key, 64)] = text(message, 1000);
    }
  }
  return {
    collected_at: text(raw.collected_at, 64),
    crowdsec_version: text(raw.crowdsec_version, 64),
    lapi_healthy: raw.lapi_healthy === true,
    decisions_total: Math.max(int(raw.decisions_total), decisions.length),
    decisions,
    alerts: list(raw.alerts, LIMITS.alerts, (item): FleetAlert => ({
      id: int(item.id),
      scenario: text(item.scenario),
      created_at: text(item.created_at, 64),
      events_count: int(item.events_count),
      source_scope: text(item.source_scope, 64),
      source_value: text(item.source_value),
      country: text(item.country, 8),
      as_name: text(item.as_name),
      kind: text(item.kind, 32),
      simulated: item.simulated === true,
    })),
    bouncers: list(raw.bouncers, LIMITS.bouncers, (item): FleetBouncer => ({
      name: text(item.name),
      ip: text(item.ip, 64),
      type: text(item.type),
      version: text(item.version, 64),
      last_pull: text(item.last_pull, 64),
    })),
    machines: list(raw.machines, LIMITS.machines, (item): FleetMachine => ({
      name: text(item.name),
      ip: text(item.ip, 64),
      version: text(item.version, 64),
      last_heartbeat: text(item.last_heartbeat, 64),
      validated: item.validated === true,
    })),
    collections: list(raw.collections, LIMITS.collections, (item): FleetHubItem => ({
      name: text(item.name),
      status: text(item.status, 64),
      local_version: text(item.local_version, 32),
    })),
    errors,
  };
}

function parseSnapshot(row: HostRow): FleetSnapshot | null {
  if (!row.snapshot) return null;
  try {
    return sanitizeSnapshot(JSON.parse(row.snapshot));
  } catch {
    return null;
  }
}

function parseJson<T>(value: string, fallback: T): T {
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

export function isFleetHostOnline(lastSeenAt: string | null, intervalSeconds: number, now = Date.now()): boolean {
  if (!lastSeenAt) return false;
  const interval = intervalSeconds > 0 ? intervalSeconds : DEFAULT_INTERVAL_SECONDS;
  return now - Date.parse(lastSeenAt) < (interval * 3 + 10) * 1000;
}

function isStaleBouncer(bouncer: FleetBouncer, now: number): boolean {
  const lastPull = Date.parse(bouncer.last_pull);
  return !Number.isFinite(lastPull) || now - lastPull > FLEET_STALE_BOUNCER_MS;
}

function needsUpdate(item: FleetHubItem): boolean {
  return /update|tainted|outdated/i.test(item.status);
}

function hostStatus(online: boolean, snapshot: FleetSnapshot | null): FleetHostStatus {
  if (!online) return 'offline';
  if (!snapshot) return 'pending';
  if (!snapshot.lapi_healthy) return 'lapi_down';
  return Object.keys(snapshot.errors).length > 0 ? 'degraded' : 'healthy';
}

function toSummary(row: HostRow, snapshot: FleetSnapshot | null, now: number): FleetHostSummary {
  const online = isFleetHostOnline(row.last_seen_at, row.interval_seconds, now);
  return {
    id: row.id,
    hostname: row.hostname,
    tags: parseJson<string[]>(row.tags, []),
    instance_id: row.instance_id,
    status: hostStatus(online, snapshot),
    enrolled_at: row.enrolled_at,
    last_seen_at: row.last_seen_at,
    remote_addr: row.remote_addr,
    agent_version: row.agent_version,
    crowdsec_version: snapshot?.crowdsec_version || null,
    snapshot_at: row.snapshot_at,
    decisions: snapshot?.decisions_total ?? 0,
    alerts: snapshot?.alerts.length ?? 0,
    bouncers: snapshot?.bouncers.length ?? 0,
    stale_bouncers: snapshot?.bouncers.filter((bouncer) => isStaleBouncer(bouncer, now)).length ?? 0,
    collections: snapshot?.collections.length ?? 0,
    updates_needed: snapshot?.collections.filter(needsUpdate).length ?? 0,
    errors: snapshot ? Object.keys(snapshot.errors).length : 0,
    pending_commands: row.pending_commands,
  };
}

/** Correlates detections across hosts; manual cscli/console alerts are not attacks. */
export function aggregateFleetSources(hosts: Array<{ hostname: string; snapshot: FleetSnapshot | null }>): FleetSourceAggregate[] {
  const sources = new Map<string, FleetSourceAggregate>();
  for (const { hostname, snapshot } of hosts) {
    for (const alert of snapshot?.alerts ?? []) {
      if (!alert.source_value || (alert.kind && alert.kind !== 'crowdsec') || alert.simulated) continue;
      let source = sources.get(alert.source_value);
      if (!source) {
        source = {
          value: alert.source_value,
          scope: alert.source_scope,
          country: alert.country,
          as_name: alert.as_name,
          alerts: 0,
          hosts: [],
          banned_on: [],
          scenarios: [],
          last_seen: '',
        };
        sources.set(alert.source_value, source);
      }
      source.alerts += 1;
      if (!source.hosts.includes(hostname)) source.hosts.push(hostname);
      if (alert.scenario && !source.scenarios.includes(alert.scenario)) source.scenarios.push(alert.scenario);
      if (alert.created_at > source.last_seen) source.last_seen = alert.created_at;
    }
  }
  for (const { hostname, snapshot } of hosts) {
    for (const decision of snapshot?.decisions ?? []) {
      const source = sources.get(decision.value);
      if (source && decision.type === 'ban' && !source.banned_on.includes(hostname)) source.banned_on.push(hostname);
    }
  }
  return [...sources.values()]
    .sort((left, right) => right.hosts.length - left.hosts.length || right.alerts - left.alerts || left.value.localeCompare(right.value))
    .slice(0, TOP_SOURCE_LIMIT);
}

export function normalizeClientAddress(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  return text(value.split(',')[0], 64).replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/, '') || null;
}

function readClientAddress(context: HonoContext): string | null {
  return normalizeClientAddress(context.req.header('x-forwarded-for') || context.env?.incoming?.socket?.remoteAddress);
}

async function readBody(context: HonoContext): Promise<Record<string, unknown> | null> {
  try {
    const body = await context.req.json();
    return body && typeof body === 'object' && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function tokensEqual(left: string, right: string): boolean {
  return left.length > 0 && hashFleetKey(left) === hashFleetKey(right);
}

export interface RegisterFleetRoutesOptions {
  app: Hono;
  basePath: string;
  database: CrowdsecDatabase;
  auth: DashboardAuth;
  auditLog: AuditLogger;
  instanceIds: string[];
  writeDatabase: <T>(operation: () => T) => Promise<T>;
  ensureCanManageEnforcement: (context: HonoContext) => Response | null;
  ensureCanManageSettings: (context: HonoContext) => Response | null;
  now?: () => number;
}

export function registerFleetRoutes(options: RegisterFleetRoutesOptions): void {
  const { app, basePath, database, auth, auditLog, instanceIds, writeDatabase, ensureCanManageEnforcement, ensureCanManageSettings } = options;
  const now = options.now ?? Date.now;
  const root = `${basePath}/api/fleet`;
  const db = database.db;

  const ensureEnrollmentToken = (): string => {
    const existing = database.getMeta(FLEET_ENROLLMENT_TOKEN_META_KEY)?.value;
    if (existing) return existing;
    const token = randomBytes(24).toString('hex');
    database.setMeta(FLEET_ENROLLMENT_TOKEN_META_KEY, token);
    return token;
  };

  const selectHosts = (where = '', ...params: unknown[]): HostRow[] => db.query(`
    SELECT h.id, h.hostname, h.tags, h.instance_id, h.enrolled_at, h.last_seen_at, h.remote_addr,
      h.agent_version, h.interval_seconds, h.snapshot, h.snapshot_at,
      (SELECT COUNT(*) FROM fleet_command_hosts c WHERE c.host_id = h.id AND c.state IN ('queued', 'sent')) AS pending_commands
    FROM fleet_hosts h ${where}
    ORDER BY h.hostname COLLATE NOCASE, h.id
  `).all(...params) as HostRow[];

  const resolveTargets = (targets: string[]): HostRow[] => {
    const hosts = selectHosts();
    const selected = new Map<string, HostRow>();
    for (const target of targets) {
      for (const host of hosts) {
        const matches = target === 'all'
          || (target.startsWith('tag:') && parseJson<string[]>(host.tags, []).includes(target.slice(4)))
          || host.id === target;
        if (matches) selected.set(host.id, host);
      }
    }
    return [...selected.values()];
  };

  const listCommands = (): FleetCommand[] => {
    const commands = db.query(`
      SELECT id, action, params, targets, created_at, created_by FROM fleet_commands
      ORDER BY created_at DESC, rowid DESC LIMIT ${COMMAND_LIST_LIMIT}
    `).all() as CommandRow[];
    if (commands.length === 0) return [];
    const statuses = db.query(`
      SELECT command_id, host_id, hostname, state, output, updated_at FROM fleet_command_hosts
      WHERE command_id IN (${commands.map(() => '?').join(',')})
      ORDER BY hostname COLLATE NOCASE
    `).all(...commands.map((command) => command.id)) as Array<FleetCommandHostStatus & { command_id: string }>;
    return commands.map((command) => ({
      id: command.id,
      action: command.action,
      params: parseJson<FleetCommandParams>(command.params, {}),
      targets: parseJson<string[]>(command.targets, []),
      created_at: command.created_at,
      created_by: command.created_by,
      hosts: statuses
        .filter((status) => status.command_id === command.id)
        .map(({ command_id: _commandId, ...status }) => status),
    }));
  };

  // ---- agent endpoints (authenticated by enrollment token / per-host key) ----

  app.post(`${root}/agent/enroll`, async (context) => {
    const body = await readBody(context);
    if (!body) return context.json({ error: 'Invalid JSON body' }, 400);
    const token = typeof body.token === 'string' ? body.token : '';
    const expected = database.getMeta(FLEET_ENROLLMENT_TOKEN_META_KEY)?.value ?? '';
    if (!expected || !tokensEqual(token, expected)) return context.json({ error: 'Invalid enrollment token' }, 401);
    const hostname = text(body.hostname, 128);
    if (!hostname) return context.json({ error: 'Hostname is required' }, 400);
    const key = randomBytes(32).toString('hex');
    const instanceId = typeof body.instance === 'string' && instanceIds.includes(body.instance) ? body.instance : null;
    const host = { id: randomUUID(), hostname, tags: JSON.stringify(sanitizeTags(body.tags)), instanceId };
    await writeDatabase(() => db.query(`
      INSERT INTO fleet_hosts (id, hostname, tags, instance_id, key_hash, enrolled_at, remote_addr, interval_seconds)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(host.id, host.hostname, host.tags, host.instanceId, hashFleetKey(key), new Date(now()).toISOString(), readClientAddress(context), DEFAULT_INTERVAL_SECONDS));
    console.log(`[fleet] Enrolled host ${hostname} (${host.id})`);
    return context.json({ agent_id: host.id, key }, 201);
  });

  app.post(`${root}/agent/checkin`, async (context) => {
    const key = (context.req.header('authorization') || '').replace(/^Bearer\s+/i, '').trim();
    if (!key) return context.json({ error: 'Missing agent key' }, 401);
    const body = await readBody(context);
    if (!body) return context.json({ error: 'Invalid JSON body' }, 400);
    const keyHash = hashFleetKey(key);
    const timestamp = new Date(now()).toISOString();
    const expiredBefore = new Date(now() - FLEET_COMMAND_EXPIRY_MS).toISOString();
    const snapshot = body.snapshot === undefined ? undefined : sanitizeSnapshot(body.snapshot);
    const results = Array.isArray(body.results) ? body.results.slice(0, 100) : [];
    const instanceId = typeof body.instance === 'string' && instanceIds.includes(body.instance) ? body.instance : null;

    const delivered = await writeDatabase(() => {
      const host = db.query('SELECT id FROM fleet_hosts WHERE key_hash = ?').get(keyHash) as { id: string } | undefined;
      if (!host) return null;
      db.query(`
        UPDATE fleet_hosts SET hostname = COALESCE(NULLIF(?, ''), hostname), tags = ?, instance_id = ?, last_seen_at = ?,
          remote_addr = ?, agent_version = ?, interval_seconds = ?
        WHERE id = ?
      `).run(
        text(body.hostname, 128),
        JSON.stringify(sanitizeTags(body.tags)),
        instanceId,
        timestamp,
        readClientAddress(context),
        text(body.agent_version, 32) || null,
        Math.min(3600, int(body.interval)) || DEFAULT_INTERVAL_SECONDS,
        host.id,
      );
      if (snapshot) {
        db.query('UPDATE fleet_hosts SET snapshot = ?, snapshot_at = ? WHERE id = ?').run(JSON.stringify(snapshot), timestamp, host.id);
      }
      for (const result of results) {
        if (!result || typeof result !== 'object' || typeof result.id !== 'string') continue;
        db.query(`
          UPDATE fleet_command_hosts SET state = ?, output = ?, updated_at = ?
          WHERE command_id = ? AND host_id = ? AND state IN ('queued', 'sent')
        `).run(result.ok === true ? 'ok' : 'failed', text(result.output, LIMITS.output), timestamp, result.id, host.id);
      }
      db.query(`
        UPDATE fleet_command_hosts SET state = 'expired', updated_at = ?
        WHERE host_id = ? AND state = 'queued'
          AND command_id IN (SELECT id FROM fleet_commands WHERE created_at < ?)
      `).run(timestamp, host.id, expiredBefore);
      const queued = db.query(`
        SELECT c.id, c.action, c.params, c.created_at FROM fleet_command_hosts s
        JOIN fleet_commands c ON c.id = s.command_id
        WHERE s.host_id = ? AND s.state = 'queued'
        ORDER BY c.created_at, c.rowid
      `).all(host.id) as Array<{ id: string; action: FleetAction; params: string; created_at: string }>;
      if (queued.length > 0) {
        db.query(`UPDATE fleet_command_hosts SET state = 'sent', updated_at = ? WHERE host_id = ? AND state = 'queued'`).run(timestamp, host.id);
      }
      return queued;
    });

    if (!delivered) return context.json({ error: 'Unknown agent key; the host may have been removed' }, 401);
    return context.json({
      commands: delivered.map((command) => ({
        id: command.id,
        action: command.action,
        params: parseJson<FleetCommandParams>(command.params, {}),
        created: command.created_at,
      })),
    });
  });

  // ---- dashboard endpoints ----

  app.get(root, auth.ensureAuth, (context) => {
    const timestamp = now();
    const rows = selectHosts();
    const parsed = rows.map((row) => ({ row, snapshot: parseSnapshot(row) }));
    const hosts = parsed.map(({ row, snapshot }) => toSummary(row, snapshot, timestamp));
    const versions = new Map<string, number>();
    for (const host of hosts) {
      if (host.crowdsec_version) versions.set(host.crowdsec_version, (versions.get(host.crowdsec_version) ?? 0) + 1);
    }
    const overview: FleetOverview = {
      hosts: hosts.length,
      online: hosts.filter((host) => host.status !== 'offline').length,
      needs_attention: hosts.filter((host) => host.status !== 'healthy' || host.stale_bouncers > 0).length,
      decisions: hosts.reduce((total, host) => total + host.decisions, 0),
      alerts: hosts.reduce((total, host) => total + host.alerts, 0),
      bouncers: hosts.reduce((total, host) => total + host.bouncers, 0),
      stale_bouncers: hosts.reduce((total, host) => total + host.stale_bouncers, 0),
      updates_needed: hosts.reduce((total, host) => total + host.updates_needed, 0),
      versions: [...versions].map(([version, count]) => ({ version, hosts: count })).sort((left, right) => right.hosts - left.hosts || left.version.localeCompare(right.version)),
      tags: [...new Set(hosts.flatMap((host) => host.tags))].sort(),
      top_sources: aggregateFleetSources(parsed.map(({ row, snapshot }) => ({ hostname: row.hostname, snapshot }))),
    };
    const response: FleetResponse = { hosts, overview };
    return context.json(response);
  });

  app.get(`${root}/hosts/:id`, auth.ensureAuth, (context) => {
    const [row] = selectHosts('WHERE h.id = ?', context.req.param('id'));
    if (!row) return context.json({ error: 'Host not found' }, 404);
    const snapshot = parseSnapshot(row);
    const detail: FleetHostDetail = { ...toSummary(row, snapshot, now()), snapshot };
    return context.json(detail);
  });

  app.delete(`${root}/hosts/:id`, auth.ensureAuth, async (context) => {
    const denied = ensureCanManageSettings(context);
    if (denied) return denied;
    const id = context.req.param('id');
    const removed = await writeDatabase(() => {
      const host = db.query('SELECT hostname FROM fleet_hosts WHERE id = ?').get(id) as { hostname: string } | undefined;
      if (!host) return null;
      db.query(`UPDATE fleet_command_hosts SET state = 'expired', updated_at = ? WHERE host_id = ? AND state IN ('queued', 'sent')`)
        .run(new Date(now()).toISOString(), id);
      db.query('DELETE FROM fleet_hosts WHERE id = ?').run(id);
      return host;
    });
    if (!removed) return context.json({ error: 'Host not found' }, 404);
    auditLog.record(context, { action: 'fleet.host.remove', outcome: 'success', host_id: id, hostname: removed.hostname });
    return context.json({ success: true });
  });

  app.get(`${root}/commands`, auth.ensureAuth, (context) => context.json(listCommands()));

  app.post(`${root}/commands`, auth.ensureAuth, async (context) => {
    const body = await readBody(context);
    if (!body) return context.json({ error: 'Invalid JSON body' }, 400);
    if (!isFleetAction(body.action)) return context.json({ error: 'Unknown action' }, 400);
    const action = body.action;
    const denied = FLEET_ENFORCEMENT_ACTIONS.includes(action) ? ensureCanManageEnforcement(context) : ensureCanManageSettings(context);
    if (denied) return denied;

    const rawParams = body.params && typeof body.params === 'object' && !Array.isArray(body.params) ? body.params as Record<string, unknown> : {};
    const params: FleetCommandParams = {};
    for (const field of ['target', 'duration', 'reason', 'kind', 'name', 'reload'] as const) {
      const value = rawParams[field];
      if (typeof value === 'string' && value.trim()) params[field] = value.trim();
    }
    const invalid = validateFleetCommand(action, params);
    if (invalid) return context.json({ error: invalid }, 400);

    const targets = Array.isArray(body.targets)
      ? [...new Set(body.targets.filter((target): target is string => typeof target === 'string' && target.length > 0 && target.length <= 64))]
      : [];
    if (targets.length === 0) return context.json({ error: 'Choose at least one target' }, 400);

    const actor = auth.getSession(context)?.username ?? null;
    const command = await writeDatabase(() => {
      const hosts = resolveTargets(targets);
      if (hosts.length === 0) return null;
      const id = randomUUID();
      const createdAt = new Date(now()).toISOString();
      db.query('INSERT INTO fleet_commands (id, action, params, targets, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)')
        .run(id, action, JSON.stringify(params), JSON.stringify(targets), createdAt, actor);
      const insert = db.query(`INSERT INTO fleet_command_hosts (command_id, host_id, hostname, state, updated_at) VALUES (?, ?, ?, 'queued', ?)`);
      for (const host of hosts) insert.run(id, host.id, host.hostname, createdAt);
      db.query(`
        DELETE FROM fleet_commands WHERE id NOT IN (
          SELECT id FROM fleet_commands ORDER BY created_at DESC, rowid DESC LIMIT ${MAX_COMMAND_HISTORY}
        )
      `).run();
      db.query('DELETE FROM fleet_command_hosts WHERE command_id NOT IN (SELECT id FROM fleet_commands)').run();
      return { id, hosts: hosts.length };
    });
    if (!command) return context.json({ error: 'No hosts match those targets' }, 400);
    auditLog.record(context, { action: 'fleet.command', outcome: 'queued', command_id: command.id, fleet_action: action, params, targets, hosts: command.hosts });
    const created = listCommands().find((entry) => entry.id === command.id);
    return context.json(created, 201);
  });

  app.get(`${root}/enrollment`, auth.ensureAuth, async (context) => {
    const denied = ensureCanManageSettings(context);
    if (denied) return denied;
    const token = database.getMeta(FLEET_ENROLLMENT_TOKEN_META_KEY)?.value ?? await writeDatabase(ensureEnrollmentToken);
    return context.json({ token });
  });

  app.post(`${root}/enrollment/rotate`, auth.ensureAuth, async (context) => {
    const denied = ensureCanManageSettings(context);
    if (denied) return denied;
    const token = randomBytes(24).toString('hex');
    await writeDatabase(() => database.setMeta(FLEET_ENROLLMENT_TOKEN_META_KEY, token));
    auditLog.record(context, { action: 'fleet.enrollment.rotate', outcome: 'success' });
    return context.json({ token });
  });
}

export function isFleetAgentPath(pathname: string, basePath: string): boolean {
  return pathname.startsWith(`${basePath}/api/fleet/agent/`);
}

