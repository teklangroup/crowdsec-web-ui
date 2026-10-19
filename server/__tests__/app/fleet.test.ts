import { describe, expect, test } from 'vitest';
import type { FleetCommand, FleetHostDetail, FleetResponse } from '../../../shared/fleet';
import { aggregateFleetSources, isFleetAgentPath, isFleetHostOnline, normalizeClientAddress, sanitizeSnapshot } from '../../fleet';
import { createAuthSessionCookie, createController } from './harness';

const root = 'http://localhost/crowdsec/api/fleet';

type Controller = ReturnType<typeof createController>['controller'];

async function request(controller: Controller, path = '', options: {
  method?: string;
  cookie?: string;
  key?: string;
  body?: unknown;
  rawBody?: string;
} = {}) {
  const hasBody = options.body !== undefined || options.rawBody !== undefined;
  return await controller.fetch(new Request(`${root}${path}`, {
    method: options.method ?? 'GET',
    headers: {
      ...(options.cookie ? { cookie: options.cookie } : {}),
      ...(options.key ? { authorization: `Bearer ${options.key}` } : {}),
      ...(hasBody ? { 'Content-Type': 'application/json' } : {}),
    },
    ...(hasBody ? { body: options.rawBody ?? JSON.stringify(options.body) } : {}),
  }));
}

function createFleet(env: Record<string, string> = {}) {
  const { controller } = createController({ env: { AUTH_ENABLED: 'true', FLEET_ENABLED: 'true', ...env } });
  const adminId = controller.database.createAuthUser({ username: 'admin', passwordHash: 'hash', role: 'admin', authProvider: 'password' });
  const viewerId = controller.database.createAuthUser({ username: 'viewer', passwordHash: 'hash', role: 'read-only', authProvider: 'password' });
  const admin = createAuthSessionCookie(controller.database, { userId: adminId, username: 'admin', role: 'admin', authMethod: 'password' });
  const viewer = createAuthSessionCookie(controller.database, { userId: viewerId, username: 'viewer', role: 'read-only', authMethod: 'password' });
  return { controller, admin, viewer };
}

async function enrollmentToken(controller: Controller, cookie: string): Promise<string> {
  const response = await request(controller, '/enrollment', { cookie });
  expect(response.status).toBe(200);
  return (await response.json() as { token: string }).token;
}

async function enroll(controller: Controller, token: string, hostname: string, tags: string[] = []) {
  const response = await request(controller, '/agent/enroll', { method: 'POST', body: { token, hostname, tags } });
  expect(response.status).toBe(201);
  return await response.json() as { agent_id: string; key: string };
}

function snapshot(overrides: Record<string, unknown> = {}) {
  return {
    collected_at: '2026-10-19T08:00:00Z',
    crowdsec_version: 'v1.8.1',
    lapi_healthy: true,
    decisions: [{ id: 1, origin: 'crowdsec', type: 'ban', scope: 'Ip', value: '203.0.113.7', duration: '3h', scenario: 'crowdsecurity/ssh-bf' }],
    alerts: [
      { id: 1, scenario: 'crowdsecurity/ssh-bf', created_at: '2026-10-19T07:59:00Z', events_count: 6, source_scope: 'Ip', source_value: '203.0.113.7', country: 'DE', as_name: 'Example AS', kind: 'crowdsec' },
      { id: 2, scenario: 'manual ban', created_at: '2026-10-19T07:58:00Z', events_count: 1, source_scope: 'Ip', source_value: '192.0.2.50', kind: 'cscli' },
    ],
    bouncers: [{ name: 'firewall', ip: '127.0.0.1', type: 'cs-firewall-bouncer', version: 'v0.0.31', last_pull: new Date().toISOString() }],
    machines: [{ name: 'localhost', ip: '127.0.0.1', version: 'v1.8.1', last_heartbeat: '', validated: true }],
    collections: [
      { name: 'crowdsecurity/sshd', status: 'enabled', local_version: '0.3' },
      { name: 'crowdsecurity/linux', status: 'enabled,update-available', local_version: '0.2' },
    ],
    ...overrides,
  };
}

describe('fleet routes', () => {
  test('are not registered unless fleet is enabled', async () => {
    const { controller } = createController({ env: { AUTH_ENABLED: 'false' } });
    expect((await request(controller)).headers.get('content-type')).toContain('text/html');
    expect((await request(controller, '/agent/enroll', { method: 'POST', body: { token: 'x', hostname: 'h' } })).status).toBe(404);
    const config = await (await controller.fetch(new Request('http://localhost/crowdsec/api/config'))).json() as { fleet_enabled: boolean };
    expect(config.fleet_enabled).toBe(false);
  });

  test('enrolls hosts, reports snapshots and aggregates the fleet', async () => {
    const { controller, admin, viewer } = createFleet();
    expect((await request(controller)).status).toBe(401);
    expect((await request(controller, '/enrollment', { cookie: viewer })).status).toBe(403);
    expect((await request(controller, '/agent/enroll', { method: 'POST', body: { token: 'guess', hostname: 'web01' } })).status).toBe(401);

    const token = await enrollmentToken(controller, admin);
    expect(token).toMatch(/^[0-9a-f]{48}$/);
    expect(await enrollmentToken(controller, admin)).toBe(token);
    expect((await request(controller, '/agent/enroll', { method: 'POST', body: { token, hostname: '  ' } })).status).toBe(400);
    expect((await request(controller, '/agent/enroll', { method: 'POST', rawBody: '[]' })).status).toBe(400);

    const web = await enroll(controller, token, 'web01', ['web', 'prod', 'bad tag!']);
    const db = await enroll(controller, token, 'db01', ['db', 'prod']);

    expect((await request(controller, '/agent/checkin', { method: 'POST', body: {} })).status).toBe(401);
    expect((await request(controller, '/agent/checkin', { method: 'POST', key: 'nope', body: {} })).status).toBe(401);
    expect((await request(controller, '/agent/checkin', { method: 'POST', key: web.key, rawBody: 'not json' })).status).toBe(400);

    const webCheckin = await request(controller, '/agent/checkin', {
      method: 'POST',
      key: web.key,
      body: { hostname: 'web01', agent_version: '0.2.0', tags: ['web', 'prod'], interval: 15, snapshot: snapshot() },
    });
    expect(webCheckin.status).toBe(200);
    expect(await webCheckin.json()).toEqual({ commands: [] });
    await request(controller, '/agent/checkin', {
      method: 'POST',
      key: db.key,
      body: { hostname: 'db01', tags: ['db', 'prod'], interval: 15, snapshot: snapshot({ lapi_healthy: false, decisions: [], bouncers: [] }) },
    });

    const fleet = await request(controller, '', { cookie: viewer }).then((response) => response.json()) as FleetResponse;
    expect(fleet.hosts.map((host) => [host.hostname, host.status])).toEqual([['db01', 'lapi_down'], ['web01', 'healthy']]);
    const webHost = fleet.hosts.find((host) => host.hostname === 'web01')!;
    expect(webHost).toMatchObject({ tags: ['web', 'prod'], agent_version: '0.2.0', crowdsec_version: 'v1.8.1', decisions: 1, alerts: 2, bouncers: 1, stale_bouncers: 0, updates_needed: 1 });
    expect(fleet.overview).toMatchObject({ hosts: 2, online: 2, needs_attention: 1, decisions: 1, updates_needed: 2, tags: ['db', 'prod', 'web'] });
    expect(fleet.overview.versions).toEqual([{ version: 'v1.8.1', hosts: 2 }]);
    expect(fleet.overview.top_sources).toHaveLength(1);
    expect(fleet.overview.top_sources[0]).toMatchObject({ value: '203.0.113.7', hosts: ['db01', 'web01'], banned_on: ['web01'], alerts: 2 });

    const detail = await request(controller, `/hosts/${web.agent_id}`, { cookie: viewer }).then((response) => response.json()) as FleetHostDetail;
    expect(detail.snapshot?.collections).toHaveLength(2);
    expect((await request(controller, '/hosts/missing', { cookie: viewer })).status).toBe(404);
  });

  test('queues commands, delivers them once and records results', async () => {
    const { controller, admin, viewer } = createFleet();
    const token = await enrollmentToken(controller, admin);
    const web = await enroll(controller, token, 'web01', ['web']);
    const db = await enroll(controller, token, 'db01', ['db']);
    const checkin = (key: string, body: Record<string, unknown> = {}) => request(controller, '/agent/checkin', { method: 'POST', key, body: { interval: 15, tags: key === web.key ? ['web'] : ['db'], ...body } })
      .then((response) => response.json()) as Promise<{ commands: Array<{ id: string; action: string; params: Record<string, string> }> }>;
    await checkin(web.key);
    await checkin(db.key);

    const create = (body: unknown, cookie = admin) => request(controller, '/commands', { method: 'POST', cookie, body });
    expect((await create({ action: 'ban', targets: ['all'], params: { target: '203.0.113.7' } }, viewer)).status).toBe(403);
    expect((await create({ action: 'hub_update', targets: ['all'] }, viewer)).status).toBe(403);
    expect((await create({ action: 'shell', targets: ['all'] })).status).toBe(400);
    expect((await create({ action: 'ban', targets: ['all'], params: { target: '1.2.3.4; rm -rf /' } })).status).toBe(400);
    expect((await create({ action: 'ban', targets: ['all'], params: { target: '203.0.113.7', duration: 'forever' } })).status).toBe(400);
    expect((await create({ action: 'hub_install', targets: ['all'], params: { kind: 'collections', name: '../etc/passwd' } })).status).toBe(400);
    expect((await create({ action: 'hub_install', targets: ['all'], params: { kind: 'binaries', name: 'crowdsecurity/nginx' } })).status).toBe(400);
    expect((await create({ action: 'refresh', targets: [] })).status).toBe(400);
    expect((await create({ action: 'refresh', targets: ['tag:missing'] })).status).toBe(400);
    expect((await request(controller, '/commands', { method: 'POST', cookie: admin, rawBody: 'x' })).status).toBe(400);

    const ban = await create({ action: 'ban', targets: ['tag:web'], params: { target: '203.0.113.0/24', duration: '2h', reason: 'fleet test', ignored: 'x' } });
    expect(ban.status).toBe(201);
    const banCommand = await ban.json() as FleetCommand;
    expect(banCommand).toMatchObject({ action: 'ban', created_by: 'admin', params: { target: '203.0.113.0/24', duration: '2h', reason: 'fleet test' } });
    expect(banCommand.hosts.map((host) => [host.hostname, host.state])).toEqual([['web01', 'queued']]);
    const install = await create({ action: 'hub_install', targets: ['all', db.agent_id], params: { kind: 'collections', name: 'crowdsecurity/nginx', reload: 'true' } }).then((response) => response.json()) as FleetCommand;
    expect(install.hosts).toHaveLength(2);

    const fleet = await request(controller, '', { cookie: admin }).then((response) => response.json()) as FleetResponse;
    expect(fleet.hosts.find((host) => host.hostname === 'web01')?.pending_commands).toBe(2);

    const delivered = await checkin(web.key);
    expect(delivered.commands.map((command) => command.action)).toEqual(['ban', 'hub_install']);
    expect(delivered.commands[0].params).toEqual({ target: '203.0.113.0/24', duration: '2h', reason: 'fleet test' });
    expect((await checkin(web.key)).commands).toEqual([]);

    await checkin(web.key, {
      results: [
        { id: banCommand.id, ok: true, output: 'Decision successfully added' },
        { id: install.id, ok: false, output: 'x'.repeat(5000) },
        { id: 'unknown', ok: true },
        null,
      ],
    });
    const commands = await request(controller, '/commands', { cookie: viewer }).then((response) => response.json()) as FleetCommand[];
    expect(commands.map((command) => command.action)).toEqual(['hub_install', 'ban']);
    const installStatus = commands[0].hosts.map((host) => [host.hostname, host.state]);
    expect(installStatus).toEqual([['db01', 'queued'], ['web01', 'failed']]);
    expect(commands[0].hosts[1].output!.length).toBeLessThanOrEqual(4001);
    expect(commands[1].hosts[0]).toMatchObject({ state: 'ok', output: 'Decision successfully added' });
  });

  test('expires stale commands and revokes removed hosts', async () => {
    const { controller, admin, viewer } = createFleet();
    const token = await enrollmentToken(controller, admin);
    const host = await enroll(controller, token, 'edge01');
    const command = await request(controller, '/commands', { method: 'POST', cookie: admin, body: { action: 'reload', targets: ['all'] } })
      .then((response) => response.json()) as FleetCommand;
    controller.database.db.query('UPDATE fleet_commands SET created_at = ? WHERE id = ?').run('2000-01-01T00:00:00.000Z', command.id);
    const response = await request(controller, '/agent/checkin', { method: 'POST', key: host.key, body: {} }).then((result) => result.json()) as { commands: unknown[] };
    expect(response.commands).toEqual([]);
    const commands = await request(controller, '/commands', { cookie: admin }).then((result) => result.json()) as FleetCommand[];
    expect(commands[0].hosts[0].state).toBe('expired');

    expect((await request(controller, `/hosts/${host.agent_id}`, { method: 'DELETE', cookie: viewer })).status).toBe(403);
    expect((await request(controller, `/hosts/${host.agent_id}`, { method: 'DELETE', cookie: admin })).status).toBe(200);
    expect((await request(controller, `/hosts/${host.agent_id}`, { method: 'DELETE', cookie: admin })).status).toBe(404);
    expect((await request(controller, '/agent/checkin', { method: 'POST', key: host.key, body: {} })).status).toBe(401);
  });

  test('rotating the enrollment token stops the old one working', async () => {
    const { controller, admin, viewer } = createFleet();
    const token = await enrollmentToken(controller, admin);
    expect((await request(controller, '/enrollment/rotate', { method: 'POST', cookie: viewer })).status).toBe(403);
    const rotated = await request(controller, '/enrollment/rotate', { method: 'POST', cookie: admin }).then((response) => response.json()) as { token: string };
    expect(rotated.token).not.toBe(token);
    expect((await request(controller, '/agent/enroll', { method: 'POST', body: { token, hostname: 'web01' } })).status).toBe(401);
    await enroll(controller, rotated.token, 'web01');
  });

  test('links hosts to configured instances only', async () => {
    const { controller, admin } = createFleet();
    const config = await (await controller.fetch(new Request('http://localhost/crowdsec/api/config', { headers: { cookie: admin } }))).json() as { fleet_enabled: boolean; instances: Array<{ id: string }> };
    expect(config.fleet_enabled).toBe(true);
    const token = await enrollmentToken(controller, admin);
    const linked = await request(controller, '/agent/enroll', { method: 'POST', body: { token, hostname: 'a', instance: config.instances[0].id } }).then((response) => response.json()) as { agent_id: string; key: string };
    const unlinked = await enroll(controller, token, 'b');
    await request(controller, '/agent/checkin', { method: 'POST', key: unlinked.key, body: { instance: 'not-configured' } });
    await request(controller, '/agent/checkin', { method: 'POST', key: linked.key, body: { instance: config.instances[0].id } });
    const fleet = await request(controller, '', { cookie: admin }).then((response) => response.json()) as FleetResponse;
    expect(fleet.hosts.map((host) => [host.hostname, host.instance_id, host.status])).toEqual([['a', config.instances[0].id, 'pending'], ['b', null, 'pending']]);
  });
});

describe('fleet helpers', () => {
  test('sanitizes untrusted snapshots', () => {
    expect(sanitizeSnapshot(null)).toBeNull();
    expect(sanitizeSnapshot([])).toBeNull();
    const result = sanitizeSnapshot({
      crowdsec_version: 42,
      lapi_healthy: 'yes',
      decisions: [{ id: -5, value: 'x'.repeat(600) }, 'junk', null],
      alerts: Array.from({ length: 150 }, (_, index) => ({ id: index })),
      errors: { lapi: 'down', ['k'.repeat(100)]: { nested: true } },
      collections: 'nope',
    })!;
    expect(result.crowdsec_version).toBe('42');
    expect(result.lapi_healthy).toBe(false);
    expect(result.decisions).toHaveLength(1);
    expect(result.decisions[0].id).toBe(0);
    expect(result.decisions[0].value.length).toBe(513);
    expect(result.decisions_total).toBe(1);
    expect(result.alerts).toHaveLength(100);
    expect(result.collections).toEqual([]);
    expect(Object.keys(result.errors)).toEqual(['lapi', `${'k'.repeat(64)}…`]);
  });

  test('computes online state and ignores manual or simulated alerts', () => {
    const now = Date.parse('2026-10-19T08:00:00Z');
    expect(isFleetHostOnline(null, 15, now)).toBe(false);
    expect(isFleetHostOnline('2026-10-19T07:59:10Z', 15, now)).toBe(true);
    expect(isFleetHostOnline('2026-10-19T07:58:00Z', 15, now)).toBe(false);
    expect(isFleetHostOnline('2026-10-19T07:59:30Z', 0, now)).toBe(true);

    const base = sanitizeSnapshot(snapshot())!;
    const simulated = { ...base, alerts: [{ ...base.alerts[0], source_value: '198.51.100.1', simulated: true }] };
    const sources = aggregateFleetSources([{ hostname: 'a', snapshot: base }, { hostname: 'b', snapshot: simulated }, { hostname: 'c', snapshot: null }]);
    expect(sources.map((source) => source.value)).toEqual(['203.0.113.7']);
    expect(isFleetAgentPath('/crowdsec/api/fleet/agent/checkin', '/crowdsec')).toBe(true);
    expect(isFleetAgentPath('/crowdsec/api/fleet', '/crowdsec')).toBe(false);
    expect(normalizeClientAddress('::ffff:172.18.0.1')).toBe('172.18.0.1');
    expect(normalizeClientAddress('203.0.113.9, 10.0.0.1')).toBe('203.0.113.9');
    expect(normalizeClientAddress('2001:db8::1')).toBe('2001:db8::1');
    expect(normalizeClientAddress(undefined)).toBeNull();
  });
});
