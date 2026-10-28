import { describe, expect, test } from 'vitest';
import { fleetTargetKind, validateFleetCommand } from '../../../../shared/fleet';
import {
  describeFleetCommand,
  describeFleetTargets,
  fleetAgentCommand,
  fleetCommandStateTone,
  fleetStatusTone,
  formatFleetRelativeTime,
  isEnforcementAction,
  summarizeFleetCommand,
} from '../fleet';
import ar from '../../locales/ar.json';
import de from '../../locales/de.json';
import en from '../../locales/en.json';
import es from '../../locales/es.json';
import fr from '../../locales/fr.json';
import hi from '../../locales/hi.json';
import ja from '../../locales/ja.json';
import ko from '../../locales/ko.json';
import pt from '../../locales/pt.json';
import ru from '../../locales/ru.json';
import zh from '../../locales/zh.json';

const t = (key: string, values?: Record<string, string | number>) => `${key}${values ? JSON.stringify(values) : ''}`;

describe('fleet helpers', () => {
  test('formats relative times', () => {
    const now = Date.parse('2026-10-19T08:00:00Z');
    expect(formatFleetRelativeTime(null, 'en', now)).toBeNull();
    expect(formatFleetRelativeTime('garbage', 'en', now)).toBeNull();
    expect(formatFleetRelativeTime('2026-10-19T07:59:30Z', 'en', now)).toBe('30 seconds ago');
    expect(formatFleetRelativeTime('2026-10-19T07:55:00Z', 'en', now)).toBe('5 minutes ago');
    expect(formatFleetRelativeTime('2026-10-19T05:00:00Z', 'en', now)).toBe('3 hours ago');
    expect(formatFleetRelativeTime('2026-10-17T08:00:00Z', 'en', now)).toBe('2 days ago');
    expect(formatFleetRelativeTime('2026-10-19T08:00:00Z', 'en', now)).toBe('now');
  });

  test('maps states to badge tones', () => {
    expect(fleetStatusTone('healthy')).toBe('success');
    expect(fleetStatusTone('degraded')).toBe('warning');
    expect(fleetStatusTone('pending')).toBe('warning');
    expect(fleetStatusTone('offline')).toBe('danger');
    expect(fleetStatusTone('lapi_down')).toBe('danger');
    expect(fleetCommandStateTone('ok')).toBe('success');
    expect(fleetCommandStateTone('failed')).toBe('danger');
    expect(fleetCommandStateTone('expired')).toBe('secondary');
    expect(fleetCommandStateTone('sent')).toBe('warning');
    expect(isEnforcementAction('ban')).toBe(true);
    expect(isEnforcementAction('reload')).toBe(false);
  });

  test('describes commands and targets', () => {
    expect(describeFleetCommand({ action: 'ban', params: { target: '192.0.2.1' } }, t)).toBe('pages.fleet.actions.ban: 192.0.2.1 (4h)');
    expect(describeFleetCommand({ action: 'unban', params: { target: '192.0.2.1' } }, t)).toBe('pages.fleet.actions.unban: 192.0.2.1');
    expect(describeFleetCommand({ action: 'hub_install', params: { name: 'crowdsecurity/nginx' } }, t)).toBe('pages.fleet.actions.hub_install: crowdsecurity/nginx');
    expect(describeFleetCommand({ action: 'reload', params: {} }, t)).toBe('pages.fleet.actions.reload');
    expect(describeFleetTargets(['all', 'tag:web', 'h1', 'gone'], new Map([['h1', 'web01']]), t))
      .toBe('pages.fleet.targetAll, pages.fleet.targetTag{"tag":"web"}, web01, gone');
    const summary = summarizeFleetCommand({
      id: 'c', action: 'reload', params: {}, targets: ['all'], created_at: '', created_by: null,
      hosts: (['ok', 'failed', 'queued', 'sent', 'expired'] as const).map((state, index) => ({ host_id: String(index), hostname: '', state, output: null, updated_at: '' })),
    });
    expect(summary).toEqual({ ok: 1, failed: 1, pending: 2, expired: 1 });
  });

  test('builds agent install commands', () => {
    expect(fleetAgentCommand('https://ui.example', 'tok', false)).not.toContain('docker');
    expect(fleetAgentCommand('https://ui.example', 'tok', true)).toContain('-cscli "docker exec crowdsec cscli"');
  });

  test('validates commands the same way as the server', () => {
    expect(fleetTargetKind('192.0.2.1')).toBe('ip');
    expect(fleetTargetKind('2001:db8::1')).toBe('ip');
    expect(fleetTargetKind('192.0.2.0/24')).toBe('range');
    expect(fleetTargetKind('2001:db8::/32')).toBe('range');
    expect(fleetTargetKind('192.0.2.0/33')).toBeNull();
    expect(fleetTargetKind('256.0.0.1')).toBeNull();
    expect(fleetTargetKind('1.2.3.4; id')).toBeNull();
    expect(fleetTargetKind('example.com')).toBeNull();
    expect(validateFleetCommand('ban', { target: '192.0.2.1', duration: '7d', reason: 'scan' })).toBeNull();
    expect(validateFleetCommand('ban', { target: '192.0.2.1', duration: '1 week' })).toMatch(/Duration/);
    expect(validateFleetCommand('ban', { target: '192.0.2.1', reason: '$(id)' })).toMatch(/Reason/);
    expect(validateFleetCommand('hub_install', { kind: 'collections', name: 'crowdsecurity/nginx' })).toBeNull();
    expect(validateFleetCommand('hub_install', { kind: 'scripts', name: 'crowdsecurity/nginx' })).toMatch(/type/);
    expect(validateFleetCommand('hub_remove', { kind: 'parsers', name: '../x' })).toMatch(/name/);
    expect(validateFleetCommand('hub_upgrade', { reload: 'maybe' })).toMatch(/Reload/);
  });
});

describe('fleet locale coverage', () => {
  const fleetKeys = (locale: Record<string, string>) => Object.keys(locale)
    .filter((key) => key.startsWith('pages.fleet.') || key === 'components.sidebar.nav.fleet')
    .sort();

  test.each(Object.entries({ ar, de, es, fr, hi, ja, ko, pt, ru, zh }))('%s contains every English fleet key', (_language, locale) => {
    expect(fleetKeys(locale)).toEqual(fleetKeys(en));
  });
});
