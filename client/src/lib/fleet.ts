import type { FleetAction, FleetCommand, FleetCommandState, FleetHostStatus } from '../../../shared/fleet';

type Translate = (key: string, values?: Record<string, string | number>) => string;

export type FleetTone = 'success' | 'warning' | 'danger' | 'secondary';

export const FLEET_POLL_INTERVAL_MS = 10_000;

const RELATIVE_UNITS: Array<[Intl.RelativeTimeFormatUnit, number]> = [
  ['day', 86_400],
  ['hour', 3_600],
  ['minute', 60],
  ['second', 1],
];

/** "3 minutes ago" in the UI language; null for missing or invalid timestamps. */
export function formatFleetRelativeTime(timestamp: string | null | undefined, language: string, now = Date.now()): string | null {
  if (!timestamp) return null;
  const time = Date.parse(timestamp);
  if (!Number.isFinite(time)) return null;
  const seconds = Math.round((time - now) / 1000);
  const formatter = new Intl.RelativeTimeFormat(language, { numeric: 'auto' });
  for (const [unit, size] of RELATIVE_UNITS) {
    if (Math.abs(seconds) >= size || unit === 'second') {
      return formatter.format(Math.round(seconds / size), unit);
    }
  }
  return null;
}

export function fleetStatusTone(status: FleetHostStatus): FleetTone {
  switch (status) {
    case 'healthy': return 'success';
    case 'degraded':
    case 'pending': return 'warning';
    default: return 'danger';
  }
}

export function fleetCommandStateTone(state: FleetCommandState): FleetTone {
  switch (state) {
    case 'ok': return 'success';
    case 'failed': return 'danger';
    case 'expired': return 'secondary';
    default: return 'warning';
  }
}

export function describeFleetCommand(command: Pick<FleetCommand, 'action' | 'params'>, t: Translate): string {
  const params = command.params;
  const action = t(`pages.fleet.actions.${command.action}`);
  switch (command.action) {
    case 'ban':
      return `${action}: ${params.target ?? ''} (${params.duration || '4h'})`;
    case 'unban':
      return `${action}: ${params.target ?? ''}`;
    case 'hub_install':
    case 'hub_remove':
      return `${action}: ${params.name ?? ''}`;
    default:
      return action;
  }
}

export function describeFleetTargets(targets: string[], hostNames: Map<string, string>, t: Translate): string {
  return targets.map((target) => {
    if (target === 'all') return t('pages.fleet.targetAll');
    if (target.startsWith('tag:')) return t('pages.fleet.targetTag', { tag: target.slice(4) });
    return hostNames.get(target) ?? target;
  }).join(', ');
}

export function summarizeFleetCommand(command: FleetCommand): Record<'ok' | 'failed' | 'pending' | 'expired', number> {
  const summary = { ok: 0, failed: 0, pending: 0, expired: 0 };
  for (const host of command.hosts) {
    if (host.state === 'ok') summary.ok += 1;
    else if (host.state === 'failed') summary.failed += 1;
    else if (host.state === 'expired') summary.expired += 1;
    else summary.pending += 1;
  }
  return summary;
}

export function isEnforcementAction(action: FleetAction): boolean {
  return action === 'ban' || action === 'unban';
}

export function fleetAgentCommand(serverUrl: string, token: string, docker: boolean): string {
  const lines = [
    'sudo crowdsec-fleet-agent \\',
    `  -server ${serverUrl} \\`,
    `  -enroll-token ${token} \\`,
  ];
  if (docker) {
    lines.push('  -cscli "docker exec crowdsec cscli" \\');
    lines.push('  -reload-cmd "docker restart crowdsec" \\');
  }
  lines.push('  -tags prod');
  return lines.join('\n');
}
