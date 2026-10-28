export const FLEET_ACTIONS = [
  'refresh',
  'ban',
  'unban',
  'hub_update',
  'hub_upgrade',
  'hub_install',
  'hub_remove',
  'reload',
] as const;

export type FleetAction = typeof FLEET_ACTIONS[number];

export const FLEET_ENFORCEMENT_ACTIONS: readonly FleetAction[] = ['ban', 'unban'];

export const FLEET_HUB_KINDS = [
  'collections',
  'parsers',
  'scenarios',
  'postoverflows',
  'appsec-rules',
  'appsec-configs',
] as const;

export type FleetHubKind = typeof FLEET_HUB_KINDS[number];

export type FleetCommandParams = Partial<Record<'target' | 'duration' | 'reason' | 'kind' | 'name' | 'reload', string>>;

export type FleetHostStatus = 'healthy' | 'degraded' | 'lapi_down' | 'offline' | 'pending';

export type FleetCommandState = 'queued' | 'sent' | 'ok' | 'failed' | 'expired';

export interface FleetDecision {
  id: number;
  origin: string;
  type: string;
  scope: string;
  value: string;
  duration: string;
  scenario: string;
}

export interface FleetAlert {
  id: number;
  scenario: string;
  created_at: string;
  events_count: number;
  source_scope: string;
  source_value: string;
  country: string;
  as_name: string;
  kind: string;
  simulated: boolean;
}

export interface FleetBouncer {
  name: string;
  ip: string;
  type: string;
  version: string;
  last_pull: string;
}

export interface FleetMachine {
  name: string;
  ip: string;
  version: string;
  last_heartbeat: string;
  validated: boolean;
}

export interface FleetHubItem {
  name: string;
  status: string;
  local_version: string;
}

export interface FleetSnapshot {
  collected_at: string;
  crowdsec_version: string;
  lapi_healthy: boolean;
  decisions_total: number;
  decisions: FleetDecision[];
  alerts: FleetAlert[];
  bouncers: FleetBouncer[];
  machines: FleetMachine[];
  collections: FleetHubItem[];
  errors: Record<string, string>;
}

export interface FleetHostSummary {
  id: string;
  hostname: string;
  tags: string[];
  instance_id: string | null;
  status: FleetHostStatus;
  enrolled_at: string;
  last_seen_at: string | null;
  remote_addr: string | null;
  agent_version: string | null;
  crowdsec_version: string | null;
  snapshot_at: string | null;
  decisions: number;
  alerts: number;
  bouncers: number;
  stale_bouncers: number;
  collections: number;
  updates_needed: number;
  errors: number;
  pending_commands: number;
}

export interface FleetHostDetail extends FleetHostSummary {
  snapshot: FleetSnapshot | null;
}

export interface FleetSourceAggregate {
  value: string;
  scope: string;
  country: string;
  as_name: string;
  alerts: number;
  hosts: string[];
  banned_on: string[];
  scenarios: string[];
  last_seen: string;
}

export interface FleetVersionCount {
  version: string;
  hosts: number;
}

export interface FleetOverview {
  hosts: number;
  online: number;
  needs_attention: number;
  decisions: number;
  alerts: number;
  bouncers: number;
  stale_bouncers: number;
  updates_needed: number;
  versions: FleetVersionCount[];
  tags: string[];
  top_sources: FleetSourceAggregate[];
}

export interface FleetResponse {
  hosts: FleetHostSummary[];
  overview: FleetOverview;
}

export interface FleetCommandHostStatus {
  host_id: string;
  hostname: string;
  state: FleetCommandState;
  output: string | null;
  updated_at: string;
}

export interface FleetCommand {
  id: string;
  action: FleetAction;
  params: FleetCommandParams;
  targets: string[];
  created_at: string;
  created_by: string | null;
  hosts: FleetCommandHostStatus[];
}

export interface CreateFleetCommandRequest {
  action: FleetAction;
  params?: FleetCommandParams;
  /** "all", "tag:<name>", or host IDs. */
  targets: string[];
}

export interface FleetEnrollmentResponse {
  token: string;
}

const DURATION_PATTERN = /^[0-9]{1,5}[smhd]$/;
const HUB_NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}(\/[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99})?$/;
const REASON_PATTERN = /^[\p{L}\p{N} _.,:;'()/#@+-]{0,200}$/u;
const TAG_PATTERN = /^[a-zA-Z0-9_.-]{1,32}$/;
const IPV4_OCTET = '(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])';
const IPV4_PATTERN = new RegExp(`^${IPV4_OCTET}(\\.${IPV4_OCTET}){3}$`);

function isIpv6(value: string): boolean {
  if (!value.includes(':') || !/^[0-9a-fA-F:.]+$/.test(value)) return false;
  try {
    return new URL(`http://[${value}]/`).hostname.length > 2;
  } catch {
    return false;
  }
}

export function fleetTargetKind(value: string): 'ip' | 'range' | null {
  const trimmed = value.trim();
  if (IPV4_PATTERN.test(trimmed) || isIpv6(trimmed)) return 'ip';
  const [address, prefix, extra] = trimmed.split('/');
  if (extra !== undefined || prefix === undefined || !/^[0-9]{1,3}$/.test(prefix)) return null;
  const bits = Number(prefix);
  if (IPV4_PATTERN.test(address)) return bits <= 32 ? 'range' : null;
  if (isIpv6(address)) return bits <= 128 ? 'range' : null;
  return null;
}

export function isFleetAction(value: unknown): value is FleetAction {
  return typeof value === 'string' && (FLEET_ACTIONS as readonly string[]).includes(value);
}

export function isFleetTag(value: string): boolean {
  return TAG_PATTERN.test(value);
}

/** Returns an error message, or null when the command is valid. */
export function validateFleetCommand(action: FleetAction, params: FleetCommandParams = {}): string | null {
  if (action === 'ban' || action === 'unban') {
    if (!fleetTargetKind(params.target ?? '')) return 'Target must be an IP address or CIDR range';
  }
  if (action === 'ban') {
    if (params.duration && !DURATION_PATTERN.test(params.duration)) return 'Duration must look like 30m, 4h or 7d';
    if (params.reason && !REASON_PATTERN.test(params.reason)) return 'Reason contains unsupported characters';
  }
  if (action === 'hub_install' || action === 'hub_remove') {
    if (!(FLEET_HUB_KINDS as readonly string[]).includes(params.kind ?? '')) return 'Unknown hub item type';
    if (!HUB_NAME_PATTERN.test(params.name ?? '')) return 'Hub item name must look like crowdsecurity/nginx';
  }
  if (params.reload !== undefined && params.reload !== 'true' && params.reload !== 'false') return 'Reload must be true or false';
  return null;
}
