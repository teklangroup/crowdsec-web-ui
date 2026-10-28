import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  Copy,
  Crosshair,
  KeyRound,
  Layers,
  PackageCheck,
  Play,
  Plug,
  Plus,
  RefreshCw,
  Server,
  ShieldBan,
  Trash2,
  type LucideIcon,
} from 'lucide-react';
import {
  FLEET_HUB_KINDS,
  validateFleetCommand,
  type CreateFleetCommandRequest,
  type FleetAction,
  type FleetCommand,
  type FleetCommandParams,
  type FleetHostDetail,
  type FleetHostSummary,
  type FleetResponse,
} from '../../../shared/fleet';
import { Badge } from '../components/ui/Badge';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { Modal } from '../components/ui/Modal';
import { CountryFlag } from '../components/CountryFlag';
import { useRefresh } from '../contexts/useRefresh';
import { useToast } from '../contexts/useToast';
import {
  createFleetCommand,
  deleteFleetHost,
  fetchConfig,
  fetchFleet,
  fetchFleetCommands,
  fetchFleetEnrollment,
  fetchFleetHost,
  rotateFleetEnrollment,
} from '../lib/api';
import { getBasePath } from '../lib/basePath';
import {
  describeFleetCommand,
  describeFleetTargets,
  fleetAgentCommand,
  fleetCommandStateTone,
  fleetStatusTone,
  formatFleetRelativeTime,
  FLEET_POLL_INTERVAL_MS,
  isEnforcementAction,
  summarizeFleetCommand,
} from '../lib/fleet';
import { useI18n } from '../lib/i18n';

const ACTION_ORDER: FleetAction[] = ['ban', 'unban', 'hub_install', 'hub_remove', 'hub_update', 'hub_upgrade', 'reload', 'refresh'];
const RELOAD_ACTIONS: FleetAction[] = ['hub_install', 'hub_remove', 'hub_upgrade'];
const INPUT_CLASS = 'block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:ring-primary-500 focus:border-primary-500 sm:text-sm';
const LABEL_CLASS = 'block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1';
const PRIMARY_BUTTON = 'inline-flex items-center gap-2 rounded-md bg-primary-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-700 disabled:cursor-not-allowed disabled:opacity-50';
const SECONDARY_BUTTON = 'inline-flex items-center gap-2 rounded-md border border-gray-300 bg-white px-3 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-200 dark:hover:bg-gray-700';
const DANGER_BUTTON = 'inline-flex items-center gap-2 rounded-md bg-red-600 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50';
const TH_CLASS = 'px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400';
const TD_CLASS = 'px-4 py-3 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300';

type Tone = 'neutral' | 'success' | 'warning' | 'danger';

const TILE_TONES: Record<Tone, string> = {
  neutral: 'bg-primary-50 text-primary-600 dark:bg-primary-900/30 dark:text-primary-400',
  success: 'bg-green-50 text-green-600 dark:bg-green-900/30 dark:text-green-400',
  warning: 'bg-amber-50 text-amber-600 dark:bg-amber-900/30 dark:text-amber-400',
  danger: 'bg-red-50 text-red-600 dark:bg-red-900/30 dark:text-red-400',
};

interface Permissions {
  enforcement: boolean;
  settings: boolean;
}

interface ActionPreset {
  action?: FleetAction;
  target?: string;
  ip?: string;
}

function FleetTile({ icon: Icon, title, value, detail, tone = 'neutral' }: {
  icon: LucideIcon;
  title: string;
  value: ReactNode;
  detail: string;
  tone?: Tone;
}) {
  return (
    <Card>
      <CardContent className="flex items-center gap-4 p-4 sm:p-5">
        <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-lg ${TILE_TONES[tone]}`}>
          <Icon className="h-5 w-5" aria-hidden="true" />
        </div>
        <div className="min-w-0">
          <p className="text-sm font-medium text-gray-500 dark:text-gray-400">{title}</p>
          <p className="mt-1 truncate text-2xl font-bold text-gray-900 dark:text-white">{value}</p>
          <p className="mt-1 truncate text-xs text-gray-500 dark:text-gray-400">{detail}</p>
        </div>
      </CardContent>
    </Card>
  );
}

function SectionTitle({ icon: Icon, children, aside }: { icon: LucideIcon; children: ReactNode; aside?: ReactNode }) {
  return (
    <CardHeader className="flex flex-wrap items-center justify-between gap-2">
      <CardTitle className="flex items-center gap-2 text-lg">
        <Icon className="h-5 w-5 text-primary-600 dark:text-primary-400" aria-hidden="true" />
        {children}
      </CardTitle>
      {aside}
    </CardHeader>
  );
}

function RelativeTime({ value }: { value: string | null | undefined }) {
  const { t, language } = useI18n();
  const label = formatFleetRelativeTime(value, language);
  if (!label || !value) return <span className="text-gray-400">{t('pages.fleet.never')}</span>;
  return <time dateTime={value} title={new Date(value).toLocaleString(language)}>{label}</time>;
}

function StatusBadge({ host }: { host: FleetHostSummary }) {
  const { t } = useI18n();
  return <Badge variant={fleetStatusTone(host.status)}>{t(`pages.fleet.status.${host.status}`)}</Badge>;
}

function Tags({ tags }: { tags: string[] }) {
  return (
    <span className="flex flex-wrap gap-1">
      {tags.map((tag) => <Badge key={tag} variant="outline">{tag}</Badge>)}
    </span>
  );
}

function EmptyRow({ colSpan, children }: { colSpan: number; children: ReactNode }) {
  return <tr><td colSpan={colSpan} className="px-4 py-6 text-center text-sm text-gray-500">{children}</td></tr>;
}

function DataTable({ headers, children }: { headers: ReactNode[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        <thead className="bg-gray-50 dark:bg-gray-900/50">
          <tr>{headers.map((header, index) => <th key={index} className={TH_CLASS}>{header}</th>)}</tr>
        </thead>
        <tbody className="divide-y divide-gray-200 bg-white dark:divide-gray-700 dark:bg-gray-800">{children}</tbody>
      </table>
    </div>
  );
}

function ActionModal({ preset, data, permissions, onClose, onSubmit }: {
  preset: ActionPreset;
  data: FleetResponse | null;
  permissions: Permissions;
  onClose: () => void;
  onSubmit: (request: CreateFleetCommandRequest) => Promise<boolean>;
}) {
  const { t } = useI18n();
  const allowedActions = ACTION_ORDER.filter((action) => (isEnforcementAction(action) ? permissions.enforcement : permissions.settings));
  const [action, setAction] = useState<FleetAction>(() => (
    preset.action && allowedActions.includes(preset.action) ? preset.action : allowedActions[0] ?? 'refresh'
  ));
  const [target, setTarget] = useState(preset.target ?? 'all');
  const [params, setParams] = useState<FleetCommandParams>({ target: preset.ip ?? '', duration: '4h', kind: 'collections' });
  const [reload, setReload] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const update = (patch: FleetCommandParams) => setParams((current) => ({ ...current, ...patch }));

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const commandParams: FleetCommandParams = {};
    if (action === 'ban' || action === 'unban') commandParams.target = params.target?.trim();
    if (action === 'ban') {
      commandParams.duration = params.duration?.trim() || '4h';
      if (params.reason?.trim()) commandParams.reason = params.reason.trim();
    }
    if (action === 'hub_install' || action === 'hub_remove') {
      commandParams.kind = params.kind;
      commandParams.name = params.name?.trim();
    }
    if (RELOAD_ACTIONS.includes(action)) commandParams.reload = reload ? 'true' : 'false';
    const invalid = validateFleetCommand(action, commandParams);
    if (invalid) {
      setError(invalid);
      return;
    }
    setSubmitting(true);
    setError(null);
    const ok = await onSubmit({ action, params: commandParams, targets: [target] });
    setSubmitting(false);
    if (ok) onClose();
  };

  return (
    <Modal isOpen onClose={onClose} title={t('pages.fleet.runAction')} maxWidth="max-w-lg">
      <form className="space-y-4" onSubmit={submit}>
        <div>
          <label htmlFor="fleet-action" className={LABEL_CLASS}>{t('pages.fleet.action')}</label>
          <select id="fleet-action" className={INPUT_CLASS} value={action} onChange={(event) => setAction(event.target.value as FleetAction)}>
            {allowedActions.map((option) => <option key={option} value={option}>{t(`pages.fleet.actions.${option}`)}</option>)}
          </select>
          <p className="mt-1 text-xs text-gray-500">{t(`pages.fleet.actionHelp.${action}`)}</p>
        </div>
        <div>
          <label htmlFor="fleet-targets" className={LABEL_CLASS}>{t('pages.fleet.targets')}</label>
          <select id="fleet-targets" className={INPUT_CLASS} value={target} onChange={(event) => setTarget(event.target.value)}>
            <option value="all">{t('pages.fleet.targetAllCount', { count: data?.hosts.length ?? 0 })}</option>
            {(data?.overview.tags.length ?? 0) > 0 && (
              <optgroup label={t('pages.fleet.tags')}>
                {data!.overview.tags.map((tag) => <option key={tag} value={`tag:${tag}`}>{t('pages.fleet.targetTag', { tag })}</option>)}
              </optgroup>
            )}
            <optgroup label={t('pages.fleet.hosts')}>
              {data?.hosts.map((host) => <option key={host.id} value={host.id}>{host.hostname}</option>)}
            </optgroup>
          </select>
        </div>
        {(action === 'ban' || action === 'unban') && (
          <div>
            <label htmlFor="fleet-target-ip" className={LABEL_CLASS}>{t('pages.fleet.ipOrRange')}</label>
            <input id="fleet-target-ip" className={INPUT_CLASS} placeholder="203.0.113.7 / 203.0.113.0/24" value={params.target ?? ''} onChange={(event) => update({ target: event.target.value })} />
          </div>
        )}
        {action === 'ban' && (
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label htmlFor="fleet-duration" className={LABEL_CLASS}>{t('pages.decisions.duration')}</label>
              <input id="fleet-duration" className={INPUT_CLASS} placeholder="4h" value={params.duration ?? ''} onChange={(event) => update({ duration: event.target.value })} />
              <p className="mt-1 text-xs text-gray-500">{t('pages.fleet.durationHint')}</p>
            </div>
            <div>
              <label htmlFor="fleet-reason" className={LABEL_CLASS}>{t('pages.decisions.reason')}</label>
              <input id="fleet-reason" className={INPUT_CLASS} value={params.reason ?? ''} onChange={(event) => update({ reason: event.target.value })} />
            </div>
          </div>
        )}
        {(action === 'hub_install' || action === 'hub_remove') && (
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label htmlFor="fleet-hub-kind" className={LABEL_CLASS}>{t('pages.fleet.hubKind')}</label>
              <select id="fleet-hub-kind" className={INPUT_CLASS} value={params.kind} onChange={(event) => update({ kind: event.target.value })}>
                {FLEET_HUB_KINDS.map((kind) => <option key={kind} value={kind}>{kind}</option>)}
              </select>
            </div>
            <div>
              <label htmlFor="fleet-hub-name" className={LABEL_CLASS}>{t('pages.fleet.hubName')}</label>
              <input id="fleet-hub-name" className={INPUT_CLASS} placeholder="crowdsecurity/nginx" value={params.name ?? ''} onChange={(event) => update({ name: event.target.value })} />
            </div>
          </div>
        )}
        {RELOAD_ACTIONS.includes(action) && (
          <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
            <input type="checkbox" className="h-4 w-4 rounded border-gray-300 text-primary-600 focus:ring-primary-500" checked={reload} onChange={(event) => setReload(event.target.checked)} />
            {t('pages.fleet.reloadAfter')}
          </label>
        )}
        {error && <p role="alert" className="text-sm text-red-600 dark:text-red-400">{error}</p>}
        <div className="flex justify-end gap-3 pt-2">
          <button type="button" className={SECONDARY_BUTTON} onClick={onClose}>{t('common.cancel')}</button>
          <button type="submit" className={PRIMARY_BUTTON} disabled={submitting}>
            <Play className="h-4 w-4" aria-hidden="true" />
            {submitting ? t('pages.fleet.queueing') : t('pages.fleet.queueAction')}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function EnrollModal({ onClose }: { onClose: () => void }) {
  const { t } = useI18n();
  const toast = useToast();
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmRotate, setConfirmRotate] = useState(false);
  const serverUrl = `${window.location.origin}${getBasePath()}`;

  useEffect(() => {
    let cancelled = false;
    fetchFleetEnrollment()
      .then((result) => { if (!cancelled) setToken(result.token); })
      .catch((reason: Error) => { if (!cancelled) setError(reason.message); });
    return () => { cancelled = true; };
  }, []);

  const copy = (text: string) => {
    void navigator.clipboard?.writeText(text).then(() => toast.addToast(t('pages.fleet.copied'), 'success'));
  };

  const rotate = async () => {
    try {
      setToken((await rotateFleetEnrollment()).token);
      setConfirmRotate(false);
      toast.addToast(t('pages.fleet.tokenRotated'), 'success');
    } catch (reason) {
      setError((reason as Error).message);
    }
  };

  const block = (title: string, command: string) => (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <p className="text-sm font-medium text-gray-700 dark:text-gray-300">{title}</p>
        <button type="button" className="inline-flex items-center gap-1 text-xs text-primary-600 hover:underline dark:text-primary-400" onClick={() => copy(command)}>
          <Copy className="h-3.5 w-3.5" aria-hidden="true" />{t('pages.fleet.copy')}
        </button>
      </div>
      <pre className="overflow-x-auto rounded-md bg-gray-900 p-3 text-xs text-gray-100">{command}</pre>
    </div>
  );

  return (
    <Modal isOpen onClose={onClose} title={t('pages.fleet.addHost')} maxWidth="max-w-2xl">
      <div className="space-y-4 text-sm text-gray-600 dark:text-gray-300">
        <p>{t('pages.fleet.enrollIntro')}</p>
        {error && <p role="alert" className="text-red-600 dark:text-red-400">{error}</p>}
        {token && (
          <>
            {block(t('pages.fleet.enrollPackage'), fleetAgentCommand(serverUrl, token, false))}
            {block(t('pages.fleet.enrollDocker'), fleetAgentCommand(serverUrl, token, true))}
            <p className="text-xs text-gray-500">{t('pages.fleet.enrollService')}</p>
            <div className="flex flex-wrap items-center gap-3 rounded-md border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800 dark:border-amber-900/50 dark:bg-amber-900/20 dark:text-amber-300">
              <KeyRound className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span className="flex-1">{t('pages.fleet.tokenWarning')}</span>
              {confirmRotate ? (
                <button type="button" className={DANGER_BUTTON} onClick={() => void rotate()}>{t('pages.fleet.confirmRotate')}</button>
              ) : (
                <button type="button" className={SECONDARY_BUTTON} onClick={() => setConfirmRotate(true)}>{t('pages.fleet.rotateToken')}</button>
              )}
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}

type HostTab = 'decisions' | 'alerts' | 'bouncers' | 'machines' | 'collections' | 'errors';

function HostModal({ hostId, permissions, onClose, onAction, onRemoved }: {
  hostId: string;
  permissions: Permissions;
  onClose: () => void;
  onAction: (preset: ActionPreset) => void;
  onRemoved: () => void;
}) {
  const { t } = useI18n();
  const toast = useToast();
  const { refreshSignal } = useRefresh();
  const [host, setHost] = useState<FleetHostDetail | null>(null);
  const [tab, setTab] = useState<HostTab>('decisions');
  const [confirmRemove, setConfirmRemove] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const load = () => fetchFleetHost(hostId).then((detail) => { if (!cancelled) setHost(detail); }).catch(() => undefined);
    void load();
    const timer = window.setInterval(load, FLEET_POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [hostId, refreshSignal]);

  const queue = async (request: CreateFleetCommandRequest) => {
    try {
      await createFleetCommand(request);
      toast.addToast(t('pages.fleet.queued', { count: 1 }), 'success');
    } catch (reason) {
      toast.addToast((reason as Error).message, 'danger');
    }
  };

  const remove = async () => {
    try {
      await deleteFleetHost(hostId);
      toast.addToast(t('pages.fleet.hostRemoved'), 'success');
      onRemoved();
    } catch (reason) {
      toast.addToast((reason as Error).message, 'danger');
    }
  };

  const snapshot = host?.snapshot;
  const tabs: Array<[HostTab, number]> = [
    ['decisions', snapshot?.decisions_total ?? 0],
    ['alerts', snapshot?.alerts.length ?? 0],
    ['bouncers', snapshot?.bouncers.length ?? 0],
    ['machines', snapshot?.machines.length ?? 0],
    ['collections', snapshot?.collections.length ?? 0],
    ['errors', Object.keys(snapshot?.errors ?? {}).length],
  ];

  let body: ReactNode = null;
  if (host && tab === 'decisions') {
    body = (
      <DataTable headers={[t('tableColumns.value'), t('tableColumns.type'), t('tableColumns.origin'), t('pages.fleet.expiresIn'), t('tableColumns.scenario'), '']}>
        {snapshot?.decisions.length ? snapshot.decisions.map((decision) => (
          <tr key={`${decision.id}-${decision.value}`}>
            <td className={`${TD_CLASS} font-mono`}>{decision.value}</td>
            <td className={TD_CLASS}>{decision.type}</td>
            <td className={TD_CLASS}>{decision.origin}</td>
            <td className={TD_CLASS}>{decision.duration}</td>
            <td className={`${TD_CLASS} max-w-xs truncate`} title={decision.scenario}>{decision.scenario}</td>
            <td className={`${TD_CLASS} text-right`}>
              {permissions.enforcement && (
                <button type="button" className="text-xs font-medium text-red-600 hover:underline dark:text-red-400" onClick={() => void queue({ action: 'unban', targets: [host.id], params: { target: decision.value } })}>
                  {t('pages.fleet.actions.unban')}
                </button>
              )}
            </td>
          </tr>
        )) : <EmptyRow colSpan={6}>{t('pages.fleet.noDecisions')}</EmptyRow>}
      </DataTable>
    );
  } else if (host && tab === 'alerts') {
    body = (
      <DataTable headers={[t('pages.fleet.when'), t('tableColumns.scenario'), t('tableColumns.source'), t('pages.fleet.origin'), t('pages.fleet.events')]}>
        {snapshot?.alerts.length ? snapshot.alerts.map((alert) => (
          <tr key={alert.id}>
            <td className={TD_CLASS}><RelativeTime value={alert.created_at} /></td>
            <td className={TD_CLASS}>
              {alert.scenario}
              {alert.kind && alert.kind !== 'crowdsec' && <Badge variant="secondary" className="ml-2">{t('pages.fleet.manual')}</Badge>}
              {alert.simulated && <Badge variant="info" className="ml-2">{t('pages.fleet.simulated')}</Badge>}
            </td>
            <td className={`${TD_CLASS} font-mono`}>{alert.source_value}</td>
            <td className={TD_CLASS}><span className="inline-flex items-center gap-2"><CountryFlag code={alert.country} />{alert.as_name}</span></td>
            <td className={TD_CLASS}>{alert.events_count}</td>
          </tr>
        )) : <EmptyRow colSpan={5}>{t('pages.fleet.noAlerts')}</EmptyRow>}
      </DataTable>
    );
  } else if (host && tab === 'bouncers') {
    body = (
      <DataTable headers={[t('common.name'), 'IP', t('tableColumns.type'), t('pages.fleet.version'), t('pages.fleet.lastPull')]}>
        {snapshot?.bouncers.length ? snapshot.bouncers.map((bouncer) => (
          <tr key={bouncer.name}>
            <td className={TD_CLASS}>{bouncer.name}</td>
            <td className={`${TD_CLASS} font-mono`}>{bouncer.ip}</td>
            <td className={TD_CLASS}>{bouncer.type}</td>
            <td className={TD_CLASS}>{bouncer.version}</td>
            <td className={TD_CLASS}><RelativeTime value={bouncer.last_pull} /></td>
          </tr>
        )) : <EmptyRow colSpan={5}>{t('pages.fleet.noBouncers')}</EmptyRow>}
      </DataTable>
    );
  } else if (host && tab === 'machines') {
    body = (
      <DataTable headers={[t('common.name'), 'IP', t('pages.fleet.version'), t('pages.fleet.heartbeat'), t('pages.fleet.validated')]}>
        {snapshot?.machines.length ? snapshot.machines.map((machine) => (
          <tr key={machine.name}>
            <td className={TD_CLASS}>{machine.name}</td>
            <td className={`${TD_CLASS} font-mono`}>{machine.ip}</td>
            <td className={TD_CLASS}>{machine.version}</td>
            <td className={TD_CLASS}><RelativeTime value={machine.last_heartbeat} /></td>
            <td className={TD_CLASS}><Badge variant={machine.validated ? 'success' : 'danger'}>{machine.validated ? t('pages.fleet.yes') : t('pages.fleet.notValidated')}</Badge></td>
          </tr>
        )) : <EmptyRow colSpan={5}>{t('pages.fleet.noMachines')}</EmptyRow>}
      </DataTable>
    );
  } else if (host && tab === 'collections') {
    body = (
      <DataTable headers={[t('common.name'), t('pages.fleet.statusColumn'), t('pages.fleet.version'), '']}>
        {snapshot?.collections.length ? snapshot.collections.map((item) => (
          <tr key={item.name}>
            <td className={TD_CLASS}>{item.name}</td>
            <td className={TD_CLASS}><Badge variant={/update|tainted/i.test(item.status) ? 'warning' : 'secondary'}>{item.status}</Badge></td>
            <td className={TD_CLASS}>{item.local_version}</td>
            <td className={`${TD_CLASS} text-right`}>
              {permissions.settings && (
                <button type="button" className="text-xs font-medium text-red-600 hover:underline dark:text-red-400" onClick={() => void queue({ action: 'hub_remove', targets: [host.id], params: { kind: 'collections', name: item.name, reload: 'true' } })}>
                  {t('common.remove')}
                </button>
              )}
            </td>
          </tr>
        )) : <EmptyRow colSpan={4}>{t('pages.fleet.noCollections')}</EmptyRow>}
      </DataTable>
    );
  } else if (host && tab === 'errors') {
    const errors = Object.entries(snapshot?.errors ?? {});
    body = errors.length ? (
      <div className="space-y-3 p-4">
        {errors.map(([key, message]) => (
          <div key={key}>
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100">{key}</p>
            <pre className="mt-1 whitespace-pre-wrap break-all rounded-md bg-gray-50 p-2 text-xs text-gray-700 dark:bg-gray-900 dark:text-gray-300">{message}</pre>
          </div>
        ))}
      </div>
    ) : <p className="p-4 text-sm text-gray-500">{t('pages.fleet.noErrors')}</p>;
  }

  return (
    <Modal isOpen onClose={onClose} title={host?.hostname ?? t('app.loading')} maxWidth="max-w-5xl">
      {host && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-3 text-sm text-gray-600 dark:text-gray-300">
            <StatusBadge host={host} />
            <Tags tags={host.tags} />
            <span>{t('pages.fleet.crowdsecVersion')}: <span className="font-mono">{host.crowdsec_version ?? '—'}</span></span>
            <span>{t('pages.fleet.agentVersion')}: <span className="font-mono">{host.agent_version ?? '—'}</span></span>
            <span>{t('pages.fleet.address')}: <span className="font-mono">{host.remote_addr ?? '—'}</span></span>
            <span>{t('pages.fleet.lastSeen')}: <RelativeTime value={host.last_seen_at} /></span>
            <span>{t('pages.fleet.snapshot')}: <RelativeTime value={host.snapshot_at} /></span>
            {host.instance_id && (
              <Link className="text-primary-600 hover:underline dark:text-primary-400" to={`/alerts?instance=${encodeURIComponent(host.instance_id)}`}>
                {t('pages.fleet.viewAlerts')}
              </Link>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex flex-wrap gap-1" role="tablist">
              {tabs.map(([key, count]) => (
                <button
                  key={key}
                  type="button"
                  role="tab"
                  aria-selected={tab === key}
                  onClick={() => setTab(key)}
                  className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${tab === key ? 'bg-primary-600 text-white' : 'text-gray-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700'}`}
                >
                  {t(`pages.fleet.tabs.${key}`)} <span className="opacity-75">{count}</span>
                </button>
              ))}
            </div>
            <div className="ml-auto flex flex-wrap gap-2">
              {permissions.settings && (
                <button type="button" className={SECONDARY_BUTTON} onClick={() => void queue({ action: 'refresh', targets: [host.id] })}>
                  <RefreshCw className="h-4 w-4" aria-hidden="true" />{t('pages.fleet.refreshNow')}
                </button>
              )}
              {(permissions.settings || permissions.enforcement) && (
                <button type="button" className={SECONDARY_BUTTON} onClick={() => onAction({ target: host.id })}>
                  <Play className="h-4 w-4" aria-hidden="true" />{t('pages.fleet.runAction')}
                </button>
              )}
              {permissions.settings && (confirmRemove ? (
                <button type="button" className={DANGER_BUTTON} onClick={() => void remove()}>
                  <Trash2 className="h-4 w-4" aria-hidden="true" />{t('pages.fleet.confirmRemoveHost')}
                </button>
              ) : (
                <button type="button" className={SECONDARY_BUTTON} onClick={() => setConfirmRemove(true)}>
                  <Trash2 className="h-4 w-4" aria-hidden="true" />{t('pages.fleet.removeHost')}
                </button>
              ))}
            </div>
          </div>
          {confirmRemove && <p className="text-sm text-red-600 dark:text-red-400">{t('pages.fleet.removeHostWarning')}</p>}
          <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700">{body}</div>
        </div>
      )}
    </Modal>
  );
}

export function Fleet() {
  const { t } = useI18n();
  const toast = useToast();
  const { refreshSignal } = useRefresh();
  const [data, setData] = useState<FleetResponse | null>(null);
  const [commands, setCommands] = useState<FleetCommand[]>([]);
  const [permissions, setPermissions] = useState<Permissions>({ enforcement: false, settings: false });
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionPreset, setActionPreset] = useState<ActionPreset | null>(null);
  const [enrollOpen, setEnrollOpen] = useState(false);
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [expandedCommand, setExpandedCommand] = useState<string | null>(null);
  const [reloadCount, setReloadCount] = useState(0);
  const reload = () => setReloadCount((count) => count + 1);

  useEffect(() => {
    let cancelled = false;
    fetchConfig().then((config) => {
      if (cancelled) return;
      setEnabled(config.fleet_enabled === true);
      setPermissions({
        enforcement: config.permissions?.can_manage_enforcement !== false,
        settings: config.permissions?.can_manage_settings !== false,
      });
    }).catch(() => { if (!cancelled) setEnabled(false); });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    const load = async () => {
      try {
        const [fleet, history] = await Promise.all([fetchFleet(), fetchFleetCommands()]);
        if (cancelled) return;
        setData(fleet);
        setCommands(history);
        setError(null);
      } catch (reason) {
        if (!cancelled) setError((reason as Error).message);
      }
    };
    void load();
    const timer = window.setInterval(() => void load(), FLEET_POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [enabled, refreshSignal, reloadCount]);

  const hostNames = useMemo(() => new Map((data?.hosts ?? []).map((host) => [host.id, host.hostname])), [data]);

  const submitCommand = async (request: CreateFleetCommandRequest) => {
    try {
      const command = await createFleetCommand(request);
      toast.addToast(t('pages.fleet.queued', { count: command.hosts.length }), 'success');
      setExpandedCommand(command.id);
      reload();
      return true;
    } catch (reason) {
      toast.addToast((reason as Error).message, 'danger');
      return false;
    }
  };

  if (enabled === null) return <div className="p-8 text-center text-gray-500">{t('app.loading')}</div>;

  if (!enabled) {
    return (
      <Card>
        <CardContent className="space-y-2 p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{t('pages.fleet.disabledTitle')}</h2>
          <p className="text-sm text-gray-600 dark:text-gray-300">{t('pages.fleet.disabledBody')}</p>
          <pre className="rounded-md bg-gray-900 p-3 text-xs text-gray-100">{'fleet:\n  enabled: true'}</pre>
        </CardContent>
      </Card>
    );
  }

  const overview = data?.overview;
  const canAct = permissions.enforcement || permissions.settings;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-gray-500">
          {overview ? t('pages.fleet.summary', { online: overview.online, hosts: overview.hosts }) : t('app.loading')}
        </p>
        <div className="flex flex-wrap gap-2">
          {permissions.settings && (
            <button type="button" className={SECONDARY_BUTTON} onClick={() => setEnrollOpen(true)}>
              <Plus className="h-4 w-4" aria-hidden="true" />{t('pages.fleet.addHost')}
            </button>
          )}
          {canAct && (
            <button type="button" className={PRIMARY_BUTTON} disabled={!data?.hosts.length} onClick={() => setActionPreset({})}>
              <Play className="h-4 w-4" aria-hidden="true" />{t('pages.fleet.runAction')}
            </button>
          )}
        </div>
      </div>

      {error && <p role="alert" className="text-sm text-red-600 dark:text-red-400">{error}</p>}

      {overview && (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
          <FleetTile icon={Server} title={t('pages.fleet.tiles.online')} value={`${overview.online}/${overview.hosts}`} detail={t('pages.fleet.tiles.onlineDetail')} tone={overview.online === overview.hosts ? 'success' : 'danger'} />
          <FleetTile icon={AlertTriangle} title={t('pages.fleet.tiles.attention')} value={overview.needs_attention} detail={t('pages.fleet.tiles.attentionDetail')} tone={overview.needs_attention ? 'warning' : 'success'} />
          <FleetTile icon={ShieldBan} title={t('pages.fleet.tiles.decisions')} value={overview.decisions.toLocaleString()} detail={t('pages.fleet.tiles.decisionsDetail')} />
          <FleetTile icon={Crosshair} title={t('pages.fleet.tiles.alerts')} value={overview.alerts.toLocaleString()} detail={t('pages.fleet.tiles.alertsDetail')} />
          <FleetTile icon={Plug} title={t('pages.fleet.tiles.bouncers')} value={overview.bouncers} detail={t('pages.fleet.tiles.bouncersDetail', { count: overview.stale_bouncers })} tone={overview.stale_bouncers ? 'warning' : 'neutral'} />
          <FleetTile icon={PackageCheck} title={t('pages.fleet.tiles.updates')} value={overview.updates_needed} detail={t('pages.fleet.tiles.updatesDetail')} tone={overview.updates_needed ? 'warning' : 'success'} />
        </div>
      )}

      <Card>
        <SectionTitle icon={Server}>{t('pages.fleet.hosts')}</SectionTitle>
        <DataTable headers={[
          t('pages.fleet.host'), t('pages.fleet.statusColumn'), t('pages.fleet.tags'), t('pages.fleet.crowdsecVersion'),
          t('pages.fleet.tabs.decisions'), t('pages.fleet.tabs.alerts'), t('pages.fleet.tabs.bouncers'), t('pages.fleet.tiles.updates'), t('pages.fleet.lastSeen'),
        ]}>
          {data?.hosts.length ? data.hosts.map((host) => (
            <tr
              key={host.id}
              className="cursor-pointer transition-colors hover:bg-gray-50 dark:hover:bg-gray-700/50"
              onClick={() => setSelectedHost(host.id)}
              onKeyDown={(event) => { if (event.key === 'Enter') setSelectedHost(host.id); }}
              tabIndex={0}
            >
              <td className={TD_CLASS}>
                <p className="font-medium text-gray-900 dark:text-white">{host.hostname}</p>
                <p className="text-xs text-gray-500">{host.remote_addr ?? ''}</p>
              </td>
              <td className={TD_CLASS}>
                <span className="flex items-center gap-2">
                  <StatusBadge host={host} />
                  {host.pending_commands > 0 && <Badge variant="info">{t('pages.fleet.pending', { count: host.pending_commands })}</Badge>}
                </span>
              </td>
              <td className={TD_CLASS}><Tags tags={host.tags} /></td>
              <td className={`${TD_CLASS} font-mono`}>{host.crowdsec_version ?? '—'}</td>
              <td className={TD_CLASS}>{host.decisions}</td>
              <td className={TD_CLASS}>{host.alerts}</td>
              <td className={TD_CLASS}>
                {host.bouncers}
                {host.stale_bouncers > 0 && <Badge variant="warning" className="ml-2">{t('pages.fleet.stale', { count: host.stale_bouncers })}</Badge>}
                {host.bouncers === 0 && host.status !== 'pending' && host.status !== 'offline' && <Badge variant="danger" className="ml-2">{t('pages.fleet.noEnforcement')}</Badge>}
              </td>
              <td className={TD_CLASS}>{host.updates_needed || ''}</td>
              <td className={TD_CLASS}><RelativeTime value={host.last_seen_at} /></td>
            </tr>
          )) : <EmptyRow colSpan={9}>{data ? t('pages.fleet.noHosts') : t('app.loading')}</EmptyRow>}
        </DataTable>
      </Card>

      <div className="grid gap-6 2xl:grid-cols-3">
        <Card className="2xl:col-span-2">
          <SectionTitle icon={Crosshair} aside={<span className="text-xs text-gray-500">{t('pages.fleet.attackersHint')}</span>}>
            {t('pages.fleet.attackers')}
          </SectionTitle>
          <DataTable headers={[t('tableColumns.source'), t('pages.fleet.origin'), t('pages.fleet.hosts'), t('pages.fleet.tabs.alerts'), t('pages.fleet.bannedOn'), t('pages.fleet.lastSeen'), '']}>
            {overview?.top_sources.length ? overview.top_sources.map((source) => {
              const missingBans = (data?.hosts.length ?? 0) - source.banned_on.length;
              return (
                <tr key={source.value}>
                  <td className={`${TD_CLASS} font-mono`}>{source.value}</td>
                  <td className={TD_CLASS}><span className="inline-flex items-center gap-2"><CountryFlag code={source.country} /><span className="max-w-[12rem] truncate" title={source.as_name}>{source.as_name}</span></span></td>
                  <td className={TD_CLASS} title={source.hosts.join(', ')}>
                    <span className={source.hosts.length > 1 ? 'font-semibold text-red-600 dark:text-red-400' : ''}>{source.hosts.length}</span>
                  </td>
                  <td className={TD_CLASS}>{source.alerts}</td>
                  <td className={TD_CLASS} title={source.banned_on.join(', ')}>{source.banned_on.length}/{data?.hosts.length ?? 0}</td>
                  <td className={TD_CLASS}><RelativeTime value={source.last_seen} /></td>
                  <td className={`${TD_CLASS} text-right`}>
                    {permissions.enforcement && missingBans > 0 && source.scope.toLowerCase() === 'ip' && (
                      <button type="button" className="text-xs font-medium text-red-600 hover:underline dark:text-red-400" onClick={() => setActionPreset({ action: 'ban', target: 'all', ip: source.value })}>
                        {t('pages.fleet.banEverywhere')}
                      </button>
                    )}
                  </td>
                </tr>
              );
            }) : <EmptyRow colSpan={7}>{t('pages.fleet.noAttackers')}</EmptyRow>}
          </DataTable>
        </Card>

        <Card>
          <SectionTitle icon={Layers}>{t('pages.fleet.versions')}</SectionTitle>
          <CardContent className="space-y-3">
            {overview?.versions.length ? overview.versions.map((entry) => (
              <div key={entry.version}>
                <div className="mb-1 flex justify-between text-sm">
                  <span className="font-mono text-gray-800 dark:text-gray-200">{entry.version}</span>
                  <span className="text-gray-500">{t('pages.fleet.hostCount', { count: entry.hosts })}</span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-gray-100 dark:bg-gray-700">
                  <div className="h-full rounded-full bg-primary-500" style={{ width: `${(entry.hosts / Math.max(1, overview.hosts)) * 100}%` }} />
                </div>
              </div>
            )) : <p className="text-sm text-gray-500">{t('common.noDataAvailable')}</p>}
            {(overview?.versions.length ?? 0) > 1 && <p className="text-xs text-amber-600 dark:text-amber-400">{t('pages.fleet.mixedVersions')}</p>}
          </CardContent>
        </Card>
      </div>

      <Card>
        <SectionTitle icon={Activity}>{t('pages.fleet.activity')}</SectionTitle>
        {commands.length ? (
          <ul className="divide-y divide-gray-200 dark:divide-gray-700">
            {commands.map((command) => {
              const summary = summarizeFleetCommand(command);
              const expanded = expandedCommand === command.id;
              return (
                <li key={command.id}>
                  <button
                    type="button"
                    aria-expanded={expanded}
                    className="flex w-full flex-wrap items-center gap-x-4 gap-y-1 px-6 py-3 text-left text-sm hover:bg-gray-50 dark:hover:bg-gray-700/50"
                    onClick={() => setExpandedCommand(expanded ? null : command.id)}
                  >
                    <span className="font-medium text-gray-900 dark:text-white">{describeFleetCommand(command, t)}</span>
                    <span className="text-gray-500">{describeFleetTargets(command.targets, hostNames, t)}</span>
                    <span className="text-gray-500">{command.created_by ?? ''} · <RelativeTime value={command.created_at} /></span>
                    <span className="ml-auto flex gap-2">
                      {summary.ok > 0 && <Badge variant="success">{t('pages.fleet.commandStates.ok')} {summary.ok}</Badge>}
                      {summary.failed > 0 && <Badge variant="danger">{t('pages.fleet.commandStates.failed')} {summary.failed}</Badge>}
                      {summary.pending > 0 && <Badge variant="warning">{t('pages.fleet.commandStates.pending')} {summary.pending}</Badge>}
                      {summary.expired > 0 && <Badge variant="secondary">{t('pages.fleet.commandStates.expired')} {summary.expired}</Badge>}
                    </span>
                  </button>
                  {expanded && (
                    <div className="bg-gray-50 px-6 pb-4 dark:bg-gray-900/30">
                      {command.hosts.map((host) => (
                        <div key={host.host_id} className="flex flex-col gap-1 border-t border-gray-200 py-2 text-sm first:border-t-0 dark:border-gray-700 sm:flex-row sm:items-start sm:gap-4">
                          <span className="w-40 shrink-0 font-medium text-gray-800 dark:text-gray-200">{host.hostname}</span>
                          <Badge variant={fleetCommandStateTone(host.state)}>{t(`pages.fleet.commandStates.${host.state}`)}</Badge>
                          {host.output && <pre className="min-w-0 flex-1 whitespace-pre-wrap break-all text-xs text-gray-600 dark:text-gray-400">{host.output}</pre>}
                        </div>
                      ))}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        ) : <p className="px-6 py-6 text-sm text-gray-500">{t('pages.fleet.noActivity')}</p>}
      </Card>

      {actionPreset && (
        <ActionModal
          preset={actionPreset}
          data={data}
          permissions={permissions}
          onClose={() => setActionPreset(null)}
          onSubmit={submitCommand}
        />
      )}
      {enrollOpen && <EnrollModal onClose={() => setEnrollOpen(false)} />}
      {selectedHost && (
        <HostModal
          key={selectedHost}
          hostId={selectedHost}
          permissions={permissions}
          onClose={() => setSelectedHost(null)}
          onAction={(preset) => { setSelectedHost(null); setActionPreset(preset); }}
          onRemoved={() => { setSelectedHost(null); reload(); }}
        />
      )}
    </div>
  );
}
