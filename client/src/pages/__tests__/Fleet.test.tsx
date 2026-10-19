import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, test, vi } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import type { FleetCommand, FleetHostDetail, FleetResponse } from '../../../../shared/fleet';
import { Fleet } from '../Fleet';

const api = vi.hoisted(() => ({
  fetchConfig: vi.fn(),
  fetchFleet: vi.fn(),
  fetchFleetCommands: vi.fn(),
  fetchFleetHost: vi.fn(),
  createFleetCommand: vi.fn(),
  deleteFleetHost: vi.fn(),
  fetchFleetEnrollment: vi.fn(),
  rotateFleetEnrollment: vi.fn(),
}));
const addToast = vi.hoisted(() => vi.fn());

vi.mock('../../lib/api', () => api);
vi.mock('../../contexts/useRefresh', () => ({ useRefresh: () => ({ refreshSignal: 0 }) }));
vi.mock('../../contexts/useToast', () => ({ useToast: () => ({ addToast }) }));

const host = {
  id: 'h1',
  hostname: 'web01',
  tags: ['web', 'prod'],
  instance_id: 'web01',
  status: 'healthy' as const,
  enrolled_at: '2026-10-19T07:00:00Z',
  last_seen_at: new Date().toISOString(),
  remote_addr: '10.0.0.5',
  agent_version: '0.2.0',
  crowdsec_version: 'v1.8.1',
  snapshot_at: new Date().toISOString(),
  decisions: 1,
  alerts: 1,
  bouncers: 0,
  stale_bouncers: 0,
  collections: 1,
  updates_needed: 1,
  errors: 0,
  pending_commands: 1,
};

const fleet: FleetResponse = {
  hosts: [host, { ...host, id: 'h2', hostname: 'db01', tags: ['db'], status: 'lapi_down', instance_id: null, bouncers: 1, stale_bouncers: 1, pending_commands: 0 }],
  overview: {
    hosts: 2, online: 2, needs_attention: 1, decisions: 2, alerts: 2, bouncers: 1, stale_bouncers: 1, updates_needed: 2,
    versions: [{ version: 'v1.8.1', hosts: 1 }, { version: 'v1.7.0', hosts: 1 }],
    tags: ['db', 'prod', 'web'],
    top_sources: [{ value: '203.0.113.7', scope: 'Ip', country: 'DE', as_name: 'Example AS', alerts: 3, hosts: ['web01', 'db01'], banned_on: ['web01'], scenarios: ['crowdsecurity/ssh-bf'], last_seen: new Date().toISOString() }],
  },
};

const commands: FleetCommand[] = [{
  id: 'c1', action: 'hub_install', params: { kind: 'collections', name: 'crowdsecurity/nginx' }, targets: ['tag:web'],
  created_at: new Date().toISOString(), created_by: 'admin',
  hosts: [
    { host_id: 'h1', hostname: 'web01', state: 'failed', output: 'collection not found', updated_at: new Date().toISOString() },
    { host_id: 'h2', hostname: 'db01', state: 'queued', output: null, updated_at: new Date().toISOString() },
  ],
}];

const detail: FleetHostDetail = {
  ...host,
  snapshot: {
    collected_at: '', crowdsec_version: 'v1.8.1', lapi_healthy: true, decisions_total: 1,
    decisions: [{ id: 1, origin: 'crowdsec', type: 'ban', scope: 'Ip', value: '203.0.113.7', duration: '3h', scenario: 'crowdsecurity/ssh-bf' }],
    alerts: [{ id: 1, scenario: 'crowdsecurity/ssh-bf', created_at: new Date().toISOString(), events_count: 6, source_scope: 'Ip', source_value: '203.0.113.7', country: 'DE', as_name: 'Example AS', kind: 'cscli', simulated: true }],
    bouncers: [], machines: [{ name: 'localhost', ip: '127.0.0.1', version: 'v1.8.1', last_heartbeat: '', validated: true }],
    collections: [{ name: 'crowdsecurity/linux', status: 'enabled,update-available', local_version: '0.2' }],
    errors: { metrics: 'timeout' },
  },
};

function renderFleet() {
  return render(<BrowserRouter><Fleet /></BrowserRouter>);
}

beforeEach(() => {
  vi.clearAllMocks();
  api.fetchConfig.mockResolvedValue({ fleet_enabled: true, permissions: { can_manage_enforcement: true, can_manage_settings: true } });
  api.fetchFleet.mockResolvedValue(fleet);
  api.fetchFleetCommands.mockResolvedValue(commands);
  api.fetchFleetHost.mockResolvedValue(detail);
  api.createFleetCommand.mockResolvedValue({ ...commands[0], id: 'c2', hosts: [commands[0].hosts[0]] });
  api.deleteFleetHost.mockResolvedValue(undefined);
  api.fetchFleetEnrollment.mockResolvedValue({ token: 'tok123' });
  api.rotateFleetEnrollment.mockResolvedValue({ token: 'tok456' });
});

describe('Fleet page', () => {
  test('explains how to enable fleet management when it is off', async () => {
    api.fetchConfig.mockResolvedValue({ fleet_enabled: false });
    renderFleet();
    expect(await screen.findByText('Fleet management is turned off')).toBeInTheDocument();
    expect(api.fetchFleet).not.toHaveBeenCalled();
  });

  test('shows hosts, cross-host attackers, versions and activity', async () => {
    renderFleet();
    expect(await screen.findByText('2 of 2 hosts online')).toBeInTheDocument();
    expect(screen.getAllByText('web01').length).toBeGreaterThan(0);
    expect(screen.getByText('LAPI down')).toBeInTheDocument();
    expect(screen.getByText('No bouncer')).toBeInTheDocument();
    expect(screen.getByText('Stale: 1')).toBeInTheDocument();
    expect(screen.getByText('Pending: 1')).toBeInTheDocument();
    expect(screen.getByText('203.0.113.7')).toBeInTheDocument();
    expect(screen.getByText('1/2')).toBeInTheDocument();
    expect(screen.getByText('Hosts run different CrowdSec versions.')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /Install hub item: crowdsecurity\/nginx/ }));
    expect(screen.getByText('collection not found')).toBeInTheDocument();
  });

  test('queues a fleet-wide ban from the attackers table', async () => {
    renderFleet();
    await userEvent.click(await screen.findByRole('button', { name: 'Ban everywhere' }));
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByLabelText('IP address or CIDR range')).toHaveValue('203.0.113.7');
    await userEvent.clear(within(dialog).getByLabelText('Duration'));
    await userEvent.type(within(dialog).getByLabelText('Duration'), 'forever');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Queue action' }));
    expect(within(dialog).getByRole('alert')).toHaveTextContent('Duration must look like');
    expect(api.createFleetCommand).not.toHaveBeenCalled();

    await userEvent.clear(within(dialog).getByLabelText('Duration'));
    await userEvent.type(within(dialog).getByLabelText('Duration'), '24h');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Queue action' }));
    await waitFor(() => expect(api.createFleetCommand).toHaveBeenCalledWith({
      action: 'ban', targets: ['all'], params: { target: '203.0.113.7', duration: '24h' },
    }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(addToast).toHaveBeenCalledWith(expect.stringContaining('Queued for hosts: 1'), 'success');
  });

  test('installs a hub item on a tag and reports server errors', async () => {
    api.createFleetCommand.mockRejectedValueOnce(new Error('No hosts match those targets'));
    renderFleet();
    await userEvent.click(await screen.findByRole('button', { name: 'Run action' }));
    const dialog = screen.getByRole('dialog');
    await userEvent.selectOptions(within(dialog).getByLabelText('Action'), 'hub_install');
    await userEvent.selectOptions(within(dialog).getByLabelText('Targets'), 'tag:web');
    await userEvent.type(within(dialog).getByLabelText('Hub item name'), 'crowdsecurity/nginx');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Queue action' }));
    await waitFor(() => expect(addToast).toHaveBeenCalledWith('No hosts match those targets', 'danger'));
    expect(api.createFleetCommand).toHaveBeenCalledWith({
      action: 'hub_install', targets: ['tag:web'], params: { kind: 'collections', name: 'crowdsecurity/nginx', reload: 'true' },
    });
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });

  test('hides write actions for read-only users', async () => {
    api.fetchConfig.mockResolvedValue({ fleet_enabled: true, permissions: { can_manage_enforcement: false, can_manage_settings: false } });
    renderFleet();
    expect(await screen.findByText('203.0.113.7')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Run action' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add host' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Ban everywhere' })).not.toBeInTheDocument();
  });

  test('shows host details and removes a host after confirmation', async () => {
    renderFleet();
    await userEvent.click((await screen.findAllByText('web01'))[0]);
    const dialog = await screen.findByRole('dialog', { name: 'web01' });
    expect(within(dialog).getByRole('link', { name: 'View alerts for this instance' })).toHaveAttribute('href', '/alerts?instance=web01');

    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove ban' }));
    expect(api.createFleetCommand).toHaveBeenCalledWith({ action: 'unban', targets: ['h1'], params: { target: '203.0.113.7' } });

    await userEvent.click(within(dialog).getByRole('tab', { name: /Alerts/ }));
    expect(within(dialog).getByText('Manual')).toBeInTheDocument();
    expect(within(dialog).getByText('Simulated')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('tab', { name: /Bouncers/ }));
    expect(within(dialog).getByText(/No bouncers registered/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('tab', { name: /Machines/ }));
    expect(within(dialog).getByText('Yes')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('tab', { name: /Collections/ }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove' }));
    expect(api.createFleetCommand).toHaveBeenLastCalledWith({ action: 'hub_remove', targets: ['h1'], params: { kind: 'collections', name: 'crowdsecurity/linux', reload: 'true' } });
    await userEvent.click(within(dialog).getByRole('tab', { name: /Errors/ }));
    expect(within(dialog).getByText('timeout')).toBeInTheDocument();

    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove host' }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Confirm removal' }));
    await waitFor(() => expect(api.deleteFleetHost).toHaveBeenCalledWith('h1'));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  test('shows enrollment commands and rotates the token', async () => {
    renderFleet();
    await userEvent.click(await screen.findByRole('button', { name: 'Add host' }));
    const dialog = screen.getByRole('dialog');
    expect(await within(dialog).findAllByText(/-enroll-token tok123/)).toHaveLength(2);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Rotate token' }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Confirm rotation' }));
    expect(await within(dialog).findAllByText(/-enroll-token tok456/)).toHaveLength(2);
  });
});
