import { afterEach, describe, expect, test, vi } from 'vitest';
import {
  createFleetCommand,
  deleteFleetHost,
  fetchFleet,
  fetchFleetCommands,
  fetchFleetEnrollment,
  fetchFleetHost,
  rotateFleetEnrollment,
} from '../api';

function mockFetch(handler: typeof fetch): void {
  Object.defineProperty(globalThis, 'fetch', { configurable: true, writable: true, value: handler });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('fleet api', () => {
  test('calls the fleet endpoints', async () => {
    const fetchMock = vi.fn(async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
      const url = String(input);
      if (init?.method === 'DELETE') return new Response(null, { status: 204 });
      if (url.endsWith('/api/fleet')) return Response.json({ hosts: [], overview: { hosts: 0 } });
      if (url.includes('/api/fleet/hosts/')) return Response.json({ id: 'a b' });
      if (url.endsWith('/api/fleet/commands') && init?.method === 'POST') return Response.json({ id: 'c1' }, { status: 201 });
      if (url.endsWith('/api/fleet/commands')) return Response.json([]);
      return Response.json({ token: 't' });
    });
    mockFetch(fetchMock);

    await expect(fetchFleet()).resolves.toMatchObject({ hosts: [] });
    await expect(fetchFleetHost('a b')).resolves.toEqual({ id: 'a b' });
    await expect(fetchFleetCommands()).resolves.toEqual([]);
    await expect(createFleetCommand({ action: 'refresh', targets: ['all'] })).resolves.toEqual({ id: 'c1' });
    await expect(deleteFleetHost('a b')).resolves.toBeUndefined();
    await expect(fetchFleetEnrollment()).resolves.toEqual({ token: 't' });
    await expect(rotateFleetEnrollment()).resolves.toEqual({ token: 't' });

    const calls = fetchMock.mock.calls.map(([input, init]) => `${init?.method ?? 'GET'} ${String(input)}`);
    expect(calls).toContain('GET /api/fleet/hosts/a%20b');
    expect(calls).toContain('DELETE /api/fleet/hosts/a%20b');
    expect(calls).toContain('POST /api/fleet/enrollment/rotate');
    const post = fetchMock.mock.calls.find(([, init]) => init?.method === 'POST' && String(init.body).includes('refresh'));
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({ action: 'refresh', targets: ['all'] });
  });

  test('surfaces server error messages', async () => {
    mockFetch(vi.fn(async () => Response.json({ error: 'No hosts match those targets' }, { status: 400 })));
    await expect(createFleetCommand({ action: 'refresh', targets: ['tag:none'] })).rejects.toThrow('No hosts match those targets');
    mockFetch(vi.fn(async () => Response.json({ error: 'Read-only mode is enabled' }, { status: 403 })));
    await expect(fetchFleetEnrollment()).rejects.toThrow('Read-only mode is enabled');
    mockFetch(vi.fn(async () => new Response('nope', { status: 500 })));
    await expect(fetchFleet()).rejects.toThrow('Failed to fetch fleet');
  });
});
