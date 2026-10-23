import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { fixtureServer } from './handlers.ts';

const server = fixtureServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterAll(() => server.close());

describe('fixture handlers', () => {
  it('answer a modelled route and refuse a path the daemon does not bind', async () => {
    const bound = await fetch('http://localhost/api/plugins/holographic?limit=100');
    expect(bound.status).toBe(200);
    expect(((await bound.json()) as { domain_state: string }).domain_state).toBe('ready');

    await expect(fetch('http://localhost/api/plugins/holographic/?limit=100')).rejects.toThrow();
  });

  it('never bypasses an unmodelled path to a listening local service', async () => {
    let networkRequests = 0;
    const ambient = createServer((_request, response) => {
      networkRequests += 1;
      response.end('not a fixture');
    });
    await new Promise<void>((resolve, reject) => {
      ambient.once('error', reject);
      ambient.listen(0, '127.0.0.1', resolve);
    });
    try {
      const base = `http://127.0.0.1:${(ambient.address() as AddressInfo).port}`;
      await expect(fetch(`${base}/api/not-a-fixture`)).rejects.toThrow();
      await expect(
        fetch(`${base}/api/work/not-a-fixture`, { method: 'POST' }),
      ).rejects.toThrow();
      expect(networkRequests).toBe(0);
    } finally {
      await new Promise<void>((resolve, reject) => {
        ambient.close((error) => (error ? reject(error) : resolve()));
      });
    }
  });
});
