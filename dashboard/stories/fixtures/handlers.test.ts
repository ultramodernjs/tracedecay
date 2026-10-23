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
    // Matched catch-alls must also refuse unknown paths without network I/O.
    await expect(fetch('http://localhost/api/not-a-fixture')).rejects.toThrow();
    await expect(
      fetch('http://localhost/api/work/not-a-fixture', { method: 'POST' }),
    ).rejects.toThrow();
  });
});
