import net from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { classifyError, probeTcp, probeTcpWithRetry, scanHost } from '../src/scanner/tcp.js';
import type { TcpProbeResult } from '../src/types.js';

const LOOPBACK = '127.0.0.1';
// RFC 5737 TEST-NET-1: reserved for documentation, never routed. SYNs to it vanish,
// which is exactly what a dropping firewall looks like from the scanner's side.
const BLACKHOLE = '192.0.2.1';

const servers: net.Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

/** Start a listener on an OS-chosen port. Port 0 means "pick a free one". */
function listen(onConnection?: (s: net.Socket) => void): Promise<{ server: net.Server; port: number }> {
  return new Promise((resolve) => {
    const server = net.createServer(onConnection);
    servers.push(server);
    server.listen(0, LOOPBACK, () => {
      resolve({ server, port: (server.address() as net.AddressInfo).port });
    });
  });
}

/** A port that was free a moment ago and has nothing listening now. */
async function closedPort(): Promise<number> {
  const { server, port } = await listen();
  servers.pop();
  await new Promise((r) => server.close(r));
  return port;
}

describe('probeTcp', () => {
  it('reports open when the handshake completes', async () => {
    const { port } = await listen();
    const r = await probeTcp(LOOPBACK, port, { timeoutMs: 1000 });
    expect(r).toMatchObject({ host: LOOPBACK, port, state: 'open', reason: 'syn-ack' });
    expect(r.errorCode).toBeUndefined();
  });

  it('reports closed when the target answers with RST', async () => {
    const port = await closedPort();
    const r = await probeTcp(LOOPBACK, port, { timeoutMs: 1000 });
    expect(r).toMatchObject({ state: 'closed', reason: 'conn-refused', errorCode: 'ECONNREFUSED' });
  });

  it('reports filtered when nothing answers before the deadline', async () => {
    const r = await probeTcp(BLACKHOLE, 80, { timeoutMs: 200 });
    expect(r.state).toBe('filtered');
    // Offline machines get ENETUNREACH immediately instead of silence; both mean filtered.
    expect(['no-response', 'net-unreach', 'host-unreach']).toContain(r.reason);
    expect(r.latencyMs).toBeLessThan(1000);
  });

  it('closes the connection it opened (no leaked sockets on open ports)', async () => {
    let serverSide!: Promise<void>;
    const { port } = await listen((s) => {
      serverSide = new Promise((r) => s.on('close', () => r()));
      s.on('error', () => {}); // a RST from the client surfaces here as ECONNRESET
    });
    await probeTcp(LOOPBACK, port, { timeoutMs: 1000 });
    // If probeTcp forgot to destroy the socket, this would hang until the test times out.
    await serverSide;
  });

  it('measures latency', async () => {
    const { port } = await listen();
    const r = await probeTcp(LOOPBACK, port, { timeoutMs: 1000 });
    expect(r.latencyMs).toBeGreaterThanOrEqual(0);
    expect(r.latencyMs).toBeLessThan(1000);
  });
});

describe('classifyError', () => {
  it.each([
    ['ECONNREFUSED', 'closed', 'conn-refused'],
    ['ECONNRESET', 'closed', 'reset'],
    ['ETIMEDOUT', 'filtered', 'no-response'],
    ['EHOSTUNREACH', 'filtered', 'host-unreach'],
    ['ENETUNREACH', 'filtered', 'net-unreach'],
    ['EMFILE', 'error', 'local-error'],
    ['EADDRNOTAVAIL', 'error', 'local-error'],
    [undefined, 'error', 'local-error'],
  ])('%s -> %s (%s)', (code, state, reason) => {
    expect(classifyError(code)).toEqual({ state, reason });
  });
});

describe('probeTcpWithRetry', () => {
  it('does not retry definitive answers (open, closed)', async () => {
    const { port: open } = await listen();
    const closed = await closedPort();
    let calls = 0;
    const opts = { timeoutMs: 1000, retries: 3, beforeAttempt: async () => void calls++ };
    expect(await probeTcpWithRetry(LOOPBACK, open, opts)).toMatchObject({ state: 'open', attempts: 1 });
    expect(await probeTcpWithRetry(LOOPBACK, closed, opts)).toMatchObject({ state: 'closed', attempts: 1 });
    expect(calls).toBe(2);
  });

  it('retries silence up to `retries` times, calling beforeAttempt each time', async () => {
    let calls = 0;
    const r = await probeTcpWithRetry(BLACKHOLE, 80, {
      timeoutMs: 100,
      retries: 2,
      beforeAttempt: async () => void calls++,
    });
    expect(r.state).toBe('filtered');
    if (r.reason === 'no-response') {
      expect(r.attempts).toBe(3);
      expect(calls).toBe(3);
    } else {
      // Offline machine: ENETUNREACH is an answer, so no retries.
      expect(r.attempts).toBe(1);
    }
  });

  it('makes exactly one attempt when retries is 0', async () => {
    const r = await probeTcpWithRetry(BLACKHOLE, 80, { timeoutMs: 100, retries: 0 });
    expect(r.attempts).toBe(1);
  });
});

describe('scanHost', () => {
  async function collect(gen: AsyncIterable<TcpProbeResult>): Promise<TcpProbeResult[]> {
    const out: TcpProbeResult[] = [];
    for await (const r of gen) out.push(r);
    return out.sort((a, b) => a.port - b.port);
  }

  it('returns one result per port', async () => {
    const { port: open } = await listen();
    const closed = await closedPort();
    const results = await collect(
      scanHost(LOOPBACK, [open, closed], { timeoutMs: 1000, retries: 0, concurrency: 10 }),
    );
    const byPort = Object.fromEntries(results.map((r) => [r.port, r.state]));
    expect(byPort).toEqual({ [open]: 'open', [closed]: 'closed' });
  });

  // The whole point of Stage 2: filtered ports wait in parallel, not one after another.
  // Sequentially this would take 20 x 300 ms = 6 s.
  it('overlaps timeouts: 20 filtered ports take about one timeout, not twenty', async () => {
    const ports = Array.from({ length: 20 }, (_, i) => i + 1);
    const start = performance.now();
    const results = await collect(scanHost(BLACKHOLE, ports, { timeoutMs: 300, retries: 0, concurrency: 20 }));
    const elapsed = performance.now() - start;
    expect(results).toHaveLength(20);
    expect(results.every((r) => r.state === 'filtered')).toBe(true);
    expect(elapsed).toBeLessThan(1500);
  });
});
