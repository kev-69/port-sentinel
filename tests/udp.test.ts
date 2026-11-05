import dgram from 'node:dgram';
import { afterEach, describe, expect, it } from 'vitest';
import { classifyUdpError, probeUdp, probeUdpWithRetry, scanUdpHost } from '../src/scanner/udp.js';
import type { UdpProbeResult } from '../src/types.js';

const LOOPBACK = '127.0.0.1';
const sockets: dgram.Socket[] = [];

afterEach(async () => {
  await Promise.all(sockets.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))));
});

/** Start a UDP responder that replies to each datagram with `reply(msg)` (or nothing). */
function serve(reply: (msg: Buffer) => Buffer | undefined): Promise<number> {
  return new Promise((resolve) => {
    const server = dgram.createSocket('udp4');
    sockets.push(server);
    server.on('message', (msg, rinfo) => {
      const out = reply(msg);
      if (out) server.send(out, rinfo.port, rinfo.address);
    });
    server.bind(0, LOOPBACK, () => resolve((server.address() as import('node:net').AddressInfo).port));
  });
}

/** A UDP port with nothing bound (bind then close to learn a free port). */
function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = dgram.createSocket('udp4');
    s.bind(0, LOOPBACK, () => {
      const port = (s.address() as import('node:net').AddressInfo).port;
      s.close(() => resolve(port));
    });
  });
}

describe('probeUdp', () => {
  it('reports open when any reply comes back', async () => {
    const port = await serve(() => Buffer.from('pong'));
    const r = await probeUdp(LOOPBACK, port, { timeoutMs: 500 });
    expect(r.state).toBe('open');
    expect(r.reason).toBe('udp-response');
  });

  it('validates a DNS reply when probing port 53 semantics', async () => {
    // Echo a well-formed DNS response: copy the query ID, set QR, 1 answer.
    const port = await serve((q) => {
      const reply = Buffer.alloc(12);
      q.copy(reply, 0, 0, 2);
      reply.writeUInt16BE(0x8180, 2);
      reply.writeUInt16BE(1, 6);
      return reply;
    });
    // probeForPort keys off the port number, so we can't force port 53 here; instead
    // assert the generic path reports open, and leave DNS parsing to udp-probes tests.
    const r = await probeUdp(LOOPBACK, port, { timeoutMs: 500 });
    expect(r.state).toBe('open');
  });

  it('reports open|filtered on silence', async () => {
    const port = await serve(() => undefined); // receives but never answers
    const r = await probeUdp(LOOPBACK, port, { timeoutMs: 300 });
    expect(r.state).toBe('open|filtered');
    expect(r.reason).toBe('no-response');
    expect(r.latencyMs).toBeGreaterThanOrEqual(250);
  });

  it('closes its socket (no leak) — many probes in a row succeed', async () => {
    const port = await serve(() => Buffer.from('x'));
    for (let i = 0; i < 20; i++) {
      const r = await probeUdp(LOOPBACK, port, { timeoutMs: 500 });
      expect(r.state).toBe('open');
    }
  });

  it('on a closed port reports closed (Linux) or open|filtered (Windows)', async () => {
    const port = await freePort();
    const r = await probeUdp(LOOPBACK, port, { timeoutMs: 400 });
    // Windows swallows the ICMP port-unreachable (libuv ignores WSAECONNRESET), so we
    // cannot require 'closed'. Document the platform split rather than pretend otherwise.
    expect(['closed', 'open|filtered']).toContain(r.state);
  });
});

describe('classifyUdpError', () => {
  it.each([
    ['ECONNREFUSED', 'closed', 'port-unreach'],
    ['EHOSTUNREACH', 'filtered', 'host-unreach'],
    ['ENETUNREACH', 'filtered', 'net-unreach'],
    ['EACCES', 'error', 'local-error'],
    [undefined, 'error', 'local-error'],
  ])('%s -> %s (%s)', (code, state, reason) => {
    expect(classifyUdpError(code)).toEqual({ state, reason });
  });
});

describe('probeUdpWithRetry', () => {
  it('retries only silence, counting attempts', async () => {
    const port = await serve(() => undefined);
    let calls = 0;
    const r = await probeUdpWithRetry(LOOPBACK, port, {
      timeoutMs: 150,
      retries: 2,
      beforeAttempt: async () => void calls++,
    });
    expect(r.state).toBe('open|filtered');
    expect(r.attempts).toBe(3);
    expect(calls).toBe(3);
  });

  it('does not retry a definitive open', async () => {
    const port = await serve(() => Buffer.from('x'));
    const r = await probeUdpWithRetry(LOOPBACK, port, { timeoutMs: 300, retries: 3 });
    expect(r.attempts).toBe(1);
  });
});

describe('scanUdpHost', () => {
  it('returns one result per port', async () => {
    const open = await serve(() => Buffer.from('x'));
    const quiet = await serve(() => undefined);
    const results: UdpProbeResult[] = [];
    for await (const r of scanUdpHost(LOOPBACK, [open, quiet], { timeoutMs: 300, retries: 0, concurrency: 10 })) {
      results.push(r);
    }
    const byPort = Object.fromEntries(results.map((r) => [r.port, r.state]));
    expect(byPort[open]).toBe('open');
    expect(byPort[quiet]).toBe('open|filtered');
  });
});
