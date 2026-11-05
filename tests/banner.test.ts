import net from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { fingerprint, grabRaw, printableBanner } from '../src/fingerprint/banner.js';
import { compileSignatures } from '../src/fingerprint/matcher.js';

const LOOPBACK = '127.0.0.1';
const servers: net.Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

/** Start a server that runs `onConnect` for each client socket. */
function serve(onConnect: (s: net.Socket) => void): Promise<number> {
  return new Promise((resolve) => {
    const server = net.createServer((s) => {
      s.on('error', () => {}); // ignore RSTs from our own teardown
      onConnect(s);
    });
    servers.push(server);
    server.listen(0, LOOPBACK, () => resolve((server.address() as net.AddressInfo).port));
  });
}

const grabOpts = { connectTimeoutMs: 1000, bannerTimeoutMs: 300, maxBytes: 4096 };

describe('grabRaw', () => {
  it('reads a banner a service sends on connect', async () => {
    const port = await serve((s) => s.write('SSH-2.0-OpenSSH_9.6\r\n'));
    const r = await grabRaw(LOOPBACK, port, grabOpts);
    expect(r.data.toString()).toBe('SSH-2.0-OpenSSH_9.6\r\n');
    expect(r.error).toBeUndefined();
  });

  it('sends a payload and reads the reply', async () => {
    const port = await serve((s) => {
      s.on('data', (d) => {
        if (d.toString().startsWith('GET ')) s.write('HTTP/1.1 200 OK\r\nServer: test/1.0\r\n\r\n');
      });
    });
    const r = await grabRaw(LOOPBACK, port, { ...grabOpts, payload: Buffer.from('GET / HTTP/1.0\r\n\r\n') });
    expect(r.data.toString()).toContain('Server: test/1.0');
  });

  it('returns an empty buffer (not an error) when the service stays silent', async () => {
    const port = await serve(() => {
      /* accept but say nothing */
    });
    const r = await grabRaw(LOOPBACK, port, grabOpts);
    expect(r.data).toHaveLength(0);
    expect(r.error).toBeUndefined();
  });

  it('caps the data at maxBytes', async () => {
    const port = await serve((s) => s.write('x'.repeat(10_000)));
    const r = await grabRaw(LOOPBACK, port, { ...grabOpts, maxBytes: 100 });
    expect(r.data.length).toBe(100);
  });

  it('reports an error for a refused connection', async () => {
    // A port we just closed: connection refused.
    const port = await serve(() => {});
    await new Promise((r) => servers[0]!.close(r));
    servers.length = 0;
    const r = await grabRaw(LOOPBACK, port, grabOpts);
    expect(r.error).toBeDefined();
    expect(r.data).toHaveLength(0);
  });
});

describe('fingerprint (end to end over loopback)', () => {
  it('identifies a fake SSH server via the NULL probe', async () => {
    const port = await serve((s) => s.write('SSH-2.0-OpenSSH_9.6p1\r\n'));
    const r = await fingerprint(LOOPBACK, port, undefined, { bannerTimeoutMs: 300 });
    expect(r.match).toMatchObject({ service: 'ssh', version: 'OpenSSH_9.6p1', probe: 'NULL' });
  });

  it('identifies a fake HTTP server via the GetRequest probe on port 80 rules', async () => {
    const port = await serve((s) => {
      s.on('data', () => s.write('HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\n\r\n'));
    });
    // Use a signature whose GetRequest applies to any port, so a random test port works.
    const anyPortSig = compileSignatures({
      probes: [
        { name: 'NULL', payload: '', matches: [{ service: 'ssh', pattern: '^SSH-' }] },
        {
          name: 'GetRequest',
          payload: 'GET / HTTP/1.0\r\n\r\n',
          matches: [{ service: 'http', pattern: '^HTTP/\\d\\.\\d \\d{3}[\\s\\S]*Server: ([^\\r\\n]+)', product: '$1' }],
        },
      ],
    });
    const r = await fingerprint(LOOPBACK, port, anyPortSig, { bannerTimeoutMs: 300 });
    expect(r.match).toMatchObject({ service: 'http', product: 'nginx/1.25', probe: 'GetRequest' });
  });

  it('returns the banner but no match for an unknown service', async () => {
    const port = await serve((s) => s.write('HELLO UNKNOWN PROTOCOL\r\n'));
    const r = await fingerprint(LOOPBACK, port, undefined, { bannerTimeoutMs: 300 });
    expect(r.match).toBeUndefined();
    expect(r.banner.toString()).toContain('HELLO UNKNOWN');
  });
});

describe('printableBanner', () => {
  it('escapes CRLF and control bytes', () => {
    expect(printableBanner(Buffer.from('ok\r\n\x00\x1b', 'latin1'))).toBe('ok\\r\\n\\x00\\x1b');
  });

  it('truncates with an ellipsis', () => {
    expect(printableBanner(Buffer.from('a'.repeat(20)), 5)).toBe('aaaaa...');
  });
});
