import { describe, expect, it } from 'vitest';
import { compileSignatures, loadDefaultSignatures, matchResponse } from '../src/fingerprint/matcher.js';

const sig = loadDefaultSignatures();

/** Build a Buffer from a latin1 string so \x00 etc. survive as single bytes. */
const bytes = (s: string): Buffer => Buffer.from(s, 'latin1');

describe('loadDefaultSignatures', () => {
  it('validates and compiles the bundled signature.json', () => {
    expect(sig.probes.length).toBeGreaterThan(0);
    expect(sig.byName.get('NULL')).toBeDefined();
  });

  it('every pattern is anchored at the start (^) to limit backtracking', () => {
    for (const probe of sig.probes) {
      for (const m of probe.matches) {
        expect(m.pattern.startsWith('^'), `${probe.name}/${m.service}: ${m.pattern}`).toBe(true);
      }
    }
  });
});

describe('matchResponse — NULL probe', () => {
  it('identifies SSH and extracts version + protocol', () => {
    const m = matchResponse(sig, 'NULL', bytes('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n'));
    expect(m).toMatchObject({ service: 'ssh', version: 'OpenSSH_9.6p1 Ubuntu-3', info: 'protocol 2.0', soft: false });
  });

  it('identifies SMTP from a 220 greeting', () => {
    const m = matchResponse(sig, 'NULL', bytes('220 mail.example.com ESMTP Postfix\r\n'));
    expect(m?.service).toBe('smtp');
    expect(m?.info).toContain('Postfix');
  });

  it('softmatches FTP (service known, version deferred)', () => {
    const m = matchResponse(sig, 'NULL', bytes('220 Welcome to vsFTPd 3.0.5\r\n'));
    expect(m).toMatchObject({ service: 'ftp', soft: true });
  });

  it('reads MySQL version out of a binary length-prefixed greeting', () => {
    // 4-byte header (len=.., seq=0), protocol 0x0a, then NUL-terminated version string.
    const greeting = bytes('\x4a\x00\x00\x00\x0a8.0.36-0ubuntu0.22.04.1\x00\x12\x34');
    const m = matchResponse(sig, 'NULL', greeting);
    expect(m).toMatchObject({ service: 'mysql', version: '8.0.36-0ubuntu0.22.04.1' });
  });

  it('returns null when nothing matches', () => {
    expect(matchResponse(sig, 'NULL', bytes('garbage\r\n'))).toBeNull();
  });

  it('returns null for an unknown probe name', () => {
    expect(matchResponse(sig, 'NoSuchProbe', bytes('SSH-2.0-x\r\n'))).toBeNull();
  });
});

describe('matchResponse — HTTP GetRequest', () => {
  const resp = [
    'HTTP/1.1 200 OK',
    'Date: Thu, 01 Jan 2026 00:00:00 GMT',
    'Server: nginx/1.25.3',
    'Content-Type: text/html',
    '',
    '<html>',
  ].join('\r\n');

  it('hard-matches http and extracts the Server product', () => {
    const m = matchResponse(sig, 'GetRequest', bytes(resp));
    expect(m).toMatchObject({ service: 'http', product: 'nginx/1.25.3', soft: false });
  });

  it('softmatches http when there is no Server header', () => {
    const m = matchResponse(sig, 'GetRequest', bytes('HTTP/1.0 404 Not Found\r\n\r\n'));
    expect(m).toMatchObject({ service: 'http', soft: true });
    expect(m?.product).toBeUndefined();
  });
});

describe('compileSignatures — hard match beats softmatch regardless of order', () => {
  it('prefers a later hard match over an earlier softmatch', () => {
    const compiled = compileSignatures({
      probes: [
        {
          name: 'NULL',
          payload: '',
          matches: [
            { service: 'generic', pattern: '^220', soft: true },
            { service: 'ftp', pattern: '^220 FTP', product: 'test' },
          ],
        },
      ],
    });
    // Both rules match "220 FTP ...", but the hard ftp rule must win even though the
    // soft rule appears first — we scan all rules and prefer any hard hit.
    const m = matchResponse(compiled, 'NULL', bytes('220 FTP ready\r\n'));
    expect(m).toMatchObject({ service: 'ftp', soft: false });
  });

  it('rejects an invalid signature file', () => {
    expect(() => compileSignatures({ probes: [] })).toThrow();
    expect(() => compileSignatures({ probes: [{ name: 'x', payload: '', matches: [] }] })).toThrow();
  });

  it('rejects a bad regex', () => {
    expect(() =>
      compileSignatures({ probes: [{ name: 'x', payload: '', matches: [{ service: 's', pattern: '(' }] }] }),
    ).toThrow();
  });
});
