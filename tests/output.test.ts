import { describe, expect, it } from 'vitest';
import { toGrep } from '../src/output/grep.js';
import { parseReport, toJson } from '../src/output/json.js';
import { buildReport, sortRecords, tcpRecord, udpRecord, type ScanResultRecord } from '../src/output/report.js';
import type { TcpProbeResult, UdpProbeResult } from '../src/types.js';

const tcp = (over: Partial<TcpProbeResult>): TcpProbeResult => ({
  host: '127.0.0.1',
  port: 80,
  state: 'open',
  reason: 'syn-ack',
  latencyMs: 1,
  attempts: 1,
  ...over,
});

const rec = (over: Partial<ScanResultRecord>): ScanResultRecord => ({
  host: '10.0.0.1',
  port: 22,
  protocol: 'tcp',
  state: 'open',
  reason: 'syn-ack',
  latencyMs: 1,
  attempts: 1,
  ...over,
});

describe('tcpRecord / udpRecord', () => {
  it('normalizes a bare TCP result', () => {
    expect(tcpRecord(tcp({ port: 22 }))).toEqual({
      host: '127.0.0.1',
      port: 22,
      protocol: 'tcp',
      state: 'open',
      reason: 'syn-ack',
      latencyMs: 1,
      attempts: 1,
    });
  });

  it('folds a fingerprint match into the TCP record', () => {
    const r = tcpRecord(tcp({ port: 22 }), {
      host: '127.0.0.1',
      port: 22,
      banner: Buffer.from('SSH-2.0-x\r\n'),
      match: { service: 'ssh', soft: false, probe: 'NULL', version: 'OpenSSH_9.6', info: 'protocol 2.0' },
    });
    expect(r).toMatchObject({ service: 'ssh', version: 'OpenSSH_9.6', info: 'protocol 2.0' });
  });

  it('omits optional keys entirely when absent (clean diffs)', () => {
    const r = tcpRecord(tcp({}));
    expect('service' in r).toBe(false);
    expect('version' in r).toBe(false);
  });

  it('carries UDP service/info through', () => {
    const u: UdpProbeResult = {
      host: '1.1.1.1',
      port: 53,
      state: 'open',
      reason: 'udp-response',
      latencyMs: 5,
      attempts: 1,
      probe: 'dns',
      service: 'dns',
      info: 'rcode=NOERROR answers=13',
    };
    expect(udpRecord(u)).toMatchObject({ protocol: 'udp', service: 'dns', info: 'rcode=NOERROR answers=13' });
  });
});

describe('sortRecords', () => {
  it('orders by dotted-quad host then port', () => {
    const sorted = sortRecords([
      rec({ host: '10.0.0.10', port: 80 }),
      rec({ host: '10.0.0.2', port: 443 }),
      rec({ host: '10.0.0.2', port: 22 }),
    ]);
    expect(sorted.map((r) => `${r.host}:${r.port}`)).toEqual(['10.0.0.2:22', '10.0.0.2:443', '10.0.0.10:80']);
  });
});

describe('buildReport + toJson + parseReport', () => {
  it('round-trips through JSON', () => {
    const report = buildReport({
      protocol: 'tcp',
      target: '127.0.0.1',
      startedAt: 1_700_000_000_000,
      finishedAt: 1_700_000_001_500,
      records: [tcpRecord(tcp({ port: 80 }))],
    });
    expect(report.elapsedMs).toBe(1500);
    expect(report.startedAt).toBe('2023-11-14T22:13:20.000Z');
    const parsed = parseReport(toJson(report));
    expect(parsed).toEqual(report);
  });

  it('rejects a malformed report', () => {
    expect(() => parseReport('{"tool":"nope"}')).toThrow();
    expect(() => parseReport('not json')).toThrow();
  });
});

describe('toGrep', () => {
  it('emits a header and one tab row per result', () => {
    const report = buildReport({
      protocol: 'tcp',
      target: 'x',
      startedAt: 0,
      finishedAt: 1,
      records: [rec({ host: '10.0.0.1', port: 22, service: 'ssh', version: 'OpenSSH_9.6' })],
    });
    const lines = toGrep(report).trimEnd().split('\n');
    expect(lines[0]).toMatch(/^# host\tport/);
    expect(lines[1]).toBe('10.0.0.1\t22\ttcp\topen\tssh\tOpenSSH_9.6\tsyn-ack');
  });

  it('strips embedded tabs/newlines from a banner-derived field', () => {
    const report = buildReport({
      protocol: 'tcp',
      target: 'x',
      startedAt: 0,
      finishedAt: 1,
      records: [rec({ service: 'http', version: 'a\tb\nc' })],
    });
    const row = toGrep(report).trimEnd().split('\n')[1]!;
    expect(row.split('\t')).toHaveLength(7); // tabs in the field didn't add columns
  });
});
