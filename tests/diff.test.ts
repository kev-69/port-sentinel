import { describe, expect, it } from 'vitest';
import { diffReports } from '../src/output/diff.js';
import { buildReport, type ScanResultRecord } from '../src/output/report.js';

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

const report = (records: ScanResultRecord[]) =>
  buildReport({ protocol: 'tcp', target: '10.0.0.0/24', startedAt: 0, finishedAt: 1, records });

describe('diffReports', () => {
  it('flags a newly open port as appeared', () => {
    const before = report([rec({ port: 22 })]);
    const after = report([rec({ port: 22 }), rec({ port: 80, service: 'http' })]);
    const d = diffReports(before, after);
    expect(d.counts.appeared).toBe(1);
    expect(d.changes.find((c) => c.kind === 'appeared')).toMatchObject({ port: 80 });
    expect(d.hasChanges).toBe(true);
  });

  it('flags a port that closed as disappeared', () => {
    const before = report([rec({ port: 22 }), rec({ port: 80 })]);
    const after = report([rec({ port: 22 }), rec({ port: 80, state: 'closed', reason: 'conn-refused' })]);
    const d = diffReports(before, after);
    expect(d.counts.disappeared).toBe(1);
    expect(d.changes.find((c) => c.kind === 'disappeared')).toMatchObject({ port: 80 });
  });

  it('treats a port dropped from the after-scan as disappeared if it was open', () => {
    const before = report([rec({ port: 22 }), rec({ port: 3306 })]);
    const after = report([rec({ port: 22 })]);
    expect(diffReports(before, after).counts.disappeared).toBe(1);
  });

  it('flags a version change on a still-open port as changed', () => {
    const before = report([rec({ port: 22, service: 'ssh', version: 'OpenSSH_8.9' })]);
    const after = report([rec({ port: 22, service: 'ssh', version: 'OpenSSH_9.6' })]);
    const d = diffReports(before, after);
    expect(d.counts.changed).toBe(1);
    expect(d.changes[0]?.detail).toContain('OpenSSH_8.9');
    expect(d.changes[0]?.detail).toContain('OpenSSH_9.6');
  });

  it('reports no changes for identical reports', () => {
    const r = report([rec({ port: 22 }), rec({ port: 80, service: 'http' })]);
    const d = diffReports(r, r);
    expect(d.hasChanges).toBe(false);
    expect(d.changes).toHaveLength(0);
  });

  it('does not flag an always-closed port appearing/disappearing', () => {
    const before = report([rec({ port: 22, state: 'closed', reason: 'conn-refused' })]);
    const after = report([]);
    expect(diffReports(before, after).hasChanges).toBe(false);
  });

  it('counts open|filtered as openish (UDP)', () => {
    const before = report([]);
    const after = report([rec({ port: 53, protocol: 'udp', state: 'open|filtered', reason: 'no-response' })]);
    expect(diffReports(before, after).counts.appeared).toBe(1);
  });
});
