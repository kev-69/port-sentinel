import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  CheckpointWriter,
  doneSet,
  loadCheckpoint,
  planMatches,
  saveCheckpoint,
  type Checkpoint,
  type PlanIdentity,
} from '../src/persistence/checkpoint.js';
import { buildReport, type ScanResultRecord } from '../src/output/report.js';

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'ps-cp-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const plan: PlanIdentity = { target: '10.0.0.0/30', ports: [22, 80], protocol: 'tcp', seed: 1 };

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

const cp = (records: ScanResultRecord[]): Checkpoint => ({
  schema: 1,
  plan,
  startedAt: '2026-01-01T00:00:00.000Z',
  report: buildReport({ protocol: 'tcp', target: plan.target, startedAt: 0, finishedAt: 1, records }),
});

describe('planMatches', () => {
  it('matches same target/ports/protocol', () => {
    expect(planMatches(plan, { ...plan, seed: 999 })).toBe(true); // seed irrelevant to coverage
  });
  it('rejects different ports or target', () => {
    expect(planMatches(plan, { ...plan, ports: [22] })).toBe(false);
    expect(planMatches(plan, { ...plan, target: '10.0.0.0/29' })).toBe(false);
    expect(planMatches(plan, { ...plan, protocol: 'udp' })).toBe(false);
  });
});

describe('save / load round-trip', () => {
  it('persists and reloads a checkpoint', () => {
    const path = join(dir, 'scan.json');
    const original = cp([rec({ port: 22 }), rec({ port: 80, state: 'closed', reason: 'conn-refused' })]);
    saveCheckpoint(path, original);
    const loaded = loadCheckpoint(path);
    expect(loaded.plan).toEqual(plan);
    expect(loaded.report.results).toHaveLength(2);
  });

  it('doneSet lists completed host:port keys', () => {
    const set = doneSet(cp([rec({ port: 22 }), rec({ port: 80 })]));
    expect(set.has('10.0.0.1:22')).toBe(true);
    expect(set.has('10.0.0.1:80')).toBe(true);
    expect(set.has('10.0.0.1:443')).toBe(false);
  });

  it('leaves no .tmp file behind (atomic rename)', () => {
    const path = join(dir, 'scan.json');
    saveCheckpoint(path, cp([rec({})]));
    expect(() => readFileSync(`${path}.tmp`)).toThrow();
  });
});

describe('CheckpointWriter', () => {
  it('flushes on the interval and accumulates all records', () => {
    const path = join(dir, 'w.json');
    let t = 0;
    const w = new CheckpointWriter(path, plan, Date.now(), [], { intervalMs: 100, now: () => t });
    w.add(rec({ port: 22 })); // t=0, no flush yet (just constructed)
    t = 50;
    w.add(rec({ port: 80 })); // within interval -> no flush
    expect(() => readFileSync(path)).toThrow(); // nothing written yet
    t = 150;
    w.add(rec({ port: 443 })); // past interval -> flush
    const loaded = loadCheckpoint(path);
    expect(loaded.report.results).toHaveLength(3);
    expect(w.all()).toHaveLength(3);
  });

  it('flush() can be called directly (SIGINT path) and seeds resume correctly', () => {
    const path = join(dir, 'w2.json');
    const w = new CheckpointWriter(path, plan, Date.now(), [rec({ port: 22 })]);
    w.add(rec({ port: 80 }));
    w.flush();
    expect(doneSet(loadCheckpoint(path)).size).toBe(2);
  });
});
