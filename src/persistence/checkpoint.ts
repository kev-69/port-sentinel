import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { z } from 'zod';
import type { Protocol } from '../types.js';
import { parseReport } from '../output/json.js';
import type { ScanReport, ScanResultRecord } from '../output/report.js';
import { SCHEMA_VERSION } from '../output/report.js';

/** Identity of a scan: two runs with the same plan cover the same target set. */
export interface PlanIdentity {
  target: string;
  ports: number[];
  protocol: Protocol;
  seed?: number;
}

export interface Checkpoint {
  schema: number;
  plan: PlanIdentity;
  startedAt: string;
  report: ScanReport;
}

const planSchema = z.object({
  target: z.string(),
  ports: z.array(z.number().int()),
  protocol: z.enum(['tcp', 'udp']),
  seed: z.number().int().optional(),
});

/** Does a saved checkpoint cover the same scan we're about to run? */
export function planMatches(a: PlanIdentity, b: PlanIdentity): boolean {
  return (
    a.target === b.target &&
    a.protocol === b.protocol &&
    a.ports.length === b.ports.length &&
    a.ports.every((p, i) => p === b.ports[i])
  );
}

/** Load a checkpoint and validate its plan shape. Throws on malformed input. */
export function loadCheckpoint(path: string): Checkpoint {
  const raw = JSON.parse(readFileSync(path, 'utf8')) as { plan?: unknown; startedAt?: unknown };
  const plan = planSchema.parse(raw.plan);
  const report = parseReport(JSON.stringify((raw as { report: unknown }).report));
  return {
    schema: SCHEMA_VERSION,
    plan: plan as PlanIdentity,
    startedAt: typeof raw.startedAt === 'string' ? raw.startedAt : report.startedAt,
    report,
  };
}

/** The set of already-completed targets, as `host:port` keys. */
export function doneSet(cp: Checkpoint): Set<string> {
  return new Set(cp.report.results.map((r) => `${r.host}:${r.port}`));
}

/**
 * Atomic save: write a temp file then rename over the target. A crash mid-write therefore
 * never corrupts the previous good checkpoint (rename is atomic on the same filesystem).
 */
export function saveCheckpoint(path: string, cp: Checkpoint): void {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(cp, null, 2)}\n`);
  renameSync(tmp, path);
}

/**
 * Accumulates results during a scan and flushes a checkpoint on a time interval (and on
 * demand, e.g. from a SIGINT handler). The CLI owns the signal handler and the clock.
 */
export class CheckpointWriter {
  private readonly records: ScanResultRecord[] = [];
  private lastFlush: number;

  constructor(
    private readonly path: string,
    private readonly plan: PlanIdentity,
    private readonly startedAtMs: number,
    seed: ScanResultRecord[] = [],
    private readonly opts: { intervalMs?: number; now?: () => number } = {},
  ) {
    this.records.push(...seed);
    this.lastFlush = this.now();
  }

  private now(): number {
    return this.opts.now?.() ?? performance.now();
  }

  /** Record one result; flush if the interval has elapsed. */
  add(record: ScanResultRecord): void {
    this.records.push(record);
    const t = this.now();
    if (t - this.lastFlush >= (this.opts.intervalMs ?? 2000)) {
      this.lastFlush = t;
      this.flush();
    }
  }

  all(): ScanResultRecord[] {
    return this.records;
  }

  /** Force a checkpoint write now (used periodically and from the SIGINT handler). */
  flush(): void {
    const finishedAt = Date.now();
    const report: ScanReport = {
      tool: 'port-sentinel',
      schema: SCHEMA_VERSION,
      protocol: this.plan.protocol,
      target: this.plan.target,
      startedAt: new Date(this.startedAtMs).toISOString(),
      finishedAt: new Date(finishedAt).toISOString(),
      elapsedMs: Math.max(0, finishedAt - this.startedAtMs),
      results: [...this.records].sort((a, b) => (a.host === b.host ? a.port - b.port : a.host < b.host ? -1 : 1)),
    };
    saveCheckpoint(this.path, {
      schema: SCHEMA_VERSION,
      plan: this.plan,
      startedAt: report.startedAt,
      report,
    });
  }
}
