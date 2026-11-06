import type { ScanReport, ScanResultRecord } from './report.js';

export type ChangeKind = 'appeared' | 'disappeared' | 'changed' | 'same';

export interface PortChange {
  kind: ChangeKind;
  host: string;
  port: number;
  protocol: string;
  before?: ScanResultRecord;
  after?: ScanResultRecord;
  /** Human-readable summary of what differs, for `changed`. */
  detail?: string;
}

export interface ReportDiff {
  changes: PortChange[];
  counts: Record<ChangeKind, number>;
  /** True if anything other than `same` is present. */
  hasChanges: boolean;
}

const key = (r: ScanResultRecord): string => `${r.host}:${r.port}/${r.protocol}`;

/** "open" and "open|filtered" both mean "reachable/responding"; group them when judging appear/disappear. */
function isOpenish(state: string): boolean {
  return state === 'open' || state === 'open|filtered';
}

function describe(before: ScanResultRecord, after: ScanResultRecord): string {
  const parts: string[] = [];
  if (before.state !== after.state) parts.push(`state ${before.state} -> ${after.state}`);
  const bv = [before.service, before.product, before.version].filter(Boolean).join(' ');
  const av = [after.service, after.product, after.version].filter(Boolean).join(' ');
  if (bv !== av) parts.push(`service "${bv}" -> "${av}"`);
  return parts.join('; ');
}

/**
 * Compare two reports port-by-port (keyed by host:port/proto).
 *
 * - appeared:    not openish before, openish after (a new listening service)
 * - disappeared: openish before, not openish after
 * - changed:     present in both, but state or service/version differs
 * - same:        no meaningful difference
 *
 * "appeared" is the security-relevant one: a port that opened since the last scan.
 */
export function diffReports(before: ScanReport, after: ScanReport): ReportDiff {
  const beforeMap = new Map(before.results.map((r) => [key(r), r]));
  const afterMap = new Map(after.results.map((r) => [key(r), r]));
  const changes: PortChange[] = [];

  for (const [k, a] of afterMap) {
    const b = beforeMap.get(k);
    if (!b) {
      if (isOpenish(a.state)) changes.push({ kind: 'appeared', host: a.host, port: a.port, protocol: a.protocol, after: a });
      continue;
    }
    const stateChanged = b.state !== a.state;
    const serviceChanged =
      (b.service ?? b.product) !== (a.service ?? a.product) || (b.version ?? '') !== (a.version ?? '');
    if (isOpenish(b.state) && !isOpenish(a.state)) {
      changes.push({ kind: 'disappeared', host: a.host, port: a.port, protocol: a.protocol, before: b, after: a });
    } else if (!isOpenish(b.state) && isOpenish(a.state)) {
      changes.push({ kind: 'appeared', host: a.host, port: a.port, protocol: a.protocol, before: b, after: a });
    } else if (stateChanged || serviceChanged) {
      changes.push({
        kind: 'changed',
        host: a.host,
        port: a.port,
        protocol: a.protocol,
        before: b,
        after: a,
        detail: describe(b, a),
      });
    }
  }

  // Ports present before but absent from the after-scan entirely (e.g. host no longer scanned,
  // or port dropped from the list). Treat an openish one vanishing as "disappeared".
  for (const [k, b] of beforeMap) {
    if (!afterMap.has(k) && isOpenish(b.state)) {
      changes.push({ kind: 'disappeared', host: b.host, port: b.port, protocol: b.protocol, before: b });
    }
  }

  const counts: Record<ChangeKind, number> = { appeared: 0, disappeared: 0, changed: 0, same: 0 };
  for (const c of changes) counts[c.kind]++;
  return { changes, counts, hasChanges: changes.length > 0 };
}
