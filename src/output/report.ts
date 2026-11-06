import type { FingerprintResult } from '../fingerprint/banner.js';
import { printableBanner } from '../fingerprint/banner.js';
import type { Protocol, TcpProbeResult, UdpProbeResult, UdpState } from '../types.js';

/** Current on-disk schema version for JSON reports and checkpoints. */
export const SCHEMA_VERSION = 1;

/** A single result, normalized so TCP and UDP look the same to output and diff. */
export interface ScanResultRecord {
  host: string;
  port: number;
  protocol: Protocol;
  state: UdpState;
  reason: string;
  latencyMs: number;
  attempts: number;
  service?: string;
  product?: string;
  version?: string;
  info?: string;
}

export interface ScanReport {
  tool: 'port-sentinel';
  schema: number;
  protocol: Protocol;
  target: string;
  startedAt: string;
  finishedAt: string;
  elapsedMs: number;
  results: ScanResultRecord[];
}

/** Stable ordering so two reports of the same network serialize line-for-line comparably. */
export function sortRecords(records: ScanResultRecord[]): ScanResultRecord[] {
  return records.sort((a, b) => {
    if (a.host !== b.host) return compareHost(a.host, b.host);
    return a.port - b.port;
  });
}

function compareHost(a: string, b: string): number {
  const pa = a.split('.');
  const pb = b.split('.');
  // Numeric dotted-quad ordering when both look like IPv4; lexical otherwise.
  if (pa.length === 4 && pb.length === 4 && [...pa, ...pb].every((o) => /^\d+$/.test(o))) {
    for (let i = 0; i < 4; i++) {
      const d = Number(pa[i]) - Number(pb[i]);
      if (d !== 0) return d;
    }
    return 0;
  }
  return a < b ? -1 : a > b ? 1 : 0;
}

function dropUndefined(rec: ScanResultRecord): ScanResultRecord {
  // Keep optional keys out of the JSON entirely when empty, so diffs stay clean.
  return Object.fromEntries(Object.entries(rec).filter(([, v]) => v !== undefined)) as unknown as ScanResultRecord;
}

/** Normalize a TCP result, folding in an optional fingerprint for the same port. */
export function tcpRecord(r: TcpProbeResult, fp?: FingerprintResult): ScanResultRecord {
  const rec: ScanResultRecord = {
    host: r.host,
    port: r.port,
    protocol: 'tcp',
    state: r.state,
    reason: r.reason,
    latencyMs: r.latencyMs,
    attempts: r.attempts,
  };
  if (fp?.match) {
    rec.service = fp.match.service;
    if (fp.match.product !== undefined) rec.product = fp.match.product;
    if (fp.match.version !== undefined) rec.version = fp.match.version;
    const info = fp.match.info ?? (fp.banner.length ? printableBanner(fp.banner, 120) : undefined);
    if (info !== undefined) rec.info = info;
  }
  return dropUndefined(rec);
}

/** Normalize a UDP result (service/info come straight off the probe). */
export function udpRecord(r: UdpProbeResult): ScanResultRecord {
  const rec: ScanResultRecord = {
    host: r.host,
    port: r.port,
    protocol: 'udp',
    state: r.state,
    reason: r.reason,
    latencyMs: r.latencyMs,
    attempts: r.attempts,
  };
  if (r.service !== undefined) rec.service = r.service;
  if (r.info !== undefined) rec.info = r.info;
  return dropUndefined(rec);
}

export interface BuildReportInput {
  protocol: Protocol;
  target: string;
  startedAt: number;
  finishedAt: number;
  records: ScanResultRecord[];
}

export function buildReport(input: BuildReportInput): ScanReport {
  return {
    tool: 'port-sentinel',
    schema: SCHEMA_VERSION,
    protocol: input.protocol,
    target: input.target,
    startedAt: new Date(input.startedAt).toISOString(),
    finishedAt: new Date(input.finishedAt).toISOString(),
    elapsedMs: Math.round(input.finishedAt - input.startedAt),
    results: sortRecords(input.records),
  };
}
