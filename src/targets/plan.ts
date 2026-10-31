import type { Target } from '../types.js';
import { intToIp, parseCidr } from './cidr.js';
import { shuffledRange } from './shuffle.js';

export interface ScanPlanOptions {
  randomize?: boolean;
  seed?: number;
}

export interface ScanPlan {
  hostCount: number;
  portCount: number;
  /** Total probes = hostCount * portCount. */
  total: number;
  /** Lazily yields every (host, port), shuffled across the whole space by default. */
  targets: () => Iterable<Target>;
}

/**
 * Build a scan plan for an IPv4 CIDR block crossed with a port list.
 *
 * The whole (host, port) space is flattened to a single index range [0, total) and
 * shuffled as one unit. Decoding index i as (host = first + ⌊i/P⌋, port = ports[i % P])
 * means a shuffle of i interleaves hosts and ports together: consecutive probes land on
 * different hosts *and* different ports, which is what avoids a sequential sweep pattern.
 */
export function planCidrScan(cidrSpec: string, ports: readonly number[], opts: ScanPlanOptions = {}): ScanPlan {
  const cidr = parseCidr(cidrSpec);
  const portCount = ports.length;
  if (portCount === 0) throw new Error('no ports to scan');
  const total = cidr.size * portCount;

  const targets = function* (): Generator<Target> {
    const shuffleOpts: Parameters<typeof shuffledRange>[2] = {};
    if (opts.seed !== undefined) shuffleOpts.seed = opts.seed;
    if (opts.randomize !== undefined) shuffleOpts.randomize = opts.randomize;
    for (const i of shuffledRange(0, total, shuffleOpts)) {
      const hostOffset = Math.floor(i / portCount);
      const portIndex = i % portCount;
      yield { host: intToIp((cidr.first + hostOffset) >>> 0), port: ports[portIndex]! };
    }
  };

  return { hostCount: cidr.size, portCount, total, targets };
}
