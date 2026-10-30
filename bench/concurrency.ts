/**
 * How does concurrency change scan time, and where does it break?
 *
 *   npx tsx bench/concurrency.ts
 *
 * Targets only loopback and RFC 5737 TEST-NET-1 (unrouted); never point this at hosts you don't own.
 */
import { scanHost } from '../src/scanner/tcp.js';
import type { PortState } from '../src/types.js';

interface Scenario {
  name: string;
  host: string;
  ports: number[];
  timeoutMs: number;
  concurrencies: number[];
}

const range = (lo: number, hi: number): number[] => Array.from({ length: hi - lo + 1 }, (_, i) => lo + i);

const scenarios: Scenario[] = [
  {
    name: 'filtered: 192.0.2.1 ports 1-1000, 500 ms timeout',
    host: '192.0.2.1',
    ports: range(1, 1000),
    timeoutMs: 500,
    concurrencies: [50, 200, 500, 1000],
  },
  {
    name: 'closed: 127.0.0.1 ports 1-65535, 1000 ms timeout',
    host: '127.0.0.1',
    ports: range(1, 65535),
    timeoutMs: 1000,
    concurrencies: [1, 10, 100, 500, 2000, 5000],
  },
];

for (const s of scenarios) {
  console.log(`\n### ${s.name}\n`);
  console.log('| concurrency | time (s) | ports/s | open | closed | filtered | error | error codes |');
  console.log('|---:|---:|---:|---:|---:|---:|---:|---|');
  for (const concurrency of s.concurrencies) {
    const counts: Record<PortState, number> = { open: 0, closed: 0, filtered: 0, error: 0 };
    const codes = new Map<string, number>();
    const start = performance.now();
    for await (const r of scanHost(s.host, s.ports, { timeoutMs: s.timeoutMs, retries: 0, concurrency })) {
      counts[r.state]++;
      if (r.state === 'error') codes.set(r.errorCode ?? '?', (codes.get(r.errorCode ?? '?') ?? 0) + 1);
    }
    const secs = (performance.now() - start) / 1000;
    const codeList = [...codes].map(([c, n]) => `${c}×${n}`).join(', ') || '-';
    console.log(
      `| ${concurrency} | ${secs.toFixed(2)} | ${Math.round(s.ports.length / secs)} | ${counts.open} | ` +
        `${counts.closed} | ${counts.filtered} | ${counts.error} | ${codeList} |`,
    );
  }
}
