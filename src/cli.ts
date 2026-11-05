#!/usr/bin/env node
import { Command } from 'commander';
import { z } from 'zod';
import { scanOptionsSchema } from './config.js';
import { fingerprint, printableBanner, type FingerprintResult } from './fingerprint/banner.js';
import { pool } from './scanner/pool.js';
import { RateLimiter } from './scanner/rate-limiter.js';
import { scanHost, scanTargets, type ScanHostOptions } from './scanner/tcp.js';
import { parseCidr } from './targets/cidr.js';
import { resolveHost } from './targets/host.js';
import { planCidrScan, type ScanPlanOptions } from './targets/plan.js';
import type { PortState, Target, TcpProbeResult } from './types.js';

const program = new Command()
  .name('port-sentinel')
  .description('TCP port scanner and service fingerprinter. Only scan hosts you own or are authorized to test.');

program
  .command('scan')
  .description('TCP connect scan of a host or IPv4 CIDR block')
  .argument('<target>', 'IP address, hostname, or IPv4 CIDR (e.g. 192.168.1.0/24)')
  .option('-p, --ports <spec>', 'ports, e.g. 22,80,8000-8100', '1-1024')
  .option('-t, --timeout <ms>', 'per-attempt connect deadline in ms', '1000')
  .option('-c, --concurrency <n>', 'max probes in flight', '500')
  .option('-r, --rate <pps>', 'max connection attempts per second (default: unlimited)')
  .option('--retries <n>', 'extra attempts for ports that did not answer', '1')
  .option('-a, --all', 'also list closed and filtered ports')
  .option('--banner', 'fingerprint open ports (service + version) after the scan')
  .option('--seq', 'scan a CIDR in ascending order instead of randomized')
  .option('--seed <n>', 'seed for randomized CIDR order (reproducible)')
  .option('--max-hosts <n>', 'refuse a CIDR block larger than this', '4096')
  .action(async (target: string, rawOpts: unknown) => {
    const parsed = scanOptionsSchema.safeParse(rawOpts);
    if (!parsed.success) {
      console.error(z.prettifyError(parsed.error));
      process.exitCode = 2;
      return;
    }
    const opts = parsed.data;

    const scanOpts: ScanHostOptions = {
      timeoutMs: opts.timeout,
      concurrency: opts.concurrency,
      retries: opts.retries,
    };
    if (opts.rate !== undefined) {
      // Burst of up to 1/10 s worth of probes smooths out timer jitter without a visible spike.
      const limiter = new RateLimiter({ ratePerSec: opts.rate, burst: Math.max(1, Math.ceil(opts.rate / 10)) });
      scanOpts.beforeAttempt = () => limiter.take();
    }

    if (target.includes('/')) {
      await runCidrScan(target, opts, scanOpts);
    } else {
      await runHostScan(target, opts, scanOpts);
    }
  });

type Opts = z.infer<typeof scanOptionsSchema>;

async function runHostScan(target: string, opts: Opts, scanOpts: ScanHostOptions): Promise<void> {
  const ip = await resolveHost(target);
  const started = performance.now();
  const results: TcpProbeResult[] = [];
  for await (const r of scanHost(ip, opts.ports, scanOpts)) results.push(r);
  const elapsed = ((performance.now() - started) / 1000).toFixed(2);

  results.sort((a, b) => a.port - b.port);
  console.log(`port-sentinel scan of ${target}${ip !== target ? ` (${ip})` : ''}`);
  printPortTable(results, opts.all);
  printSummary(results, elapsed);

  if (opts.banner) await runBannerPhase(results, opts.concurrency);
}

/**
 * Second phase: fingerprint every open port with bounded concurrency.
 * Runs after the scan so port discovery stays independent of version detection.
 */
async function runBannerPhase(results: readonly TcpProbeResult[], concurrency: number): Promise<void> {
  const open: Target[] = results.filter((r) => r.state === 'open').map((r) => ({ host: r.host, port: r.port }));
  if (open.length === 0) return;

  console.log('\nSERVICE DETECTION');
  const found: FingerprintResult[] = [];
  for await (const fp of pool(open, (t) => fingerprint(t.host, t.port), { concurrency: Math.min(concurrency, 50) })) {
    found.push(fp);
  }
  found.sort((a, b) => (a.host === b.host ? a.port - b.port : ipCompare(a.host, b.host)));
  for (const fp of found) {
    const svc = fp.match
      ? `${fp.match.service}${fp.match.soft ? '?' : ''}` +
        [fp.match.product, fp.match.version, fp.match.info].filter(Boolean).map((x) => ` ${x}`).join('')
      : 'unknown';
    const banner = fp.banner.length ? `  "${printableBanner(fp.banner, 80)}"` : '';
    console.log(`${`${fp.host}:${fp.port}`.padEnd(22)}${svc}${banner}`);
  }
}

async function runCidrScan(target: string, opts: Opts, scanOpts: ScanHostOptions): Promise<void> {
  const cidr = parseCidr(target);
  if (cidr.size > opts.maxHosts) {
    console.error(
      `refusing to scan ${cidr.size} hosts (${target}); raise --max-hosts to proceed. ` +
        'Only scan networks you own or are authorized to test.',
    );
    process.exitCode = 2;
    return;
  }
  // Ethics guardrail: a CIDR scan touches many machines. Make authorization explicit.
  console.error(
    `scanning ${cidr.size} hosts x ${opts.ports.length} ports = ${cidr.size * opts.ports.length} probes. ` +
      'Only scan networks you own or have written permission to test.',
  );

  const planOpts: ScanPlanOptions = { randomize: !opts.seq };
  if (opts.seed !== undefined) planOpts.seed = opts.seed;
  const plan = planCidrScan(target, opts.ports, planOpts);

  const started = performance.now();
  const byHost = new Map<string, TcpProbeResult[]>();
  let open = 0;
  for await (const r of scanTargets(plan.targets(), scanOpts)) {
    if (r.state === 'open') open++;
    if (opts.all || r.state === 'open' || r.state === 'error') {
      let list = byHost.get(r.host);
      if (!list) byHost.set(r.host, (list = []));
      list.push(r);
    }
  }
  const elapsed = ((performance.now() - started) / 1000).toFixed(2);

  for (const host of [...byHost.keys()].sort(ipCompare)) {
    const results = byHost.get(host)!.sort((a, b) => a.port - b.port);
    console.log(`\n${host}`);
    printPortTable(results, true);
  }
  console.log(
    `\n${plan.total} probes across ${plan.hostCount} hosts in ${elapsed}s: ${open} open ports found` +
      (byHost.size ? ` on ${byHost.size} host(s)` : ''),
  );

  if (opts.banner) {
    await runBannerPhase([...byHost.values()].flat(), opts.concurrency);
  }
}

function printPortTable(results: readonly TcpProbeResult[], all: boolean | undefined): void {
  console.log('PORT      STATE     REASON        TRIES  LATENCY');
  for (const r of results) {
    if (!all && r.state !== 'open') continue;
    const detail = r.state === 'error' && r.errorCode ? ` (${r.errorCode})` : '';
    console.log(
      `${`${r.port}/tcp`.padEnd(10)}${r.state.padEnd(10)}${r.reason.padEnd(14)}` +
        `${String(r.attempts).padEnd(7)}${r.latencyMs}ms${detail}`,
    );
  }
}

function printSummary(results: readonly TcpProbeResult[], elapsed: string): void {
  const counts: Record<PortState, number> = { open: 0, closed: 0, filtered: 0, error: 0 };
  let attempts = 0;
  for (const r of results) {
    counts[r.state]++;
    attempts += r.attempts;
  }
  console.log(
    `\n${results.length} ports (${attempts} attempts) in ${elapsed}s: ${counts.open} open, ` +
      `${counts.closed} closed, ${counts.filtered} filtered, ${counts.error} error`,
  );
}

/** Sort dotted-quad strings numerically, not lexically (so .10 comes after .9). */
function ipCompare(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 4; i++) {
    if (pa[i] !== pb[i]) return (pa[i] ?? 0) - (pb[i] ?? 0);
  }
  return 0;
}

await program.parseAsync();
