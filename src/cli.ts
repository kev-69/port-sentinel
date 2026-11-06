#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { Command } from 'commander';
import { z } from 'zod';
import { scanOptionsSchema } from './config.js';
import { fingerprint } from './fingerprint/banner.js';
import { diffReports, type ReportDiff } from './output/diff.js';
import { toGrep } from './output/grep.js';
import { parseReport, toJson } from './output/json.js';
import { Progress } from './output/progress.js';
import { buildReport, tcpRecord, udpRecord, type ScanReport, type ScanResultRecord } from './output/report.js';
import {
  CheckpointWriter,
  doneSet,
  loadCheckpoint,
  planMatches,
  type PlanIdentity,
} from './persistence/checkpoint.js';
import { pool } from './scanner/pool.js';
import { RateLimiter } from './scanner/rate-limiter.js';
import { scanTargets, type ScanHostOptions } from './scanner/tcp.js';
import { scanUdpTargets, type ScanUdpOptions } from './scanner/udp.js';
import { parseCidr } from './targets/cidr.js';
import { resolveHost } from './targets/host.js';
import { planCidrScan, type ScanPlanOptions } from './targets/plan.js';
import type { Protocol, Target, TcpProbeResult } from './types.js';

type Opts = z.infer<typeof scanOptionsSchema>;

const program = new Command()
  .name('port-sentinel')
  .description('TCP/UDP port scanner and service fingerprinter. Only scan hosts you own or are authorized to test.');

program
  .command('scan')
  .description('Scan a host or IPv4 CIDR block')
  .argument('<target>', 'IP address, hostname, or IPv4 CIDR (e.g. 192.168.1.0/24)')
  .option('-p, --ports <spec>', 'ports, e.g. 22,80,8000-8100', '1-1024')
  .option('-t, --timeout <ms>', 'per-attempt deadline in ms', '1000')
  .option('-c, --concurrency <n>', 'max probes in flight', '500')
  .option('-r, --rate <pps>', 'max attempts per second (default: unlimited)')
  .option('--retries <n>', 'extra attempts for ports that did not answer', '1')
  .option('-a, --all', 'also list non-open ports')
  .option('--udp', 'scan UDP instead of TCP (53=DNS, 123=NTP, else empty datagram)')
  .option('--banner', 'fingerprint open TCP ports (service + version) after the scan')
  .option('--seq', 'scan a CIDR in ascending order instead of randomized')
  .option('--seed <n>', 'seed for randomized CIDR order (reproducible)')
  .option('--max-hosts <n>', 'refuse a CIDR block larger than this', '4096')
  .option('-o, --output <fmt>', 'output format: text, json, grep', 'text')
  .option('--out-file <path>', 'write the report to a file instead of stdout')
  .option('--progress', 'show a progress meter on stderr even when not a TTY')
  .option('--checkpoint <path>', 'periodically save scan progress to this file')
  .option('--resume <path>', 'resume from a checkpoint, skipping completed targets')
  .action(async (target: string, rawOpts: unknown) => {
    const parsed = scanOptionsSchema.safeParse(rawOpts);
    if (!parsed.success) {
      console.error(z.prettifyError(parsed.error));
      process.exitCode = 2;
      return;
    }
    await runScan(target, parsed.data);
  });

program
  .command('diff')
  .description('Compare two JSON scan reports (exit 1 if anything changed)')
  .argument('<before>', 'path to the earlier report (JSON)')
  .argument('<after>', 'path to the later report (JSON)')
  .action((beforePath: string, afterPath: string) => {
    let before: ScanReport;
    let after: ScanReport;
    try {
      before = parseReport(readFileSync(beforePath, 'utf8'));
      after = parseReport(readFileSync(afterPath, 'utf8'));
    } catch (e) {
      console.error(`could not read reports: ${(e as Error).message}`);
      process.exitCode = 2;
      return;
    }
    const d = diffReports(before, after);
    printDiff(d);
    process.exitCode = d.hasChanges ? 1 : 0;
  });

await program.parseAsync();

// --- scan pipeline -------------------------------------------------------------

async function runScan(target: string, opts: Opts): Promise<void> {
  const protocol: Protocol = opts.udp ? 'udp' : 'tcp';

  // 1. Resolve the target into a stream of (host, port) probes.
  const built = await buildTargets(target, opts, protocol);
  if (!built) return; // refused (e.g. CIDR too large)
  const { targets, total } = built;

  // 2. Resume: load prior results and skip the targets already completed.
  const planId: PlanIdentity = { target, ports: opts.ports, protocol };
  if (opts.seed !== undefined) planId.seed = opts.seed;
  let seed: ScanResultRecord[] = [];
  const done = new Set<string>();
  if (opts.resume && existsSync(opts.resume)) {
    const cp = loadCheckpoint(opts.resume);
    if (!planMatches(cp.plan, planId)) {
      console.error('resume: checkpoint plan does not match this scan (target/ports/protocol differ)');
      process.exitCode = 2;
      return;
    }
    seed = cp.report.results;
    for (const k of doneSet(cp)) done.add(k);
    console.error(`resuming: ${done.size} target(s) already done, ${total - done.size} to go`);
  }

  // 3. Checkpoint writer (to --checkpoint, or back to the --resume file).
  const cpPath = opts.checkpoint ?? opts.resume;
  const startedAtMs = Date.now();
  const writer = cpPath ? new CheckpointWriter(cpPath, planId, startedAtMs, seed) : undefined;

  // Flush progress to disk on Ctrl-C so an interrupted scan is resumable.
  const onSigint = (): void => {
    writer?.flush();
    console.error('\ninterrupted; progress saved. exiting.');
    process.exit(130);
  };
  if (writer) process.on('SIGINT', onSigint);

  // 4. Scan the remaining targets, streaming records into progress + checkpoint.
  const remaining = skipDone(targets, done);
  const progress = new Progress({ total, force: opts.progress });
  for (let i = 0; i < done.size; i++) progress.tick(false); // account resumed work in ETA
  const records: ScanResultRecord[] = [...seed];
  const openForBanner: TcpProbeResult[] = [];

  if (protocol === 'udp') {
    for await (const r of scanUdpTargets(remaining, udpOptions(opts))) {
      const rec = udpRecord(r);
      records.push(rec);
      writer?.add(rec);
      progress.tick(r.state === 'open');
    }
  } else {
    for await (const r of scanTargets(remaining, tcpOptions(opts))) {
      const rec = tcpRecord(r);
      records.push(rec);
      writer?.add(rec);
      if (r.state === 'open') openForBanner.push(r);
      progress.tick(r.state === 'open');
    }
  }
  progress.finish();

  // 5. Optional TCP fingerprint phase; merge service/version back into the records.
  if (protocol === 'tcp' && opts.banner && openForBanner.length > 0) {
    await mergeFingerprints(records, openForBanner, opts.concurrency);
  }

  // 6. Build and emit the report.
  const report = buildReport({ protocol, target, startedAt: startedAtMs, finishedAt: Date.now(), records });
  writer?.flush();
  if (writer) process.off('SIGINT', onSigint);
  emit(report, opts);
}

interface BuiltTargets {
  targets: Iterable<Target>;
  total: number;
}

async function buildTargets(target: string, opts: Opts, protocol: Protocol): Promise<BuiltTargets | undefined> {
  if (target.includes('/')) {
    const cidr = parseCidr(target);
    if (cidr.size > opts.maxHosts) {
      console.error(
        `refusing to scan ${cidr.size} hosts (${target}); raise --max-hosts to proceed. ` +
          'Only scan networks you own or are authorized to test.',
      );
      process.exitCode = 2;
      return undefined;
    }
    console.error(
      `${protocol.toUpperCase()} scanning ${cidr.size} hosts x ${opts.ports.length} ports. ` +
        'Only scan networks you own or have written permission to test.',
    );
    const planOpts: ScanPlanOptions = { randomize: !opts.seq };
    if (opts.seed !== undefined) planOpts.seed = opts.seed;
    const plan = planCidrScan(target, opts.ports, planOpts);
    return { targets: plan.targets(), total: plan.total };
  }
  const ip = await resolveHost(target);
  const ports = opts.ports;
  const targets = (function* () {
    for (const port of ports) yield { host: ip, port };
  })();
  return { targets, total: ports.length };
}

/** Yield only targets whose host:port is not already in the done-set. */
function* skipDone(targets: Iterable<Target>, done: Set<string>): Generator<Target> {
  if (done.size === 0) {
    yield* targets;
    return;
  }
  for (const t of targets) {
    if (!done.has(`${t.host}:${t.port}`)) yield t;
  }
}

function tcpOptions(opts: Opts): ScanHostOptions {
  const o: ScanHostOptions = { timeoutMs: opts.timeout, concurrency: opts.concurrency, retries: opts.retries };
  const limiter = makeLimiter(opts);
  if (limiter) o.beforeAttempt = () => limiter.take();
  return o;
}

function udpOptions(opts: Opts): ScanUdpOptions {
  const o: ScanUdpOptions = { timeoutMs: opts.timeout, concurrency: opts.concurrency, retries: opts.retries };
  const limiter = makeLimiter(opts);
  if (limiter) o.beforeAttempt = () => limiter.take();
  return o;
}

function makeLimiter(opts: Opts): RateLimiter | undefined {
  if (opts.rate === undefined) return undefined;
  return new RateLimiter({ ratePerSec: opts.rate, burst: Math.max(1, Math.ceil(opts.rate / 10)) });
}

async function mergeFingerprints(
  records: ScanResultRecord[],
  openPorts: TcpProbeResult[],
  concurrency: number,
): Promise<void> {
  const byKey = new Map(records.map((r) => [`${r.host}:${r.port}`, r]));
  const targets: Target[] = openPorts.map((r) => ({ host: r.host, port: r.port }));
  for await (const fp of pool(targets, (t) => fingerprint(t.host, t.port), { concurrency: Math.min(concurrency, 50) })) {
    if (!fp.match) continue;
    const rec = byKey.get(`${fp.host}:${fp.port}`);
    if (!rec) continue;
    rec.service = fp.match.service;
    if (fp.match.product !== undefined) rec.product = fp.match.product;
    if (fp.match.version !== undefined) rec.version = fp.match.version;
    if (fp.match.info !== undefined) rec.info = fp.match.info;
  }
}

// --- output --------------------------------------------------------------------

function emit(report: ScanReport, opts: Opts): void {
  let text: string;
  if (opts.output === 'json') text = toJson(report);
  else if (opts.output === 'grep') text = toGrep(report);
  else {
    printTextReport(report, opts.all);
    return; // the text table goes straight to stdout; nothing to write to a file
  }
  if (opts.outFile) {
    writeFileSync(opts.outFile, text);
    console.error(`wrote ${report.results.length} results to ${opts.outFile}`);
  } else {
    process.stdout.write(text);
  }
}

function printTextReport(report: ScanReport, all: boolean | undefined): void {
  console.log(`port-sentinel ${report.protocol.toUpperCase()} scan of ${report.target}`);
  const proto = report.protocol;
  const byHost = new Map<string, ScanResultRecord[]>();
  let open = 0;
  for (const r of report.results) {
    if (r.state === 'open') open++;
    const show = all || r.state === 'open' || (proto === 'udp' && r.state === 'closed');
    if (!show) continue;
    let list = byHost.get(r.host);
    if (!list) byHost.set(r.host, (list = []));
    list.push(r);
  }
  const multi = new Set(report.results.map((r) => r.host)).size > 1;
  for (const host of byHost.keys()) {
    if (multi) console.log(`\n${host}`);
    console.log('PORT      STATE          SERVICE  REASON');
    for (const r of byHost.get(host)!) {
      const svc = [r.service ?? r.product, r.version, r.info].filter(Boolean).join(' ') || '-';
      console.log(`${`${r.port}/${proto}`.padEnd(10)}${r.state.padEnd(15)}${(svc.length > 40 ? `${svc.slice(0, 37)}...` : svc).padEnd(9)}${r.reason}`);
    }
  }
  console.log(`\n${report.results.length} ports in ${(report.elapsedMs / 1000).toFixed(2)}s: ${open} open`);
}

function printDiff(d: ReportDiff): void {
  if (!d.hasChanges) {
    console.log('no changes');
    return;
  }
  const marks: Record<string, string> = { appeared: '+', disappeared: '-', changed: '~', same: ' ' };
  for (const c of d.changes) {
    const svc = c.after?.service ?? c.after?.product ?? c.before?.service ?? '';
    const tail = c.kind === 'changed' ? ` (${c.detail})` : svc ? ` ${svc}` : '';
    console.log(`${marks[c.kind]} ${c.host}:${c.port}/${c.protocol} ${c.kind}${tail}`);
  }
  console.log(`\n${d.counts.appeared} appeared, ${d.counts.disappeared} disappeared, ${d.counts.changed} changed`);
}
