#!/usr/bin/env node
import { Command } from 'commander';
import { z } from 'zod';
import { scanOptionsSchema } from './config.js';
import { RateLimiter } from './scanner/rate-limiter.js';
import { scanHost, type ScanHostOptions } from './scanner/tcp.js';
import { resolveHost } from './targets/host.js';
import type { PortState, TcpProbeResult } from './types.js';

const program = new Command()
  .name('port-sentinel')
  .description('TCP port scanner and service fingerprinter. Only scan hosts you own or are authorized to test.');

program
  .command('scan')
  .description('TCP connect scan of a single host')
  .argument('<target>', 'IP address or hostname')
  .option('-p, --ports <spec>', 'ports, e.g. 22,80,8000-8100', '1-1024')
  .option('-t, --timeout <ms>', 'per-attempt connect deadline in ms', '1000')
  .option('-c, --concurrency <n>', 'max probes in flight', '500')
  .option('-r, --rate <pps>', 'max connection attempts per second (default: unlimited)')
  .option('--retries <n>', 'extra attempts for ports that did not answer', '1')
  .option('-a, --all', 'also list closed and filtered ports')
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

    const ip = await resolveHost(target);
    const started = performance.now();
    const results: TcpProbeResult[] = [];
    for await (const r of scanHost(ip, opts.ports, scanOpts)) results.push(r);
    const elapsed = ((performance.now() - started) / 1000).toFixed(2);

    // The pool yields in completion order; sort for a stable, readable report.
    results.sort((a, b) => a.port - b.port);

    console.log(`port-sentinel scan of ${target}${ip !== target ? ` (${ip})` : ''}`);
    console.log('PORT      STATE     REASON        TRIES  LATENCY');
    for (const r of results) {
      if (!opts.all && r.state !== 'open') continue;
      const detail = r.state === 'error' && r.errorCode ? ` (${r.errorCode})` : '';
      console.log(
        `${`${r.port}/tcp`.padEnd(10)}${r.state.padEnd(10)}${r.reason.padEnd(14)}` +
          `${String(r.attempts).padEnd(7)}${r.latencyMs}ms${detail}`,
      );
    }

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
  });

await program.parseAsync();
