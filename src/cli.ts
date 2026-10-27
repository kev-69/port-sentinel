#!/usr/bin/env node
import { Command } from 'commander';
import { z } from 'zod';
import { scanOptionsSchema } from './config.js';
import { scanHostSequential } from './scanner/tcp.js';
import { resolveHost } from './targets/host.js';
import type { PortState } from './types.js';

const program = new Command()
  .name('port-sentinel')
  .description('TCP port scanner and service fingerprinter. Only scan hosts you own or are authorized to test.');

program
  .command('scan')
  .description('TCP connect scan of a single host')
  .argument('<target>', 'IP address or hostname')
  .option('-p, --ports <spec>', 'ports, e.g. 22,80,8000-8100', '1-1024')
  .option('-t, --timeout <ms>', 'per-port connect deadline in ms', '1000')
  .option('-a, --all', 'also list closed and filtered ports')
  .action(async (target: string, rawOpts: unknown) => {
    const parsed = scanOptionsSchema.safeParse(rawOpts);
    if (!parsed.success) {
      console.error(z.prettifyError(parsed.error));
      process.exitCode = 2;
      return;
    }
    const opts = parsed.data;

    const ip = await resolveHost(target);
    const started = performance.now();
    const results = await scanHostSequential(ip, opts.ports, { timeoutMs: opts.timeout });
    const elapsed = ((performance.now() - started) / 1000).toFixed(2);

    console.log(`port-sentinel scan of ${target}${ip !== target ? ` (${ip})` : ''}`);
    console.log('PORT      STATE     REASON        LATENCY');
    for (const r of results) {
      if (!opts.all && r.state !== 'open') continue;
      const detail = r.state === 'error' && r.errorCode ? ` (${r.errorCode})` : '';
      console.log(
        `${`${r.port}/tcp`.padEnd(10)}${r.state.padEnd(10)}${r.reason.padEnd(14)}${r.latencyMs}ms${detail}`,
      );
    }

    const counts: Record<PortState, number> = { open: 0, closed: 0, filtered: 0, error: 0 };
    for (const r of results) counts[r.state]++;
    console.log(
      `\n${results.length} ports in ${elapsed}s: ${counts.open} open, ${counts.closed} closed, ` +
        `${counts.filtered} filtered, ${counts.error} error`,
    );
  });

await program.parseAsync();
