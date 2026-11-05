import dgram from 'node:dgram';
import net from 'node:net';
import type { Reason, Target, UdpProbeResult, UdpState } from '../types.js';
import { pool } from './pool.js';
import { probeForPort } from './udp-probes.js';

export interface UdpProbeOptions {
  /** How long to wait for a reply before calling it silence, in ms. */
  timeoutMs: number;
}

/** Map a dgram socket error code to a UDP port state. */
export function classifyUdpError(code: string | undefined): { state: UdpState; reason: Reason } {
  switch (code) {
    // ICMP port unreachable, surfaced as ECONNREFUSED on a connected UDP socket (Linux).
    case 'ECONNREFUSED':
      return { state: 'closed', reason: 'port-unreach' };
    case 'EHOSTUNREACH':
      return { state: 'filtered', reason: 'host-unreach' };
    case 'ENETUNREACH':
      return { state: 'filtered', reason: 'net-unreach' };
    default:
      return { state: 'error', reason: 'local-error' };
  }
}

/**
 * Probe one UDP port by sending a protocol-appropriate payload and waiting for a reply.
 *
 * Never rejects. Silence becomes `open|filtered` because, unlike TCP, we cannot tell an
 * open-but-quiet service apart from a firewall that dropped the datagram.
 */
export function probeUdp(host: string, port: number, opts: UdpProbeOptions): Promise<UdpProbeResult> {
  const probe = probeForPort(port);
  const { payload, validate } = probe.build();
  const family = net.isIPv6(host) ? 'udp6' : 'udp4';

  return new Promise((resolve) => {
    const socket = dgram.createSocket(family);
    const start = performance.now();
    let settled = false;

    const finish = (state: UdpState, reason: Reason, extra?: Partial<UdpProbeResult>): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      socket.close();
      const result: UdpProbeResult = {
        host,
        port,
        state,
        reason,
        probe: probe.name,
        latencyMs: Math.round((performance.now() - start) * 100) / 100,
        attempts: 1,
        ...extra,
      };
      resolve(result);
    };

    const deadline = setTimeout(() => finish('open|filtered', 'no-response'), opts.timeoutMs);

    socket.on('message', (reply: Buffer) => {
      // Any reply means a service is there. Validation only decides whether we can name it.
      const v = validate(reply);
      const extra: Partial<UdpProbeResult> = {};
      if (v.service !== undefined) extra.service = v.service;
      if (v.info !== undefined) extra.info = v.info;
      else if (!v.valid) extra.info = `${reply.length}B reply (unrecognized)`;
      finish('open', 'udp-response', extra);
    });

    socket.on('error', (err: NodeJS.ErrnoException) => {
      const { state, reason } = classifyUdpError(err.code);
      finish(state, reason, err.code !== undefined ? { errorCode: err.code } : undefined);
    });

    // connect() so the kernel delivers ICMP errors back to us (Linux) and filters
    // datagrams to only this peer. Then send the probe payload.
    socket.connect(port, host, () => {
      socket.send(payload, (err) => {
        // A synchronous send error (e.g. EMSGSIZE) surfaces here, not on 'error'.
        if (err) finish('error', 'local-error', { errorCode: (err as NodeJS.ErrnoException).code ?? 'send-error' });
      });
    });
  });
}

export interface UdpRetryOptions extends UdpProbeOptions {
  retries: number;
  beforeAttempt?: () => Promise<void>;
}

/** Probe with retries. Only silence (open|filtered / no-response) is retried. */
export async function probeUdpWithRetry(host: string, port: number, opts: UdpRetryOptions): Promise<UdpProbeResult> {
  for (let attempt = 1; ; attempt++) {
    await opts.beforeAttempt?.();
    const result = await probeUdp(host, port, opts);
    const retryable = result.state === 'open|filtered' && result.reason === 'no-response';
    if (!retryable || attempt > opts.retries) return { ...result, attempts: attempt };
  }
}

export interface ScanUdpOptions extends UdpRetryOptions {
  concurrency: number;
}

/** Scan an arbitrary stream of UDP targets with bounded concurrency. */
export function scanUdpTargets(
  targets: Iterable<Target>,
  opts: ScanUdpOptions,
): AsyncGenerator<UdpProbeResult, void, undefined> {
  return pool(targets, (t) => probeUdpWithRetry(t.host, t.port, opts), { concurrency: opts.concurrency });
}

/** Scan many UDP ports on one host. */
export function scanUdpHost(
  host: string,
  ports: Iterable<number>,
  opts: ScanUdpOptions,
): AsyncGenerator<UdpProbeResult, void, undefined> {
  const targets = (function* () {
    for (const port of ports) yield { host, port };
  })();
  return scanUdpTargets(targets, opts);
}
