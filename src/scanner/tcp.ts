import net from 'node:net';
import type { PortState, Reason, TcpProbeResult } from '../types.js';
import { pool } from './pool.js';

export interface TcpProbeOptions {
  /** Wall-clock deadline for the handshake, in milliseconds. */
  timeoutMs: number;
}

/**
 * Map a socket error code to a port state.
 *
 * The question behind every row: did the *target* (or something on the path to it)
 * tell us this, or did it come from our own machine?
 */
export function classifyError(code: string | undefined): { state: PortState; reason: Reason } {
  switch (code) {
    // Target's TCP stack answered our SYN with RST: reachable, nothing listening.
    case 'ECONNREFUSED':
      return { state: 'closed', reason: 'conn-refused' };
    case 'ECONNRESET':
      return { state: 'closed', reason: 'reset' };

    // The OS retransmitted the SYN until it gave up. Same meaning as our own deadline.
    case 'ETIMEDOUT':
      return { state: 'filtered', reason: 'no-response' };

    // A router (or the target) sent ICMP unreachable, or we have no route at all.
    case 'EHOSTUNREACH':
      return { state: 'filtered', reason: 'host-unreach' };
    case 'ENETUNREACH':
      return { state: 'filtered', reason: 'net-unreach' };

    // EMFILE (out of file descriptors), EADDRNOTAVAIL (out of ephemeral ports),
    // EACCES (local firewall policy), ... These describe us, not the target.
    default:
      return { state: 'error', reason: 'local-error' };
  }
}

/**
 * Probe one TCP port with a full connect() (Nmap's -sT).
 *
 * Never rejects: every outcome, including local failures, is a result.
 */
export function probeTcp(host: string, port: number, opts: TcpProbeOptions): Promise<TcpProbeResult> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const start = performance.now();
    let settled = false;

    const finish = (state: PortState, reason: Reason, errorCode?: string): void => {
      // 'error', 'close' and the timer can all fire for the same probe. Only the first one counts.
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      // Release the file descriptor immediately. For an open port this also tears down
      // the established connection (Node sends FIN, or RST if data is pending).
      socket.destroy();
      const result: TcpProbeResult = {
        host,
        port,
        state,
        reason,
        latencyMs: Math.round((performance.now() - start) * 100) / 100,
        attempts: 1,
      };
      if (errorCode !== undefined) result.errorCode = errorCode;
      resolve(result);
    };

    // Our own deadline, not socket.setTimeout(): that one is an *idle* timer that is
    // re-armed by activity. We want "the handshake must finish within N ms".
    const deadline = setTimeout(() => finish('filtered', 'no-response'), opts.timeoutMs);

    socket.once('connect', () => finish('open', 'syn-ack'));

    // `on`, not `once`: an EventEmitter 'error' with no listener throws and crashes the
    // process, so a listener must stay attached for the socket's whole life.
    socket.on('error', (err: NodeJS.ErrnoException) => {
      const { state, reason } = classifyError(err.code);
      finish(state, reason, err.code);
    });

    socket.connect({ host, port });
  });
}

export interface RetryOptions extends TcpProbeOptions {
  /** Extra attempts after a no-response timeout. 0 = never retry. */
  retries: number;
  /** Called before every attempt, including retries: each attempt sends a SYN. */
  beforeAttempt?: () => Promise<void>;
}

/**
 * Probe with retries, but only when silence could be packet loss.
 *
 * SYN/ACK, RST and ICMP unreachable are answers; asking again would get the same answer.
 * Silence is the one outcome that a single lost SYN or SYN/ACK can produce by accident.
 */
export async function probeTcpWithRetry(
  host: string,
  port: number,
  opts: RetryOptions,
): Promise<TcpProbeResult> {
  for (let attempt = 1; ; attempt++) {
    await opts.beforeAttempt?.();
    const result = await probeTcp(host, port, opts);
    const retryable = result.state === 'filtered' && result.reason === 'no-response';
    if (!retryable || attempt > opts.retries) return { ...result, attempts: attempt };
  }
}

export interface ScanHostOptions extends RetryOptions {
  concurrency: number;
}

/**
 * Scan many ports on one host with bounded concurrency. Yields results as they complete,
 * so callers can stream them (progress, output) instead of waiting for the whole scan.
 *
 * concurrency = 1 reproduces the Stage 1 sequential scan.
 */
export function scanHost(
  host: string,
  ports: Iterable<number>,
  opts: ScanHostOptions,
): AsyncGenerator<TcpProbeResult, void, undefined> {
  return pool(ports, (port) => probeTcpWithRetry(host, port, opts), { concurrency: opts.concurrency });
}
