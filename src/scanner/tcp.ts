import net from 'node:net';
import type { PortState, Reason, TcpProbeResult } from '../types.js';

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

/**
 * Probe ports one at a time. Deliberately naive: total time is the sum of every probe,
 * so filtered ports cost a full timeout each. Stage 2 replaces this with a pool.
 */
export async function scanHostSequential(
  host: string,
  ports: readonly number[],
  opts: TcpProbeOptions,
): Promise<TcpProbeResult[]> {
  const results: TcpProbeResult[] = [];
  for (const port of ports) {
    results.push(await probeTcp(host, port, opts));
  }
  return results;
}
