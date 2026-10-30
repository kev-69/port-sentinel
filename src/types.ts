/**
 * What we concluded about a port.
 * - open:     the handshake completed (something is listening)
 * - closed:   the host answered with RST (reachable, nothing listening)
 * - filtered: no answer, or an ICMP error (something in the path is blocking or the host is gone)
 * - error:    the probe failed for a local reason; says nothing about the target
 */
export type PortState = 'open' | 'closed' | 'filtered' | 'error';

/** Why we concluded `state`. Mirrors the strings `nmap --reason` prints. */
export type Reason =
  | 'syn-ack'
  | 'conn-refused'
  | 'reset'
  | 'no-response'
  | 'host-unreach'
  | 'net-unreach'
  | 'local-error';

export interface TcpProbeResult {
  host: string;
  port: number;
  state: PortState;
  reason: Reason;
  /** Time from connect() to the outcome of the *last* attempt, in milliseconds. */
  latencyMs: number;
  /** How many connect() attempts were made (1 + retries used). */
  attempts: number;
  /** The raw errno code (e.g. ECONNREFUSED) when the outcome came from an error. */
  errorCode?: string;
}
