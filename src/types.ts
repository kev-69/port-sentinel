/**
 * What we concluded about a TCP port.
 * - open:     the handshake completed (something is listening)
 * - closed:   the host answered with RST (reachable, nothing listening)
 * - filtered: no answer, or an ICMP error (something in the path is blocking or the host is gone)
 * - error:    the probe failed for a local reason; says nothing about the target
 */
export type PortState = 'open' | 'closed' | 'filtered' | 'error';

/**
 * UDP adds one state TCP can't produce: `open|filtered`. UDP has no handshake, so silence
 * could be an open service ignoring our datagram *or* a firewall dropping it — genuinely
 * indistinguishable, so we report both.
 */
export type UdpState = PortState | 'open|filtered';

/** Why we concluded `state`. Mirrors the strings `nmap --reason` prints. */
export type Reason =
  | 'syn-ack'
  | 'conn-refused'
  | 'reset'
  | 'udp-response'
  | 'port-unreach'
  | 'no-response'
  | 'host-unreach'
  | 'net-unreach'
  | 'local-error';

export type Protocol = 'tcp' | 'udp';

/** One thing to probe: a host (as a string, v4 or v6) and a port. */
export interface Target {
  host: string;
  port: number;
}

export interface ProbeResult {
  host: string;
  port: number;
  state: PortState;
  reason: Reason;
  /** Time from sending to the outcome of the *last* attempt, in milliseconds. */
  latencyMs: number;
  /** How many attempts were made (1 + retries used). */
  attempts: number;
  /** The raw errno code (e.g. ECONNREFUSED) when the outcome came from an error. */
  errorCode?: string;
}

export type TcpProbeResult = ProbeResult;

export interface UdpProbeResult extends Omit<ProbeResult, 'state'> {
  state: UdpState;
  /** Which payload we sent: "dns", "ntp" or "empty". */
  probe: string;
  /** Set when the reply parsed as the protocol we asked for. */
  service?: string;
  /** Protocol details pulled from the reply, e.g. "rcode=NOERROR answers=13". */
  info?: string;
}
