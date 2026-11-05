import { randomBytes } from 'node:crypto';

/**
 * A UDP probe: the payload to send, and a validator that decides whether a reply really
 * came from the protocol we asked for. The validator is what lets us say "open" with
 * confidence instead of "something sent bytes back".
 */
export interface UdpProbe {
  name: string;
  /** Build the datagram. May carry per-probe state (e.g. a nonce) via the returned `validate`. */
  build(): { payload: Buffer; validate: (reply: Buffer) => UdpValidation };
}

export interface UdpValidation {
  /** True only if the reply is a well-formed answer to *our* probe. */
  valid: boolean;
  service?: string;
  info?: string;
}

const DNS_RCODES = ['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED'];

/**
 * DNS query for the root zone's NS records (RFC 1035 §4.1).
 * Header: random ID, flags 0x0100 (RD), QDCOUNT=1. Question: root name (one 0 byte),
 * QTYPE=NS(2), QCLASS=IN(1). No real domain name is looked up.
 */
export const dnsProbe: UdpProbe = {
  name: 'dns',
  build() {
    const id = randomBytes(2);
    const header = Buffer.alloc(12);
    id.copy(header, 0);
    header.writeUInt16BE(0x0100, 2); // flags: recursion desired
    header.writeUInt16BE(1, 4); // QDCOUNT = 1
    const question = Buffer.from([0x00, 0x00, 0x02, 0x00, 0x01]); // root, QTYPE=NS, QCLASS=IN
    const payload = Buffer.concat([header, question]);

    const validate = (reply: Buffer): UdpValidation => {
      // Must be at least a header, echo our ID, and have the QR (response) bit set.
      if (reply.length < 12) return { valid: false };
      if (reply[0] !== id[0] || reply[1] !== id[1]) return { valid: false };
      const flags = reply.readUInt16BE(2);
      if ((flags & 0x8000) === 0) return { valid: false }; // QR bit
      const rcode = flags & 0x000f;
      const answers = reply.readUInt16BE(6);
      return {
        valid: true,
        service: 'dns',
        info: `rcode=${DNS_RCODES[rcode] ?? rcode} answers=${answers}`,
      };
    };
    return { payload, validate };
  },
};

/**
 * NTP client request (RFC 5905 §7.3). 48 bytes. First byte 0x23 = LI 0, VN 4, Mode 3.
 * A random transmit timestamp (bytes 40-47) is echoed back by the server in the origin
 * field (bytes 24-31), which is how we know the reply is answering *us*.
 */
export const ntpProbe: UdpProbe = {
  name: 'ntp',
  build() {
    const payload = Buffer.alloc(48);
    payload[0] = 0x23;
    const nonce = randomBytes(8);
    nonce.copy(payload, 40); // transmit timestamp

    const validate = (reply: Buffer): UdpValidation => {
      if (reply.length < 48) return { valid: false };
      const mode = reply[0]! & 0x07;
      if (mode !== 4) return { valid: false }; // must be a server reply
      // The origin timestamp must equal the transmit timestamp we sent.
      if (!reply.subarray(24, 32).equals(nonce)) return { valid: false };
      const version = (reply[0]! >> 3) & 0x07;
      const stratum = reply[1]!;
      return { valid: true, service: 'ntp', info: `stratum=${stratum} version=${version}` };
    };
    return { payload, validate };
  },
};

/** An empty datagram: most services ignore it, so expect open|filtered. */
export const emptyProbe: UdpProbe = {
  name: 'empty',
  build: () => ({ payload: Buffer.alloc(0), validate: () => ({ valid: false }) }),
};

/** Pick the probe for a port: 53 -> DNS, 123 -> NTP, otherwise empty. */
export function probeForPort(port: number): UdpProbe {
  if (port === 53) return dnsProbe;
  if (port === 123) return ntpProbe;
  return emptyProbe;
}
