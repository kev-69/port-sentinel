import { describe, expect, it } from 'vitest';
import { dnsProbe, emptyProbe, ntpProbe, probeForPort } from '../src/scanner/udp-probes.js';

describe('dnsProbe', () => {
  it('builds a 17-byte root NS query with RD set and QDCOUNT=1', () => {
    const { payload } = dnsProbe.build();
    expect(payload.length).toBe(17); // 12 header + 5 question
    expect(payload.readUInt16BE(2)).toBe(0x0100); // flags: recursion desired
    expect(payload.readUInt16BE(4)).toBe(1); // QDCOUNT
    expect([...payload.subarray(12)]).toEqual([0x00, 0x00, 0x02, 0x00, 0x01]); // root, NS, IN
  });

  it('accepts a reply that echoes the ID and sets the QR bit, and reports rcode/answers', () => {
    const { payload, validate } = dnsProbe.build();
    const reply = Buffer.alloc(12);
    payload.copy(reply, 0, 0, 2); // echo the random ID
    reply.writeUInt16BE(0x8180, 2); // QR=1, RD=1, RA=1, rcode=NOERROR
    reply.writeUInt16BE(13, 6); // 13 answers (the 13 root servers)
    expect(validate(reply)).toEqual({ valid: true, service: 'dns', info: 'rcode=NOERROR answers=13' });
  });

  it('rejects a reply with the wrong ID (not our query)', () => {
    const { validate } = dnsProbe.build();
    const reply = Buffer.alloc(12);
    reply.writeUInt16BE(0xffff, 0);
    reply.writeUInt16BE(0x8180, 2);
    expect(validate(reply).valid).toBe(false);
  });

  it('rejects a reply without the QR bit', () => {
    const { payload, validate } = dnsProbe.build();
    const reply = Buffer.alloc(12);
    payload.copy(reply, 0, 0, 2);
    reply.writeUInt16BE(0x0100, 2); // QR=0 (still a query)
    expect(validate(reply).valid).toBe(false);
  });

  it('rejects a too-short reply', () => {
    const { validate } = dnsProbe.build();
    expect(validate(Buffer.alloc(4)).valid).toBe(false);
  });

  it('uses a fresh random ID per build', () => {
    const a = dnsProbe.build().payload.subarray(0, 2);
    const b = dnsProbe.build().payload.subarray(0, 2);
    // Astronomically unlikely to collide; guards against a hard-coded ID.
    expect(a.equals(b)).toBe(false);
  });
});

describe('ntpProbe', () => {
  it('builds a 48-byte client request (LI=0 VN=4 Mode=3)', () => {
    const { payload } = ntpProbe.build();
    expect(payload.length).toBe(48);
    expect(payload[0]).toBe(0x23);
  });

  it('accepts a server reply that echoes our transmit timestamp as origin', () => {
    const { payload, validate } = ntpProbe.build();
    const reply = Buffer.alloc(48);
    reply[0] = (4 << 3) | 4; // VN=4, Mode=4 (server)
    reply[1] = 2; // stratum 2
    payload.copy(reply, 24, 40, 48); // origin = our transmit timestamp
    expect(validate(reply)).toEqual({ valid: true, service: 'ntp', info: 'stratum=2 version=4' });
  });

  it('rejects a reply whose origin does not match (spoof / stray packet)', () => {
    const { validate } = ntpProbe.build();
    const reply = Buffer.alloc(48);
    reply[0] = (4 << 3) | 4;
    reply.fill(0xab, 24, 32); // wrong origin timestamp
    expect(validate(reply).valid).toBe(false);
  });

  it('rejects a non-server mode', () => {
    const { payload, validate } = ntpProbe.build();
    const reply = Buffer.alloc(48);
    reply[0] = (4 << 3) | 3; // Mode=3 (client), not a server reply
    payload.copy(reply, 24, 40, 48);
    expect(validate(reply).valid).toBe(false);
  });
});

describe('probeForPort', () => {
  it('maps 53 to dns, 123 to ntp, else empty', () => {
    expect(probeForPort(53)).toBe(dnsProbe);
    expect(probeForPort(123)).toBe(ntpProbe);
    expect(probeForPort(80)).toBe(emptyProbe);
  });

  it('empty probe sends nothing and never validates', () => {
    const { payload, validate } = emptyProbe.build();
    expect(payload.length).toBe(0);
    expect(validate(Buffer.from('anything')).valid).toBe(false);
  });
});
