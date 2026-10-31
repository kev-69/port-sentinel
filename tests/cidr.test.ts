import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { cidrAddresses, intToIp, ipToInt, parseCidr, prefixMask } from '../src/targets/cidr.js';

describe('ipToInt / intToIp', () => {
  it.each([
    ['0.0.0.0', 0],
    ['0.0.0.1', 1],
    ['0.0.1.0', 256],
    ['127.0.0.1', 2130706433],
    // The signed-shift trap: top bit set must stay positive.
    ['128.0.0.0', 2147483648],
    ['192.168.1.1', 3232235777],
    ['255.255.255.255', 4294967295],
  ])('%s <-> %d', (ip, n) => {
    expect(ipToInt(ip)).toBe(n);
    expect(intToIp(n)).toBe(ip);
  });

  it.each(['256.0.0.1', '1.2.3', '1.2.3.4.5', 'a.b.c.d', '', '1.2.3.', '-1.0.0.0', '1.2.3.300'])(
    'rejects %j',
    (bad) => {
      expect(() => ipToInt(bad)).toThrow();
    },
  );

  it('round-trips every uint32 (property)', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 0xffffffff }), (n) => {
        expect(ipToInt(intToIp(n))).toBe(n);
      }),
    );
  });
});

describe('prefixMask', () => {
  it.each([
    [0, 0],
    [1, 0x80000000],
    [8, 0xff000000],
    [24, 0xffffff00],
    [32, 0xffffffff],
  ])('/%d -> %d', (prefix, mask) => {
    expect(prefixMask(prefix)).toBe(mask >>> 0);
  });
});

describe('parseCidr', () => {
  it('parses a /24', () => {
    expect(parseCidr('192.168.1.0/24')).toEqual({
      network: ipToInt('192.168.1.0'),
      prefix: 24,
      size: 256,
      first: ipToInt('192.168.1.0'),
      last: ipToInt('192.168.1.255'),
    });
  });

  it('zeroes host bits (192.168.1.5/24 -> .0 network)', () => {
    expect(intToIp(parseCidr('192.168.1.5/24').network)).toBe('192.168.1.0');
  });

  it.each([
    ['10.0.0.0/8', 16777216],
    ['172.16.0.0/12', 1048576],
    ['192.168.0.0/16', 65536],
    ['192.168.1.0/30', 4],
    ['192.168.1.0/31', 2],
    ['192.168.1.1/32', 1],
    ['0.0.0.0/0', 4294967296],
  ])('%s has size %d', (spec, size) => {
    expect(parseCidr(spec).size).toBe(size);
  });

  it('keeps last address exact for /0', () => {
    expect(parseCidr('0.0.0.0/0').last).toBe(4294967295);
  });

  it('treats a bare address as /32', () => {
    expect(parseCidr('8.8.8.8')).toMatchObject({ prefix: 32, size: 1 });
  });

  it.each(['1.2.3.0/33', '1.2.3.0/-1', '1.2.3.0/abc', '256.0.0.0/24'])('rejects %j', (bad) => {
    expect(() => parseCidr(bad)).toThrow();
  });
});

describe('cidrAddresses', () => {
  it('yields first..last inclusive', () => {
    const addrs = [...cidrAddresses(parseCidr('192.168.1.0/30'))].map(intToIp);
    expect(addrs).toEqual(['192.168.1.0', '192.168.1.1', '192.168.1.2', '192.168.1.3']);
  });

  it('yields exactly `size` addresses', () => {
    expect([...cidrAddresses(parseCidr('10.1.2.0/28'))]).toHaveLength(16);
  });
});
