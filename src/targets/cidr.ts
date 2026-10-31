/**
 * IPv4 address math for CIDR expansion.
 *
 * Addresses are handled as unsigned 32-bit integers. The recurring hazard is that
 * JavaScript's bitwise operators work on *signed* 32-bit values, so anything with the
 * top bit set (first octet >= 128) comes out negative unless we coerce with `>>> 0`.
 */

const OCTET = /^\d{1,3}$/;

/** Parse "a.b.c.d" into an unsigned 32-bit integer. Throws on anything malformed. */
export function ipToInt(ip: string): number {
  const parts = ip.split('.');
  if (parts.length !== 4) throw new Error(`"${ip}" is not a dotted-quad IPv4 address`);
  let acc = 0;
  for (const part of parts) {
    if (!OCTET.test(part)) throw new Error(`"${ip}" has a non-numeric octet "${part}"`);
    const n = Number(part);
    if (n > 255) throw new Error(`"${ip}" has octet ${n} > 255`);
    // Build up with multiplication, not <<, so the running value never goes negative.
    acc = acc * 256 + n;
  }
  // acc is already 0..2^32-1; >>> 0 pins the type as uint32.
  return acc >>> 0;
}

/** Inverse of ipToInt. */
export function intToIp(n: number): string {
  return `${(n >>> 24) & 0xff}.${(n >>> 16) & 0xff}.${(n >>> 8) & 0xff}.${n & 0xff}`;
}

export interface Cidr {
  /** Base address with host bits zeroed. */
  network: number;
  /** Prefix length 0..32. */
  prefix: number;
  /** Number of addresses in the block (plain double; up to 2^32). */
  size: number;
  /** First address (== network). */
  first: number;
  /** Last address (== network + size - 1). */
  last: number;
}

/** Build the 32-bit netmask for a prefix length. */
export function prefixMask(prefix: number): number {
  if (prefix === 0) return 0; // `0xFFFFFFFF << 32` would wrap to << 0: special-case it.
  return (0xffffffff << (32 - prefix)) >>> 0;
}

/** Parse "network/prefix". A bare address (no slash) is treated as /32. */
export function parseCidr(spec: string): Cidr {
  const slash = spec.indexOf('/');
  const ipPart = slash === -1 ? spec : spec.slice(0, slash);
  const prefix = slash === -1 ? 32 : Number(spec.slice(slash + 1));
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new Error(`"${spec}" has an invalid prefix (expected /0../32)`);
  }
  const ip = ipToInt(ipPart);
  const mask = prefixMask(prefix);
  const network = (ip & mask) >>> 0;
  const size = 2 ** (32 - prefix);
  return { network, prefix, size, first: network, last: network + size - 1 };
}

/** Yield every address in the block, in ascending order, as uint32 values. */
export function* cidrAddresses(cidr: Cidr): Generator<number> {
  for (let i = 0; i < cidr.size; i++) yield (cidr.first + i) >>> 0;
}
