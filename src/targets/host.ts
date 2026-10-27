import { lookup } from 'node:dns/promises';
import net from 'node:net';

/**
 * Turn a target into a single IP address, resolving hostnames once up front.
 *
 * If we passed a hostname to every connect() instead, each probe would do its own DNS
 * lookup. That slows the scan down, puts the lookup time inside the probe's deadline,
 * and can make different ports hit different IPs when the name has several A records.
 */
export async function resolveHost(target: string): Promise<string> {
  if (net.isIP(target) !== 0) return target;
  const { address } = await lookup(target);
  return address;
}
