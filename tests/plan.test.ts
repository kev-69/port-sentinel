import { describe, expect, it } from 'vitest';
import { planCidrScan } from '../src/targets/plan.js';
import type { Target } from '../src/types.js';

const key = (t: Target): string => `${t.host}:${t.port}`;

describe('planCidrScan', () => {
  it('counts hosts x ports', () => {
    const plan = planCidrScan('192.168.1.0/30', [22, 80], {});
    expect(plan.hostCount).toBe(4);
    expect(plan.portCount).toBe(2);
    expect(plan.total).toBe(8);
  });

  it('covers every (host, port) exactly once', () => {
    const ports = [22, 80, 443];
    const plan = planCidrScan('192.168.1.0/29', ports, { seed: 5 });
    const targets = [...plan.targets()];
    expect(targets).toHaveLength(8 * 3);
    const unique = new Set(targets.map(key));
    expect(unique.size).toBe(24);
    for (let h = 0; h < 8; h++) {
      for (const p of ports) expect(unique.has(`192.168.1.${h}:${p}`)).toBe(true);
    }
  });

  it('interleaves hosts rather than finishing one before the next (randomized)', () => {
    const plan = planCidrScan('10.0.0.0/24', [80, 443], { seed: 1 });
    const first20 = [...plan.targets()].slice(0, 20);
    const distinctHosts = new Set(first20.map((t) => t.host));
    // Sequential order would show at most a couple of hosts in the first 20 probes.
    expect(distinctHosts.size).toBeGreaterThan(5);
  });

  it('--seq produces ascending host-major order', () => {
    const plan = planCidrScan('192.168.1.0/30', [22, 80], { randomize: false });
    expect([...plan.targets()].map(key)).toEqual([
      '192.168.1.0:22',
      '192.168.1.0:80',
      '192.168.1.1:22',
      '192.168.1.1:80',
      '192.168.1.2:22',
      '192.168.1.2:80',
      '192.168.1.3:22',
      '192.168.1.3:80',
    ]);
  });

  it('is reproducible for a given seed', () => {
    const a = [...planCidrScan('10.0.0.0/28', [1, 2, 3], { seed: 99 }).targets()].map(key);
    const b = [...planCidrScan('10.0.0.0/28', [1, 2, 3], { seed: 99 }).targets()].map(key);
    expect(a).toEqual(b);
  });

  it('throws with no ports', () => {
    expect(() => planCidrScan('10.0.0.0/30', [], {})).toThrow();
  });
});
