import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { MAX_PORT, MIN_PORT, parsePorts, scanOptionsSchema } from '../src/config.js';

describe('parsePorts', () => {
  it('parses single ports, ranges and mixes', () => {
    expect(parsePorts('22')).toEqual([22]);
    expect(parsePorts('20-23')).toEqual([20, 21, 22, 23]);
    expect(parsePorts('443, 80,22-23')).toEqual([22, 23, 80, 443]);
  });

  it('de-duplicates overlapping entries', () => {
    expect(parsePorts('80,79-81,80')).toEqual([79, 80, 81]);
  });

  it.each(['0', '65536', '-1', 'http', '80-', '1-2-3', '10-5', '', '22,,80', '1e3'])(
    'rejects %j',
    (spec) => {
      expect(() => parsePorts(spec)).toThrow();
    },
  );

  // Property: whatever valid ports we start from, writing them as a spec and parsing
  // it back gives the same set, sorted. fast-check tries hundreds of random inputs
  // and shrinks any failure to the smallest one that breaks.
  it('round-trips any set of valid ports', () => {
    const port = fc.integer({ min: MIN_PORT, max: MAX_PORT });
    fc.assert(
      fc.property(fc.array(port, { minLength: 1, maxLength: 50 }), (ports) => {
        const expected = [...new Set(ports)].sort((a, b) => a - b);
        expect(parsePorts(ports.join(','))).toEqual(expected);
      }),
    );
  });

  it('expands any valid range to exactly hi - lo + 1 ports', () => {
    const port = fc.integer({ min: MIN_PORT, max: MAX_PORT });
    fc.assert(
      fc.property(port, port, (a, b) => {
        const [lo, hi] = a <= b ? [a, b] : [b, a];
        const result = parsePorts(`${lo}-${hi}`);
        expect(result.length).toBe(hi - lo + 1);
        expect(result[0]).toBe(lo);
        expect(result.at(-1)).toBe(hi);
      }),
    );
  });
});

describe('scanOptionsSchema', () => {
  // What commander hands us: every value is a string, and --rate is absent unless given.
  const cli = { ports: '22,80', timeout: '500', concurrency: '500', retries: '1' };

  it('accepts CLI strings and converts them', () => {
    expect(scanOptionsSchema.parse(cli)).toEqual({
      ports: [22, 80],
      timeout: 500,
      concurrency: 500,
      retries: 1,
      all: false,
    });
    expect(scanOptionsSchema.parse({ ...cli, rate: '250' }).rate).toBe(250);
  });

  it('rejects a bad port spec with a readable message', () => {
    const r = scanOptionsSchema.safeParse({ ...cli, ports: '99999' });
    expect(r.success).toBe(false);
    expect(r.error?.issues[0]?.message).toMatch(/out of range/);
  });

  it.each(['0', '-5', 'abc', '1.5', '60001'])('rejects timeout %j', (timeout) => {
    expect(scanOptionsSchema.safeParse({ ...cli, timeout }).success).toBe(false);
  });

  it.each(['0', '-1', '2.5', '10001'])('rejects concurrency %j', (concurrency) => {
    expect(scanOptionsSchema.safeParse({ ...cli, concurrency }).success).toBe(false);
  });

  it.each(['0', '-1', 'fast'])('rejects rate %j', (rate) => {
    expect(scanOptionsSchema.safeParse({ ...cli, rate }).success).toBe(false);
  });

  it.each(['-1', '11', '0.5'])('rejects retries %j', (retries) => {
    expect(scanOptionsSchema.safeParse({ ...cli, retries }).success).toBe(false);
  });
});
