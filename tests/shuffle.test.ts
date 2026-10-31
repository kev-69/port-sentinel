import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { shuffledIndices, shuffledRange } from '../src/targets/shuffle.js';

/** The defining property: the output is a permutation of [0, n). */
function isPermutation(out: number[], n: number): boolean {
  if (out.length !== n) return false;
  const seen = new Uint8Array(n);
  for (const x of out) {
    if (!Number.isInteger(x) || x < 0 || x >= n || seen[x]) return false;
    seen[x] = 1;
  }
  return true;
}

describe('shuffledIndices', () => {
  it.each([0, 1, 2, 3, 4, 5, 7, 8, 100, 256, 257, 1000, 4999])(
    'produces a permutation of [0, %d)',
    (n) => {
      expect(isPermutation([...shuffledIndices(n)], n)).toBe(true);
    },
  );

  it('is a permutation for any n (property)', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 5000 }), (n) => {
        expect(isPermutation([...shuffledIndices(n)], n)).toBe(true);
      }),
      { numRuns: 200 },
    );
  });

  it('is deterministic for a given seed', () => {
    expect([...shuffledIndices(500, { seed: 42 })]).toEqual([...shuffledIndices(500, { seed: 42 })]);
  });

  it('different seeds give different orders', () => {
    const a = [...shuffledIndices(500, { seed: 1 })];
    const b = [...shuffledIndices(500, { seed: 2 })];
    expect(a).not.toEqual(b);
  });

  it('does not just return ascending order', () => {
    const out = [...shuffledIndices(1000, { seed: 7 })];
    const ascending = out.every((x, i) => x === i);
    expect(ascending).toBe(false);
  });

  it('spreads early output across the range (not clustered at the start)', () => {
    // A real sweep would hammer low indices first. Check the first 10% of emissions
    // are not all in the first 10% of the range.
    const n = 1000;
    const out = [...shuffledIndices(n, { seed: 3 })].slice(0, 100);
    const inFirstTenth = out.filter((x) => x < n / 10).length;
    expect(inFirstTenth).toBeLessThan(50); // random would be ~10
  });

  it.each([-1, 1.5, Number.NaN])('rejects n = %s', (n) => {
    expect(() => [...shuffledIndices(n)]).toThrow(RangeError);
  });
});

describe('shuffledRange', () => {
  it('offsets by start and stays a permutation', () => {
    const out = [...shuffledRange(1000, 50, { seed: 9 })];
    expect(isPermutation(out.map((x) => x - 1000), 50)).toBe(true);
  });

  it('randomize:false yields ascending order', () => {
    expect([...shuffledRange(10, 5, { randomize: false })]).toEqual([10, 11, 12, 13, 14]);
  });
});
