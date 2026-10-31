/**
 * A lazy pseudo-random permutation of [0, n) using a small Feistel network.
 *
 * Why not Fisher-Yates: that needs the whole array in memory. A /8 across 1000 ports is
 * 16 billion targets, which we can generate on demand but never store. A Feistel network
 * is a *stateless* bijection: given an index it returns its shuffled position in O(1),
 * so we can walk 0,1,2,... and emit a permutation without an array.
 *
 * Why a Feistel network is always a permutation: each round maps (L, R) -> (R, L XOR F(R)).
 * That is invertible for *any* function F (run the rounds backwards), and an invertible
 * map on a finite set is a bijection. So we get a permutation regardless of how good or
 * bad F is; F only controls how well-mixed the order looks.
 */

/** A cheap integer avalanche hash (based on MurmurHash3's finalizer), masked by the caller. */
function roundFn(half: number, round: number, seed: number): number {
  let h = (half + Math.imul(round + 1, 0x9e3779b1) + seed) | 0;
  h = Math.imul(h ^ (h >>> 15), 0x85ebca6b);
  h ^= h >>> 13;
  return h >>> 0;
}

export interface ShuffleOptions {
  seed?: number;
  rounds?: number;
}

/**
 * Yield a permutation of [0, n). Deterministic for a given (n, seed, rounds).
 */
export function* shuffledIndices(n: number, opts: ShuffleOptions = {}): Generator<number> {
  if (!Number.isInteger(n) || n < 0) throw new RangeError(`n must be a non-negative integer, got ${n}`);
  if (n === 0) return;
  if (n === 1) {
    yield 0;
    return;
  }
  const seed = opts.seed ?? 0x2545f491;
  const rounds = opts.rounds ?? 4;

  // Round the domain up to 2^bits with an even bit count, so the two halves are equal
  // width (balanced Feistel). The extra values are skipped by cycle-walking below.
  let bits = Math.ceil(Math.log2(n));
  if (bits % 2 === 1) bits++;
  const halfBits = bits / 2;
  const mask = (1 << halfBits) - 1; // halfBits <= 16, so this fits in a signed int

  const permute = (x: number): number => {
    let left = (x >>> halfBits) & mask;
    let right = x & mask;
    for (let i = 0; i < rounds; i++) {
      const next = left ^ (roundFn(right, i, seed) & mask);
      left = right;
      right = next;
    }
    return ((left << halfBits) | right) >>> 0;
  };

  // Walk the *input* over [0, n) only. For each i, cycle-walk the permutation until it
  // lands back inside [0, n). Because i is itself in [0, n), its permutation orbit is
  // guaranteed to return there, so this always terminates. (Iterating i over the full
  // domain instead would let an orbit that lives entirely in [n, domain) loop forever.)
  for (let i = 0; i < n; i++) {
    let p = permute(i);
    while (p >= n) p = permute(p);
    yield p;
  }
}

/** Yield `start, start+1, ..., start+n-1` in shuffled order (or ascending if `randomize` is false). */
export function* shuffledRange(
  start: number,
  n: number,
  opts: ShuffleOptions & { randomize?: boolean } = {},
): Generator<number> {
  if (opts.randomize === false) {
    for (let i = 0; i < n; i++) yield start + i;
    return;
  }
  for (const idx of shuffledIndices(n, opts)) yield start + idx;
}
