import { setTimeout as sleep } from 'node:timers/promises';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { pool } from '../src/scanner/pool.js';

async function collect<R>(gen: AsyncIterable<R>): Promise<R[]> {
  const out: R[] = [];
  for await (const r of gen) out.push(r);
  return out;
}

/** A promise you can resolve from outside, used to hold workers "in flight" on purpose. */
function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => (resolve = r));
  return { promise, resolve };
}

describe('pool', () => {
  it('yields one result per item', async () => {
    const results = await collect(pool([1, 2, 3, 4, 5], async (n) => n * 10, { concurrency: 2 }));
    expect(results.sort((a, b) => a - b)).toEqual([10, 20, 30, 40, 50]);
  });

  it('yields in completion order, not input order', async () => {
    const delays = [30, 10, 20];
    const results = await collect(
      pool(delays, async (ms) => {
        await sleep(ms);
        return ms;
      }, { concurrency: 3 }),
    );
    expect(results).toEqual([10, 20, 30]);
  });

  it('actually runs `concurrency` workers at once', async () => {
    const gate = deferred();
    let started = 0;
    const gen = pool([1, 2, 3, 4, 5], async (n) => {
      started++;
      await gate.promise;
      return n;
    }, { concurrency: 5 });
    const first = gen.next(); // starts the pool
    await sleep(10);
    expect(started).toBe(5); // all five started before any could finish
    gate.resolve();
    await first;
    await collect(gen);
  });

  // Property: for any concurrency and any mix of task durations, the number of
  // simultaneously running workers never exceeds the limit, and nothing is lost.
  it('never exceeds the concurrency limit', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 8 }),
        fc.array(fc.integer({ min: 0, max: 5 }), { maxLength: 40 }),
        async (concurrency, durations) => {
          let active = 0;
          let peak = 0;
          const results = await collect(
            pool(durations.map((d, i) => ({ d, i })), async ({ d, i }) => {
              active++;
              peak = Math.max(peak, active);
              await sleep(d);
              active--;
              return i;
            }, { concurrency }),
          );
          expect(peak).toBeLessThanOrEqual(concurrency);
          expect(results.sort((a, b) => a - b)).toEqual(durations.map((_, i) => i));
        },
      ),
      { numRuns: 50 },
    );
  });

  it('applies backpressure: a consumer that stops pulling stops new work', async () => {
    let started = 0;
    const gen = pool(Array.from({ length: 100 }, (_, i) => i), async (n) => {
      started++;
      return n;
    }, { concurrency: 4 });

    await gen.next(); // take one result, then go quiet
    await sleep(20); // plenty of time for workers to run, if anything would start them
    // Finished-but-unconsumed results hold their slots, so nothing beyond the
    // initial `concurrency` items may have started.
    expect(started).toBeLessThanOrEqual(4);
    await gen.return(undefined);
  });

  it('pulls lazily, so an infinite source works', async () => {
    function* naturals(): Generator<number> {
      for (let n = 0; ; n++) yield n;
    }
    const taken: number[] = [];
    for await (const n of pool(naturals(), async (n) => n, { concurrency: 3 })) {
      taken.push(n);
      if (taken.length === 10) break;
    }
    expect(taken).toHaveLength(10);
  });

  it('starts no new work after the consumer breaks out', async () => {
    let started = 0;
    const gen = pool(Array.from({ length: 50 }, (_, i) => i), async (n) => {
      started++;
      await sleep(5);
      return n;
    }, { concurrency: 3 });
    for await (const _ of gen) break;
    const atBreak = started;
    await sleep(30);
    expect(started).toBe(atBreak);
  });

  it('propagates a worker rejection and stops starting work', async () => {
    let started = 0;
    const gen = pool([1, 2, 3, 4, 5, 6, 7, 8], async (n) => {
      started++;
      if (n === 2) throw new Error('boom');
      await sleep(5);
      return n;
    }, { concurrency: 2 });
    await expect(collect(gen)).rejects.toThrow('boom');
    expect(started).toBeLessThan(8);
  });

  it('treats a worker that throws synchronously like a rejection', async () => {
    const worker = (n: number): Promise<number> => {
      if (n === 1) throw new Error('sync boom');
      return Promise.resolve(n);
    };
    await expect(collect(pool([1], worker, { concurrency: 1 }))).rejects.toThrow('sync boom');
  });

  it('yields results that are undefined', async () => {
    const results = await collect(pool([1, 2, 3], async () => undefined, { concurrency: 2 }));
    expect(results).toEqual([undefined, undefined, undefined]);
  });

  it('handles an empty source', async () => {
    expect(await collect(pool([], async (n: number) => n, { concurrency: 5 }))).toEqual([]);
  });

  it.each([0, -1, 1.5, Number.NaN])('rejects concurrency %s', async (concurrency) => {
    await expect(collect(pool([1], async (n) => n, { concurrency }))).rejects.toThrow(RangeError);
  });
});
