import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { RateLimiter } from '../src/scanner/rate-limiter.js';

/** A clock the test controls, so timing assertions are exact and instant. */
function fakeClock(start = 1000): { now: () => number; advance: (ms: number) => void } {
  let t = start;
  return { now: () => t, advance: (ms) => (t += ms) };
}

describe('RateLimiter.reserve', () => {
  it('spaces calls made at the same instant by 1/rate', () => {
    const clock = fakeClock();
    const rl = new RateLimiter({ ratePerSec: 10, now: clock.now });
    expect([rl.reserve(), rl.reserve(), rl.reserve()]).toEqual([0, 100, 200]);
  });

  it('lets `burst` calls through immediately, then applies the rate', () => {
    const clock = fakeClock();
    const rl = new RateLimiter({ ratePerSec: 10, burst: 3, now: clock.now });
    expect([rl.reserve(), rl.reserve(), rl.reserve(), rl.reserve(), rl.reserve()]).toEqual([0, 0, 0, 100, 200]);
  });

  it('does not wait when calls arrive slower than the rate', () => {
    const clock = fakeClock();
    const rl = new RateLimiter({ ratePerSec: 10, now: clock.now });
    for (let i = 0; i < 5; i++) {
      expect(rl.reserve()).toBe(0);
      clock.advance(100);
    }
  });

  it('caps saved-up credit at `burst`, however long it was idle', () => {
    const clock = fakeClock();
    const rl = new RateLimiter({ ratePerSec: 10, burst: 2, now: clock.now });
    rl.reserve();
    clock.advance(60_000); // a minute idle must not buy 600 free probes
    expect([rl.reserve(), rl.reserve(), rl.reserve()]).toEqual([0, 0, 100]);
  });

  // Property: in any window of W ms, at most burst + W * rate / 1000 probes are scheduled.
  it('never schedules more than the rate allows', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 1000 }),
        fc.integer({ min: 1, max: 10 }),
        fc.array(fc.integer({ min: 0, max: 50 }), { minLength: 1, maxLength: 200 }),
        (rate, burst, gaps) => {
          const clock = fakeClock();
          const rl = new RateLimiter({ ratePerSec: rate, burst, now: clock.now });
          const sendTimes: number[] = [];
          for (const gap of gaps) {
            clock.advance(gap);
            sendTimes.push(clock.now() + rl.reserve());
          }
          const interval = 1000 / rate;
          for (let i = 0; i < sendTimes.length; i++) {
            for (let j = i + burst; j < sendTimes.length; j++) {
              // Probe j is at least (j - i - burst + 1) intervals after probe i.
              expect(sendTimes[j]! - sendTimes[i]!).toBeGreaterThanOrEqual((j - i - burst + 1) * interval - 1e-6);
            }
          }
        },
      ),
      { numRuns: 100 },
    );
  });

  it.each([
    [{ ratePerSec: 0 }],
    [{ ratePerSec: -5 }],
    [{ ratePerSec: Number.NaN }],
    [{ ratePerSec: 10, burst: 0 }],
    [{ ratePerSec: 10, burst: 1.5 }],
  ])('rejects %j', (opts) => {
    expect(() => new RateLimiter(opts)).toThrow(RangeError);
  });
});

describe('RateLimiter.take', () => {
  it('really waits (real clock)', async () => {
    const rl = new RateLimiter({ ratePerSec: 50 }); // one per 20 ms
    const start = performance.now();
    await Promise.all(Array.from({ length: 6 }, () => rl.take()));
    // 6 probes: first immediate, last at +100 ms. Allow for timer coarseness.
    expect(performance.now() - start).toBeGreaterThanOrEqual(90);
  });
});
