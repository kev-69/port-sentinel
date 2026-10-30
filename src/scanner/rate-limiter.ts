import { setTimeout as sleep } from 'node:timers/promises';

export interface RateLimiterOptions {
  /** Sustained rate, in probes per second. */
  ratePerSec: number;
  /** How many probes may go back-to-back before the rate applies. Default 1 (no burst). */
  burst?: number;
  /** Clock in milliseconds. Injectable so tests don't need real time. */
  now?: () => number;
}

/**
 * Rate limiter using GCRA (generic cell rate algorithm), also called virtual scheduling.
 *
 * Mathematically equivalent to a token bucket, but it stores one number instead of a
 * token count plus a refill time: `tat`, the "theoretical arrival time" of the next
 * conforming probe. Each call reserves a slot synchronously, so many concurrent callers
 * each get their own slot, in call order, without a lock or a queue.
 */
export class RateLimiter {
  private readonly intervalMs: number;
  private readonly burstAllowanceMs: number;
  private readonly now: () => number;
  private tat = Number.NEGATIVE_INFINITY;

  constructor(opts: RateLimiterOptions) {
    const burst = opts.burst ?? 1;
    if (!(opts.ratePerSec > 0)) throw new RangeError(`ratePerSec must be > 0, got ${opts.ratePerSec}`);
    if (!Number.isInteger(burst) || burst < 1) throw new RangeError(`burst must be an integer >= 1, got ${burst}`);
    this.intervalMs = 1000 / opts.ratePerSec;
    // How far `tat` may lag behind now: (burst - 1) intervals of "saved up" capacity.
    this.burstAllowanceMs = (burst - 1) * this.intervalMs;
    this.now = opts.now ?? (() => performance.now());
  }

  /** Reserve the next slot and return how many ms the caller must wait for it (0 = go now). */
  reserve(): number {
    const now = this.now();
    // Idle time builds up credit, but never more than `burst` probes' worth.
    const slot = Math.max(this.tat, now - this.burstAllowanceMs);
    this.tat = slot + this.intervalMs;
    return Math.max(0, slot - now);
  }

  /** Wait until the caller is allowed to send one probe. */
  async take(): Promise<void> {
    const waitMs = this.reserve();
    if (waitMs > 0) await sleep(waitMs);
  }
}
