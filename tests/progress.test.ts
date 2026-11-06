import { describe, expect, it } from 'vitest';
import { formatProgress, Progress } from '../src/output/progress.js';

describe('formatProgress', () => {
  it('shows count, percent, open, rate and ETA', () => {
    const s = formatProgress({ done: 250, total: 1000, open: 3, elapsedMs: 1000 });
    expect(s).toBe('250/1000 (25%) · 3 open · 250/s · ETA 00:03');
  });

  it('shows ETA 00:00 when complete', () => {
    expect(formatProgress({ done: 10, total: 10, open: 1, elapsedMs: 1000 })).toContain('ETA 00:00');
  });

  it('handles the zero-elapsed start without dividing by zero', () => {
    expect(formatProgress({ done: 0, total: 100, open: 0, elapsedMs: 0 })).toContain('0/100 (0%)');
  });
});

describe('Progress (throttled, injected I/O)', () => {
  function harness() {
    const out: string[] = [];
    let t = 0;
    const p = new Progress({
      total: 4,
      write: (s) => out.push(s),
      now: () => t,
      intervalMs: 100,
      force: true,
    });
    return { out, p, advance: (ms: number) => (t += ms) };
  }

  it('throttles redraws to the interval', () => {
    const { out, p, advance } = harness();
    p.tick(false); // t=0, draws (first tick, lastDraw=-Infinity)
    p.tick(false); // t=0, within interval -> no draw
    advance(150);
    p.tick(true); // past interval -> draws
    expect(out.length).toBe(2);
  });

  it('always draws the final tick even within the interval', () => {
    const { out, p } = harness();
    p.tick(false);
    p.tick(false);
    p.tick(false);
    p.tick(true); // done === total -> forced draw regardless of throttle
    expect(out.length).toBe(2); // first + final
    expect(out.at(-1)).toContain('4/4 (100%)');
    expect(out.at(-1)).toContain('1 open');
  });

  it('finish() writes a trailing newline', () => {
    const { out, p } = harness();
    p.tick(false);
    p.finish();
    expect(out.at(-1)).toBe('\n');
  });

  it('is silent when disabled (not a TTY, not forced)', () => {
    const out: string[] = [];
    const p = new Progress({ total: 2, write: (s) => out.push(s), now: () => 0, isTty: false });
    p.tick(true);
    p.finish();
    expect(out).toHaveLength(0);
  });
});
