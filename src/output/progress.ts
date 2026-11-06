export interface ProgressState {
  done: number;
  total: number;
  open: number;
  elapsedMs: number;
}

function pad(n: number): string {
  return String(n).padStart(2, '0');
}

function clock(ms: number): string {
  const s = Math.floor(ms / 1000);
  return `${pad(Math.floor(s / 60))}:${pad(s % 60)}`;
}

/**
 * Render a one-line progress string. Pure: no I/O, no clock of its own, so it's unit-tested
 * by passing a state in and asserting the string out.
 */
export function formatProgress(s: ProgressState): string {
  const pct = s.total > 0 ? Math.floor((s.done / s.total) * 100) : 0;
  const rate = s.elapsedMs > 0 ? s.done / (s.elapsedMs / 1000) : 0;
  const remaining = rate > 0 ? ((s.total - s.done) / rate) * 1000 : 0;
  const eta = s.done >= s.total ? '00:00' : clock(remaining);
  return `${s.done}/${s.total} (${pct}%) · ${s.open} open · ${Math.round(rate)}/s · ETA ${eta}`;
}

export interface ProgressOptions {
  total: number;
  /** Where to draw (default process.stderr). */
  write?: (s: string) => void;
  /** Clock in ms (default performance.now). */
  now?: () => number;
  /** Minimum ms between redraws. */
  intervalMs?: number;
  /** Force drawing even when not a TTY. */
  force?: boolean;
  isTty?: boolean;
}

/**
 * Throttled stderr progress meter. Call `tick(isOpen)` per completed probe and `finish()`
 * at the end. Silent unless stderr is a TTY or `force` is set, so it never corrupts a
 * redirected report on stdout.
 */
export class Progress {
  private done = 0;
  private open = 0;
  private lastDraw = -Infinity;
  private readonly start: number;
  private readonly write: (s: string) => void;
  private readonly now: () => number;
  private readonly intervalMs: number;
  private readonly enabled: boolean;

  constructor(private readonly opts: ProgressOptions) {
    this.write = opts.write ?? ((s) => process.stderr.write(s));
    this.now = opts.now ?? (() => performance.now());
    this.intervalMs = opts.intervalMs ?? 100;
    // Explicit isTty (true OR false) overrides real detection, so tests can simulate either.
    this.enabled = Boolean(opts.force) || (opts.isTty ?? Boolean(process.stderr.isTTY));
    this.start = this.now();
  }

  tick(isOpen: boolean): void {
    this.done++;
    if (isOpen) this.open++;
    if (!this.enabled) return;
    const t = this.now();
    if (t - this.lastDraw < this.intervalMs && this.done < this.opts.total) return;
    this.lastDraw = t;
    this.draw();
  }

  private draw(): void {
    this.write(
      `\r${formatProgress({ done: this.done, total: this.opts.total, open: this.open, elapsedMs: this.now() - this.start })}`,
    );
  }

  finish(): void {
    if (!this.enabled) return;
    this.draw();
    this.write('\n');
  }
}
