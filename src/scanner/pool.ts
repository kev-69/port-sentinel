export interface PoolOptions {
  /** Maximum number of items in progress *or* finished but not yet consumed. */
  concurrency: number;
}

/**
 * Run `worker` over `source` with bounded concurrency, yielding results as they finish.
 *
 * Pull-based: items are taken from `source` only when a slot frees up, and a slot frees up
 * only when the consumer takes a result. A slow consumer therefore stops new work from
 * starting (backpressure), and memory stays O(concurrency) however large `source` is.
 *
 * Results arrive in completion order, not input order.
 */
export async function* pool<T, R>(
  source: Iterable<T>,
  worker: (item: T) => Promise<R>,
  opts: PoolOptions,
): AsyncGenerator<R, void, undefined> {
  if (!Number.isInteger(opts.concurrency) || opts.concurrency < 1) {
    throw new RangeError(`concurrency must be a positive integer, got ${opts.concurrency}`);
  }

  const items = source[Symbol.iterator]();
  let exhausted = false;
  let stopped = false;
  let active = 0;
  const finished: R[] = [];
  let failure: { error: unknown } | undefined;
  // Resolves the consumer's "wait for something to happen" promise. One slot is enough:
  // the consumer re-checks all state after waking, so extra wake-ups are harmless.
  let wake: (() => void) | undefined;

  const fill = (): void => {
    while (!exhausted && !stopped && !failure && active + finished.length < opts.concurrency) {
      const next = items.next();
      if (next.done) {
        exhausted = true;
        return;
      }
      active++;
      // new Promise(...) turns a worker that throws synchronously into a rejection
      // instead of an exception escaping from fill().
      new Promise<R>((resolve) => resolve(worker(next.value)))
        .then(
          (result) => {
            if (!stopped) finished.push(result);
          },
          (error: unknown) => {
            failure ??= { error };
          },
        )
        .finally(() => {
          active--;
          wake?.();
        });
    }
  };

  try {
    fill();
    for (;;) {
      if (failure) throw failure.error;
      // Check length rather than `shift() !== undefined`: a worker may legitimately return undefined.
      if (finished.length > 0) {
        // While suspended here the consumer is busy. No new work starts until it asks
        // for the next result, which is the backpressure point.
        yield finished.shift() as R;
        fill();
        continue;
      }
      if (exhausted && active === 0) return;
      // Nothing ready yet: sleep until some worker settles. Setting `wake` happens in the
      // same synchronous turn as the checks above, so no completion can slip in between.
      await new Promise<void>((resolve) => (wake = resolve));
      wake = undefined;
    }
  } finally {
    // Runs on normal completion, on a thrown error, and when the consumer `break`s out.
    stopped = true;
  }
}
