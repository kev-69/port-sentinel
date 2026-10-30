import { z } from 'zod';

export const MIN_PORT = 1;
export const MAX_PORT = 65535;

/**
 * Parse a port spec like "22,80,8000-8100" into a sorted, de-duplicated list.
 * Port 0 is excluded: it is reserved and you cannot connect() to it.
 */
export function parsePorts(spec: string): number[] {
  const ports = new Set<number>();
  for (const raw of spec.split(',')) {
    const part = raw.trim();
    if (part === '') throw new Error(`empty entry in port spec "${spec}"`);

    const range = /^(\d+)-(\d+)$/.exec(part);
    if (range) {
      const lo = toPort(range[1]!, spec);
      const hi = toPort(range[2]!, spec);
      if (lo > hi) throw new Error(`descending range "${part}"`);
      for (let p = lo; p <= hi; p++) ports.add(p);
    } else {
      ports.add(toPort(part, spec));
    }
  }
  return [...ports].sort((a, b) => a - b);
}

function toPort(text: string, spec: string): number {
  if (!/^\d+$/.test(text)) throw new Error(`"${text}" is not a port number (in "${spec}")`);
  const n = Number(text);
  if (n < MIN_PORT || n > MAX_PORT) throw new Error(`port ${n} out of range ${MIN_PORT}-${MAX_PORT}`);
  return n;
}

/** CLI options for `scan`, validated at the boundary so the scanner can trust its inputs. */
export const scanOptionsSchema = z.object({
  ports: z.string().transform((spec, ctx) => {
    try {
      return parsePorts(spec);
    } catch (e) {
      ctx.addIssue({ code: 'custom', message: (e as Error).message });
      return z.NEVER;
    }
  }),
  timeout: z.coerce.number().int().min(1).max(60_000),
  concurrency: z.coerce.number().int().min(1).max(10_000),
  // Probes per second; omitted means unlimited (bounded only by concurrency).
  rate: z.coerce.number().positive().max(1_000_000).optional(),
  retries: z.coerce.number().int().min(0).max(10),
  all: z.boolean().default(false),
});

export type ScanOptions = z.infer<typeof scanOptionsSchema>;
