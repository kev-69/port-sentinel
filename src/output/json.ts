import { z } from 'zod';
import type { ScanReport } from './report.js';

/** Serialize a report as pretty-printed JSON (the canonical, diffable artifact). */
export function toJson(report: ScanReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

const recordSchema = z.object({
  host: z.string(),
  port: z.number().int(),
  protocol: z.enum(['tcp', 'udp']),
  state: z.enum(['open', 'closed', 'filtered', 'open|filtered', 'error']),
  reason: z.string(),
  latencyMs: z.number(),
  attempts: z.number().int(),
  service: z.string().optional(),
  product: z.string().optional(),
  version: z.string().optional(),
  info: z.string().optional(),
});

const reportSchema = z.object({
  tool: z.literal('port-sentinel'),
  schema: z.number().int(),
  protocol: z.enum(['tcp', 'udp']),
  target: z.string(),
  startedAt: z.string(),
  finishedAt: z.string(),
  elapsedMs: z.number(),
  results: z.array(recordSchema),
});

/** Parse and validate a JSON report (used by `diff` and `--resume`). Throws on malformed input. */
export function parseReport(text: string): ScanReport {
  return reportSchema.parse(JSON.parse(text)) as ScanReport;
}
