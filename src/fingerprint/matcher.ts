import { readFileSync } from 'node:fs';
import { z } from 'zod';

/** One regex rule: if `pattern` matches a response, we've identified `service`. */
const matchSchema = z.object({
  service: z.string().min(1),
  /** JS regex source, matched against the response decoded as latin1. */
  pattern: z.string().min(1),
  /** Regex flags (e.g. "s" for dotall, "i" for case-insensitive). No "g": we want one match. */
  flags: z
    .string()
    .regex(/^[simu]*$/, 'only s/i/m/u flags allowed')
    .optional(),
  /** Softmatch: name the service but keep probing for a better (version) match. */
  soft: z.boolean().default(false),
  /** Templates with $1..$9 capture references (Nmap's p// v// i//). */
  product: z.string().optional(),
  version: z.string().optional(),
  info: z.string().optional(),
});

const probeSchema = z.object({
  name: z.string().min(1),
  /** Bytes to send on connect; "" means the NULL probe (listen only). */
  payload: z.string(),
  /** Restrict a send-probe to these ports; omitted means "any port". */
  ports: z.array(z.number().int()).optional(),
  rarity: z.number().int().min(1).max(10).default(1),
  matches: z.array(matchSchema).min(1),
});

const signatureFileSchema = z.object({ probes: z.array(probeSchema).min(1) });

export type SignatureMatch = z.infer<typeof matchSchema>;
export type Probe = z.infer<typeof probeSchema>;

interface CompiledMatch extends SignatureMatch {
  regex: RegExp;
}
interface CompiledProbe extends Probe {
  matches: CompiledMatch[];
  /** payload as bytes, ready to write to a socket. */
  payloadBytes: Buffer;
}

export interface CompiledSignatures {
  probes: CompiledProbe[];
  byName: Map<string, CompiledProbe>;
}

export interface ServiceMatch {
  service: string;
  soft: boolean;
  probe: string;
  product?: string;
  version?: string;
  info?: string;
}

/** Validate and compile a raw signature object (regexes compiled once, up front). */
export function compileSignatures(raw: unknown): CompiledSignatures {
  const parsed = signatureFileSchema.parse(raw);
  const probes: CompiledProbe[] = parsed.probes.map((p) => ({
    ...p,
    payloadBytes: Buffer.from(p.payload, 'latin1'),
    matches: p.matches.map((m) => ({ ...m, regex: new RegExp(m.pattern, m.flags ?? '') })),
  }));
  return { probes, byName: new Map(probes.map((p) => [p.name, p])) };
}

/** Fill $1..$9 in a template from a regex match. Missing groups become "". */
function applyTemplate(template: string, m: RegExpExecArray): string {
  return template.replace(/\$(\d)/g, (_, d: string) => m[Number(d)] ?? '');
}

function buildMatch(m: CompiledMatch, probe: string, mm: RegExpExecArray): ServiceMatch {
  const result: ServiceMatch = { service: m.service, soft: m.soft, probe };
  if (m.product !== undefined) result.product = applyTemplate(m.product, mm);
  if (m.version !== undefined) result.version = applyTemplate(m.version, mm);
  if (m.info !== undefined) result.info = applyTemplate(m.info, mm);
  return result;
}

/**
 * Try every rule for `probeName` against `data`.
 * Returns the first *hard* match; otherwise the first softmatch; otherwise null.
 */
export function matchResponse(sig: CompiledSignatures, probeName: string, data: Buffer): ServiceMatch | null {
  const probe = sig.byName.get(probeName);
  if (!probe) return null;
  // latin1: each byte maps to exactly one char, so binary protocols (e.g. MySQL's
  // length-prefixed greeting) survive and \x00 in a pattern means a literal NUL byte.
  const text = data.toString('latin1');
  let soft: ServiceMatch | null = null;
  for (const m of probe.matches) {
    const mm = m.regex.exec(text);
    if (!mm) continue;
    const hit = buildMatch(m, probeName, mm);
    if (!hit.soft) return hit;
    soft ??= hit;
  }
  return soft;
}

let cached: CompiledSignatures | undefined;

/** Load and compile the bundled signature.json (cached after first call). */
export function loadDefaultSignatures(): CompiledSignatures {
  if (!cached) {
    const path = new URL('./signature.json', import.meta.url);
    cached = compileSignatures(JSON.parse(readFileSync(path, 'utf8')));
  }
  return cached;
}
