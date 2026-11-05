import net from 'node:net';
import { loadDefaultSignatures, matchResponse, type CompiledSignatures, type ServiceMatch } from './matcher.js';

export interface GrabOptions {
  /** Deadline for the TCP handshake, in ms. */
  connectTimeoutMs: number;
  /** How long to keep reading after connect (resets on each chunk), in ms. */
  bannerTimeoutMs: number;
  /** Stop reading after this many bytes. */
  maxBytes: number;
  /** Bytes to send once connected. Omit/empty for a listen-only (NULL) grab. */
  payload?: Buffer;
}

export interface GrabResult {
  data: Buffer;
  /** Set when the connection failed outright (not merely "no banner"). */
  error?: string;
}

/**
 * Connect, optionally send a payload, and collect the response.
 *
 * Settle-once / always-destroy, same discipline as probeTcp. "No banner" is a normal,
 * empty result, not an error: many open ports simply stay silent to a NULL probe.
 */
export function grabRaw(host: string, port: number, opts: GrabOptions): Promise<GrabResult> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const chunks: Buffer[] = [];
    let received = 0;
    let settled = false;
    let bannerTimer: NodeJS.Timeout | undefined;

    const finish = (error?: string): void => {
      if (settled) return;
      settled = true;
      clearTimeout(connectTimer);
      clearTimeout(bannerTimer);
      socket.destroy();
      const data = Buffer.concat(chunks, Math.min(received, opts.maxBytes));
      resolve(error !== undefined ? { data, error } : { data });
    };

    // The read window is an *idle* timer: it restarts on each chunk, so a service that
    // dribbles a banner slowly still gets read, but a connection that goes quiet ends.
    const armBannerTimer = (): void => {
      clearTimeout(bannerTimer);
      bannerTimer = setTimeout(() => finish(), opts.bannerTimeoutMs);
    };

    const connectTimer = setTimeout(() => finish('connect-timeout'), opts.connectTimeoutMs);

    socket.once('connect', () => {
      clearTimeout(connectTimer);
      if (opts.payload && opts.payload.length > 0) socket.write(opts.payload);
      armBannerTimer();
    });

    socket.on('data', (chunk: Buffer) => {
      received += chunk.length;
      chunks.push(chunk);
      if (received >= opts.maxBytes) return finish();
      armBannerTimer();
    });

    // Server hung up: whatever we have is the complete banner.
    socket.once('end', () => finish());
    socket.on('error', (err: NodeJS.ErrnoException) => finish(err.code ?? 'error'));

    socket.connect({ host, port });
  });
}

export interface FingerprintResult {
  host: string;
  port: number;
  match?: ServiceMatch;
  /** Raw bytes of the banner we matched on (or the first non-empty response seen). */
  banner: Buffer;
  /** Name of the probe that produced `banner`. */
  probe?: string;
}

export interface FingerprintOptions {
  connectTimeoutMs?: number;
  bannerTimeoutMs?: number;
  maxBytes?: number;
}

/**
 * Identify the service on one open port.
 *
 * Order mirrors Nmap: the NULL probe first (most services greet on connect), then any
 * send-probe whose `ports` list includes this port. Each probe uses a fresh connection.
 * Stops at the first hard match; keeps a softmatch as a fallback.
 */
export async function fingerprint(
  host: string,
  port: number,
  sig: CompiledSignatures = loadDefaultSignatures(),
  opts: FingerprintOptions = {},
): Promise<FingerprintResult> {
  const grab: GrabOptions = {
    connectTimeoutMs: opts.connectTimeoutMs ?? 1000,
    bannerTimeoutMs: opts.bannerTimeoutMs ?? 2000,
    maxBytes: opts.maxBytes ?? 4096,
  };

  let banner: Buffer = Buffer.alloc(0);
  let bannerProbe: string | undefined;
  let soft: ServiceMatch | null = null;

  for (const probe of sig.probes) {
    // Skip send-probes that don't apply to this port (but NULL always runs).
    if (probe.payloadBytes.length > 0 && probe.ports && !probe.ports.includes(port)) continue;

    const grabOpts: GrabOptions = { ...grab };
    if (probe.payloadBytes.length > 0) grabOpts.payload = probe.payloadBytes;
    const res = await grabRaw(host, port, grabOpts);
    if (res.data.length === 0) continue;

    // Keep the first response we saw as the banner to show, even if nothing matches it.
    if (banner.length === 0) {
      banner = res.data;
      bannerProbe = probe.name;
    }

    const m = matchResponse(sig, probe.name, res.data);
    if (m && !m.soft) {
      return { host, port, match: m, banner: res.data, probe: probe.name };
    }
    soft ??= m;
  }

  const result: FingerprintResult = { host, port, banner };
  if (soft) result.match = soft;
  if (bannerProbe !== undefined) result.probe = bannerProbe;
  return result;
}

/** Render a banner for terminal display: escape non-printables, collapse, truncate. */
export function printableBanner(data: Buffer, limit = 160): string {
  let out = '';
  for (const byte of data.subarray(0, limit)) {
    if (byte === 0x0d || byte === 0x0a) out += byte === 0x0a ? '\\n' : '\\r';
    else if (byte >= 0x20 && byte < 0x7f) out += String.fromCharCode(byte);
    else out += `\\x${byte.toString(16).padStart(2, '0')}`;
  }
  return data.length > limit ? `${out}...` : out;
}
