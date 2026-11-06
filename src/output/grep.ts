import type { ScanReport, ScanResultRecord } from './report.js';

const HEADER = '# host\tport\tproto\tstate\tservice\tversion\treason';

/** Escape tabs/newlines so each record stays on exactly one tab-delimited line. */
function cell(value: string | undefined): string {
  if (!value) return '';
  return value.replace(/[\t\r\n]+/g, ' ');
}

function row(r: ScanResultRecord): string {
  return [
    r.host,
    r.port,
    r.protocol,
    r.state,
    cell(r.service ?? r.product),
    cell(r.version),
    r.reason,
  ].join('\t');
}

/**
 * Greppable output: one tab-separated row per result, with a comment header.
 * Designed for `grep open`, `awk -F'\t'`, `cut -f`.
 */
export function toGrep(report: ScanReport): string {
  return `${[HEADER, ...report.results.map(row)].join('\n')}\n`;
}
