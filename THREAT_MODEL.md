# Threat model

Scope: `port-sentinel`, a CLI TCP/UDP scanner and service fingerprinter run by an operator
against hosts they own or are authorized to test. This models risks of *operating and running
the tool*, not of the networks being scanned.

## Assets
- **The operator's standing / legal position.** Scanning the wrong host can breach computer-misuse
  law or an acceptable-use policy. This is the highest-value asset.
- **The machine running the scanner** (file descriptors, ephemeral ports, CPU) — exhaustible local resources.
- **Scan results** — reveal which hosts and services exist; sensitive if leaked.
- **Integrity of the tool itself** — the signature file and dependencies.

## Attackers
- **The operator, by mistake** — fat-fingers a CIDR (`/8` instead of `/28`), scans the wrong range,
  or runs against production without approval. The most likely "attacker".
- **A hostile scan target** — a host that answers probes with crafted, oversized, or slow responses
  designed to exhaust or hang the scanner (a honeypot or tarpit).
- **A malicious signature file** — a third-party or tampered `signature.json` with a
  catastrophic-backtracking regex (ReDoS) or a resource-heavy probe.
- **A local snoop** — another user on the machine reading scan output or argv.

## Abuse cases
1. Accidentally scanning an unauthorized or production network (wrong target / range).
2. A tarpit feeds an endless or very slow banner, hanging a worker or filling memory.
3. A target returns gigabytes to a NULL probe to exhaust scanner memory.
4. A ReDoS pattern in the signature file makes one banner hang the whole process.
5. Running too wide a scan exhausts local file descriptors / ephemeral ports (self-DoS).
6. The scan is itself detected and attributed (the operator wanted to stay within authorized bounds).

## Mitigations
| Risk | Mitigation | Where |
|---|---|---|
| Wrong / oversized range | `--max-hosts` cap (default 4096); refuse larger blocks | `cli.ts` → runCidrScan |
| Unauthorized scanning | Authorization notice printed to stderr for every CIDR scan; README legal section | `cli.ts`, README |
| Tarpit slow banner | Idle read timer (`bannerTimeoutMs`); connect deadline | `banner.ts` grabRaw |
| Oversized banner | `maxBytes` cap (default 4096), stop reading past it | `banner.ts` grabRaw |
| ReDoS in signatures | Bounded match input; anchored-pattern test; zod flag allow-list | `matcher.ts`, tests |
| FD / port exhaustion | Bounded concurrency pool; results classified as `error` (not `filtered`) so overload is visible | `pool.ts`, `tcp.ts` |
| Detection / attribution | Rate limiter and randomized order reduce scan footprint (do not eliminate it) | `rate-limiter.ts`, `shuffle.ts` |

## Known gaps (not yet mitigated)
- No per-regex execution timeout (Node lacks one); a truly adversarial signature file could still hang. Candidate: run matching in a worker thread with a timeout.
- Banner connections close with RST, which is itself detectable and can log errors on the target (DECISIONS 019).
- Scan output is written in the clear to stdout/files; no encryption or redaction.
- Only IPv4 CIDR is bounded by `--max-hosts`; IPv6 expansion is out of scope.
