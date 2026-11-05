# Decisions

One entry per trade-off: context, options considered, decision, consequences.

## 001: Separate tsconfig for build vs. type-check
- **Context:** tests live outside `src/`, but `dist/` should contain only `src/`.
- **Decision:** `tsconfig.json` type-checks `src` + `tests` with `noEmit`; `tsconfig.build.json` extends it, sets `rootDir: src`, and emits to `dist/`.
- **Consequences:** `npm run typecheck` covers tests; `npm run build` ships only CLI code. Tests run from source via vitest.

## 002: Own wall-clock deadline instead of `socket.setTimeout()`
- **Context:** a probe needs "the handshake finishes within N ms or the port is filtered".
- **Options:** `socket.setTimeout()`, which is an idle timer re-armed by activity and only emits an event without closing anything; the OS connect timeout (about 21 s on Windows, often over 2 minutes on Linux); or our own `setTimeout` started at `connect()`.
- **Decision:** our own timer. Whichever fires first among connect, error and the timer settles the probe. The socket is always destroyed.
- **Consequences:** latency is bounded by `timeoutMs`. A slow but open host can be misreported as filtered when the timeout is too low (Stage 2 adds retries).

## 003: Unknown and local errors are `error`, not `filtered`
- **Context:** it's tempting to treat every failure as "filtered".
- **Decision:** only errors that come from the target or the network path (`ECONNREFUSED`, `ECONNRESET`, `ETIMEDOUT`, `EHOSTUNREACH`, `ENETUNREACH`) say anything about the port. Everything else is `error` with the raw `errorCode` kept.
- **Evidence:** scanning 127.0.0.1 on Windows gave `EACCES` on 137/tcp (NetBIOS). That is local OS policy, not a filter on the target.
- **Consequences:** results never claim a firewall exists when the problem is our own machine (for example running out of file descriptors under load in Stage 2).

## 004: Resolve hostnames once, before scanning
- **Decision:** `resolveHost()` turns the target into one IP. Probes connect to that IP literal.
- **Why:** this avoids one DNS lookup per port, keeps DNS time out of each probe's deadline, and keeps every port on the same IP when the name has several A records.
- **Trade-off:** for now only the first address is scanned (IPv4/IPv6 dual-stack hosts are not both scanned).

## 005: TEST-NET-1 (192.0.2.1) as the "filtered" test target
- **Context:** we need a deterministic "no answer" target without a firewall lab.
- **Decision:** RFC 5737 reserves 192.0.2.0/24 for documentation and it is not routed, so SYNs to it get no reply. On an offline machine the result is `ENETUNREACH` instead, which is still `filtered`, so the test accepts either.
- **Consequences:** the test sends one SYN toward the default gateway. No real host receives it.

## 006: Pull-based pool with a completion queue (not `Promise.race`, not batches)
- **Options:**
  1. *Batches* (`Promise.all` over chunks of N): one slow probe holds up the whole batch, so concurrency drops while it waits.
  2. *`Promise.race` over the in-flight set:* simple, but every race attaches a callback to every pending promise. A probe that stays pending through K completions collects K callbacks, roughly O(concurrency²) live callbacks at 500 in flight.
  3. *Completion queue:* each worker pushes its result into an array and wakes the consumer. Each completion costs O(1).
- **Decision:** option 3, exposed as an async generator.
- **Consequences:** slots refill the moment a probe finishes, and results stream out for progress and output. Unconsumed results count toward `concurrency`, so a slow consumer applies backpressure and memory stays bounded. The source is consumed lazily, which Stage 3 needs for CIDR × ports.

## 007: GCRA for rate limiting
- **Options:** a token bucket with a refill timer; a queue with a dispatcher loop; GCRA, where one `tat` timestamp is updated synchronously.
- **Decision:** GCRA. Each `take()` reserves its slot synchronously, so concurrent workers get distinct FIFO slots without a lock, queue or timer. `reserve()` is pure given a clock, so the tests use a fake clock and check exact numbers.
- **Consequences:** a worker waiting for a token holds a pool slot. That's intended: the in-flight count includes probes waiting to be sent.

## 008: Retry only `no-response`
- **Decision:** SYN/ACK, RST and ICMP unreachable are answers, so only silence is retried (default `--retries 1`).
- **Why:** with a 1 s deadline the OS never retransmits the SYN itself (Windows' first retransmission is at about 3 s), so a single lost packet would otherwise flip open to filtered.
- **Consequences:** each retry is another SYN the target logs. Retries also hide local overload (see BENCHMARKS Stage 2), so they are no substitute for a sensible concurrency.

## 009: Default concurrency 500
- **Evidence:** docs/BENCHMARKS.md. Filtered-heavy scans benefit almost linearly. Loopback tops out at about 8,000 sockets/s whatever the concurrency, and 5,000 caused false "filtered" results.
- **Decision:** default 500, max 10,000 (the max lets you reproduce the failure on purpose).

## 010: uint32 via multiply/`>>> 0`, not left shifts
- **Context:** `ipToInt` must turn "255.255.255.255" into 4294967295, not -1.
- **Decision:** accumulate octets with `acc * 256 + n`, then `>>> 0` once at the end. `intToIp` uses `>>> 8`/`& 0xff`, which already yield unsigned results.
- **Why:** JS bitwise operators are signed-32-bit, so `a << 24` for `a >= 128` goes negative. `prefixMask` still uses `<<` but special-cases `/0` because a shift of 32 wraps to a shift of 0.

## 011: Feistel permutation for randomized order (not Fisher-Yates, not LCG)
- **Context:** need pseudo-random scan order over a space too big to store (a /8 × 1000 ports is 16.8 billion targets, confirmed in BENCHMARKS).
- **Options:** Fisher–Yates (needs the whole array); an LCG with a full-period modulus (works, but low bits have short periods and mix poorly); a Feistel network (a stateless keyed bijection).
- **Decision:** a 4-round balanced Feistel over `2^bits` (bits rounded up to even), with cycle-walking to restrict the image to `[0, n)`.
- **Why Feistel is always a permutation:** every round is invertible for any round function, so the whole network is a bijection regardless of the hash quality; the hash only affects how well-mixed it looks.
- **Consequences:** O(1) memory, O(1) per index, seedable (so Stage 6 can resume a scan in the same order). Measured: 1,000,000 targets from a /8 plan in 158 ms, heap flat at 8.3 MB.

## 012: Cycle-walk the input over [0, n), not [0, domain)  [BUG FOUND]
- **Context:** the first implementation looped the index over the full padded domain and cycle-walked each value. Tests hung.
- **Cause:** a Feistel permutation can have cycles that live entirely in `[n, domain)`. Starting a cycle-walk from such a value never re-enters `[0, n)`, so the `while (p >= n)` loop never terminated.
- **Fix:** iterate the input `i` over `[0, n)` only. Because `i` is in `[0, n)`, its permutation orbit is guaranteed to return there, so the walk always terminates. This is the standard cycle-walking construction.
- **Lesson:** cycle-walking is a property of *where you start*, not just of the test condition.

## 013: Flatten (host, port) to one index and shuffle that
- **Decision:** index `i` decodes to `host = first + ⌊i/P⌋`, `port = ports[i % P]`; the single range `[0, hosts*P)` is shuffled as a unit.
- **Why:** shuffling one combined space interleaves hosts and ports, so consecutive probes hit different hosts and different ports. Shuffling hosts and ports separately would still sweep one host's ports in a block.
- **Consequences:** a single Feistel call drives the whole scan. Verified: the first 5 targets of a /8 plan were 5 distinct hosts and 5 distinct ports.

## 014: --max-hosts blast-radius cap and a stderr authorization notice
- **Decision:** CIDR scans refuse blocks larger than `--max-hosts` (default 4096) and always print "only scan networks you own or are authorized to test" to stderr.
- **Why:** a CIDR scan touches many machines; an accidental `/8` is the kind of mistake that gets an engineer in real trouble. The cap and notice make scope and authorization explicit (THREAT_MODEL abuse case).

## 015: Fingerprinting is a separate phase with its own connection
- **Context:** we could grab a banner on the same socket that found the port open.
- **Decision:** run fingerprinting *after* the scan, opening a fresh connection per open port, mirroring Nmap's `-sV`.
- **Why:** keeps `probeTcp` a pure port-state classifier (easy to reason about and test), and version detection is opt-in via `--banner`. There are far fewer open ports than scanned ports, so the extra connection is cheap.
- **Trade-off:** a service that only shows its banner once per connection is re-greeted; acceptable.

## 016: Data-driven signatures (regexes in JSON, validated by zod)
- **Decision:** signatures live in `signature.json`: probes (NULL + send-probes) each with regex `matches` and `$1..$9` version templates. `compileSignatures` validates with zod and compiles each `RegExp` once.
- **Why:** the brief requires data-driven, not hard-coded. New services are a JSON edit, not a code change. Compiling once avoids rebuilding regexes per probe.
- **latin1 decode:** responses are matched as latin1 so binary protocols (MySQL's length-prefixed greeting) survive and `\x00` in a pattern is a literal NUL.

## 017: NULL probe first, then port-scoped send-probes; hard match wins
- **Decision:** always try the NULL probe (listen only); then send-probes whose `ports` include this port. Scan every rule and return the first *hard* match, falling back to a retained *softmatch*.
- **Why:** many services greet on connect (SSH/FTP/SMTP); HTTP and Redis only answer when prompted, and scoping send-probes by port avoids sending an HTTP GET to a mail server. Softmatch names the service while leaving room for a version match (Nmap's model).

## 018: ReDoS surface of a signature file
- **Context:** regexes are data; a catastrophic-backtracking pattern could hang the scanner (ReDoS), and a signature file could one day be third-party.
- **Mitigations:** match only against a bounded buffer (`maxBytes`, default 4096); a test asserts every bundled pattern is anchored with `^`; zod rejects unknown regex flags.
- **Known gap:** we don't yet run regexes under a timeout (Node has no built-in per-regex timeout). Noted in THREAT_MODEL; a worker-thread timeout is a future option.

## 019: Close banner connections with destroy() (RST), like the port probe
- **Context:** after reading a banner we could send FIN (`end()`) or RST (`destroy()`).
- **Decision:** `destroy()`, matching `probeTcp` and Nmap.
- **Detection note (project 7):** an abrupt RST after a bare banner read is itself a scan signal, and some servers log the reset as an error. A graceful `end()` would look more like a normal client. Left as a future stealth option.
