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
