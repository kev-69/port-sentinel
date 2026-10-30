# port-sentinel spec

Write each stage's section before writing its code.

## Scope and non-goals

## Stage 1: TCP connect scan (single host)

**Goal:** determine whether each requested TCP port on one host is open, closed or filtered, using the OS's full `connect()` (Nmap `-sT`).

- **Inputs**
  - `target`: an IPv4/IPv6 literal or a hostname. Hostnames are resolved **once** before scanning (not per port).
  - `ports`: a spec string such as `22,80,8000-8100`. Each port is an integer in 1..65535. Duplicates are removed and the list is sorted.
  - `timeoutMs`: per-probe connect deadline, default 1000 ms.
- **Outputs:** one result per port, `{ host, port, state, reason, latencyMs, errorCode? }`. `reason` uses Nmap's vocabulary so results can be compared with `nmap --reason`.
- **Port state classification**

  | Observation | On the wire | state | reason |
  |---|---|---|---|
  | `connect` event | SYN → SYN/ACK → ACK | open | syn-ack |
  | `ECONNREFUSED` | SYN → RST | closed | conn-refused |
  | `ECONNRESET` | RST during setup | closed | reset |
  | our deadline fires | SYN → (nothing) | filtered | no-response |
  | `ETIMEDOUT` | OS gave up retransmitting SYN | filtered | no-response |
  | `EHOSTUNREACH` | ICMP host unreachable | filtered | host-unreach |
  | `ENETUNREACH` | no route / ICMP net unreachable | filtered | net-unreach |
  | anything else (`EMFILE`, `EADDRNOTAVAIL`, `EACCES`…) | problem is local | error | local-error |

- **Timeout semantics:** the deadline is a wall-clock timer that starts when `connect()` is called. It is *not* `socket.setTimeout()`, which is an idle timer. When the deadline fires the probe is reported as filtered and the socket is destroyed. Every probe settles exactly once and always destroys its socket.
- **Concurrency:** none in this stage. Ports are probed one after another. Stage 2 exists because this is slow.
- **Non-goals:** banners, UDP, CIDR, output formats.
- **Risks:** some Windows builds wait ~1 s before reporting `ECONNREFUSED` on loopback. On this machine it took 0–6 ms, measured 2026-10-27. If a closed port takes longer than the deadline, it will be misreported as filtered.

## Stage 2: Concurrency pool, rate limit, retries

**Goal:** scan time should be limited by how many probes are in flight, not by the sum of every timeout. Stage 1 measured 20 filtered ports × 500 ms = 10.1 s, which extrapolates to about 18 hours for 65,535 filtered ports at 1 s.

- **Pool** (`pool(source, worker, { concurrency })`): an async generator.
  - At most `concurrency` items are in progress at once. Completed results that the consumer hasn't taken yet *also* count toward that limit. That is the backpressure: a slow consumer stops new work from starting, so memory stays bounded.
  - Pulls lazily from any `Iterable`. It never turns the source into an array, so Stage 3 can feed it a CIDR × ports generator with billions of combinations.
  - Results come out in completion order, not input order.
  - If a worker rejects, the generator throws that error and starts no new work.
  - If the consumer stops early (`break`), no new work starts. Work already in progress runs to completion and its results are dropped.
- **Rate limiter** (`RateLimiter(ratePerSec, burst)`): GCRA / virtual scheduling.
  - Each `take()` reserves the next free time slot *synchronously* and then sleeps until it. Concurrent callers therefore get distinct, FIFO-ordered slots with no locks.
  - Allows `burst` back-to-back probes, then one every `1000 / rate` ms.
  - It limits *attempts* (each one sends a SYN), so retries consume tokens too.
  - The default is no limit.
- **Retries:** a probe that ends in `filtered / no-response` (our deadline fired) is retried up to `retries` times (default 1). Any other outcome is a definitive answer from the target or the path, so it is not retried: open (SYN/ACK), closed (RST), unreachable (ICMP), or a local error. The result records `attempts`.
  - Why we retry at all: with a 1 s deadline the OS never gets to retransmit the SYN itself, because Windows' first retransmission comes after about 3 s. A single lost packet would otherwise turn an open port into a filtered one.
- **CLI:** `-c, --concurrency <n>` (default 500, range 1–10,000), `-r, --rate <pps>` (optional), `--retries <n>` (default 1, range 0–10). Results are sorted by port for display.
- **Non-goals:** adaptive timing (Nmap's RTT-based timeouts and congestion control), cancellation and Ctrl-C (Stage 6).

## Stage 3: CIDR parsing and randomized order

## Stage 4: Banner grabbing and signatures

## Stage 5: UDP probes (DNS, NTP)

## Stage 6: Output formats, progress, resume, diff

## Stage 7: Study: why Nmap SYN scans need raw sockets
