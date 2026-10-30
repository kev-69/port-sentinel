# Benchmarks

Machine: Windows 11 (build 26200), Node 22.14.0. Reproduce with `npx tsx bench/concurrency.ts`.
Targets are loopback and RFC 5737 TEST-NET-1 only.

## Stage 2: concurrency (2026-10-28)

### Filtered ports: time is set by the number of timeout "waves"

192.0.2.1, ports 1–1000, 500 ms timeout, no retries.

| concurrency | time (s) | ports/s |
|---:|---:|---:|
| 1 (Stage 1, extrapolated) | ~500 | 2 |
| 50 | 10.22 | 98 |
| 200 | 2.59 | 386 |
| 500 | 1.08 | 926 |
| 1000 | 0.53 | 1893 |

Time ≈ ⌈ports / concurrency⌉ × timeout. Every probe spends almost all of its life waiting, so
running probes in parallel makes the scan faster in direct proportion. Here concurrency is the only thing that matters.

### Closed ports on loopback: concurrency barely matters, and too much breaks results

127.0.0.1, ports 1–65535, 1000 ms timeout, no retries.

| concurrency | time (s) | ports/s | open | closed | filtered | error |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 8.53 | 7686 | 27 | 65507 | 0 | 1 (EACCES) |
| 10 | 7.92 | 8273 | 27 | 65507 | 0 | 1 |
| 100 | 8.94 | 7332 | 27 | 65507 | 0 | 1 |
| 500 | 8.85 | 7403 | 27 | 65507 | 0 | 1 |
| 2000 | 10.00 | 6554 | 27 | 65507 | 0 | 1 |
| **5000** | 11.63 | 5636 | 27 | **62949** | **2558** | 1 |

An RST from loopback arrives in microseconds, so the bottleneck is the cost of creating and tearing down a socket in Node and in the
Windows TCP stack: about 8,000 sockets/s. Past that ceiling, extra concurrency only adds overhead.

**What broke at 5000:** about 2,500 closed ports were reported as *filtered*. Follow-up run at concurrency 5000:

| timeout | retries | time (s) | false filtered | attempts | latency p50 / p90 / p99 |
|---:|---:|---:|---:|---:|---|
| 1000 | 0 | 11.79 | 4324 | 65535 | 910 / 976 / 1011 ms |
| 3000 | 0 | 11.59 | 0 | 65535 | 908 / 971 / 1239 ms |
| 1000 | 1 | 11.92 | 0 | 67820 | 882 / 961 / 1006 ms |

By Little's law (L = λW): with L = 5000 probes in flight and λ ≈ 5,600 completions/s, each probe
spends W ≈ 0.9 s in the system. The network round trip is ~0.1 ms. The rest is **queueing inside our
own machine**. The deadline can't tell "the target was silent" apart from "we were too busy to notice the answer",
so the slowest ~7% of probes cross 1000 ms and get misclassified.

**Takeaways**
- Useful concurrency ≈ throughput ceiling × the real per-probe time. Beyond that, extra concurrency only lengthens queues.
- A raised timeout or a retry hides the problem but doesn't fix it: retries cost 2,285 extra connection attempts, which a
  defender also sees.
- Nmap avoids this with adaptive timing: it measures RTT and shrinks its in-flight window when responses go missing.
  This is a non-goal for now (see SPEC Stage 2).
