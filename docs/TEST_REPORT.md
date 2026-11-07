# Test report

| | |
|---|---|
| Date | 2026-11-07 |
| Commit under test | after `d138df1` (Stage 6 complete) |
| Environment | Windows 11 (build 26200), Node 22.14.0, vitest 5.0.5, @vitest/coverage-v8 5.0.5 |
| Command | `npm run test:coverage` |
| Result | **220 / 220 passed** across 15 files, 0 failed, 0 skipped (~3.9 s wall clock) |

## Summary

- Every library module has direct tests. 9 of the 19 runtime source files have 100% statement coverage.
- Overall coverage is **73% statements / 67% branches / 82% functions / 75% lines**. The total
  is pulled down by two files with no automated tests: [`cli.ts`](../src/cli.ts) (0%) and
  [`host.ts`](../src/targets/host.ts) (0%). Both are covered only by manual runs, which are
  logged in [BENCHMARKS.md](BENCHMARKS.md). See [Gaps](#gaps-and-risks).
- Network behaviour is tested against **real sockets on loopback**, not mocks. Timing logic
  (rate limiter, progress, checkpoint interval) uses **injected fake clocks**, so the assertions are exact.
- Invariants are checked with **fast-check property tests**: port-spec round-trips, uint32
  IP round-trips, the Feistel shuffle being a permutation, rate-limit bounds, and the pool's concurrency bound.

## Inventory

| Test file | Tests | Time | Subject | Technique |
|---|---:|---:|---|---|
| [tcp.test.ts](../tests/tcp.test.ts) | 18 | 1054 ms | connect probe states, error classification, retries, parallel timeouts | loopback servers; TEST-NET-1 (192.0.2.1) as a no-response target |
| [pool.test.ts](../tests/pool.test.ts) | 15 | 1786 ms | concurrency bound, backpressure, lazy/infinite sources, early break, rejection | property test (random durations × concurrency); gated deferreds |
| [rate-limiter.test.ts](../tests/rate-limiter.test.ts) | 11 | 136 ms | GCRA spacing, burst, idle-credit cap, argument validation | fake clock; property test of the rate bound; one real-clock check |
| [config.test.ts](../tests/config.test.ts) | 31 | 233 ms | port-spec parsing, zod option schema | table tests; property round-trip and range-size tests |
| [cidr.test.ts](../tests/cidr.test.ts) | 38 | 31 ms | ip↔int, prefix masks, CIDR sizes incl. /0 /31 /32 | signed-shift edge cases; property round-trip over all uint32 |
| [shuffle.test.ts](../tests/shuffle.test.ts) | 23 | 157 ms | Feistel permutation, seeding, spread | property test: output is a permutation for any n ≤ 5000 |
| [plan.test.ts](../tests/plan.test.ts) | 6 | 12 ms | hosts × ports coverage, interleaving, `--seq`, reproducibility | exhaustive coverage check on small blocks |
| [matcher.test.ts](../tests/matcher.test.ts) | 13 | 17 ms | signature validation, NULL/HTTP matches, softmatch precedence | captured banners incl. a binary MySQL greeting; anchored-pattern lint |
| [banner.test.ts](../tests/banner.test.ts) | 10 | 2219 ms | banner grab, payload send, silence, `maxBytes`, end-to-end fingerprint | fake SSH/HTTP/silent servers on loopback |
| [udp-probes.test.ts](../tests/udp-probes.test.ts) | 12 | 11 ms | DNS/NTP payload layout and reply validation | hand-built replies, incl. wrong-ID and wrong-origin rejects |
| [udp.test.ts](../tests/udp.test.ts) | 13 | 1564 ms | UDP open / open\|filtered / closed, retries, socket cleanup | loopback dgram responders |
| [output.test.ts](../tests/output.test.ts) | 9 | 21 ms | record normalization, sorting, JSON round-trip, grep rows | pure functions |
| [diff.test.ts](../tests/diff.test.ts) | 7 | 9 ms | appeared / disappeared / changed / no-change | pure functions |
| [progress.test.ts](../tests/progress.test.ts) | 7 | 9 ms | progress formatting, throttling, final draw, TTY gating | fake clock + captured writes |
| [checkpoint.test.ts](../tests/checkpoint.test.ts) | 7 | 62 ms | plan matching, save/load, atomic rename, interval flush | temp directories |

The slowest files (banner, pool, udp, tcp) are slow on purpose: they wait out real timeouts
(100–300 ms) to prove that silence is classified correctly.

## Coverage by file

| File | Stmts | Branch | Funcs | Lines |
|---|---:|---:|---:|---:|
| **All files** | **73.04** | **66.51** | **81.69** | **74.54** |
| src/cli.ts | 0 | 0 | 0 | 0 |
| src/config.ts | 100 | 100 | 100 | 100 |
| src/fingerprint/banner.ts | 94.20 | 88.46 | 83.33 | 100 |
| src/fingerprint/matcher.ts | 100 | 94.44 | 100 | 100 |
| src/output/diff.ts | 94.59 | 86.11 | 100 | 96.66 |
| src/output/grep.ts | 83.33 | 50.00 | 100 | 100 |
| src/output/json.ts | 100 | 100 | 100 | 100 |
| src/output/progress.ts | 94.11 | 85.18 | 77.77 | 100 |
| src/output/report.ts | 91.66 | 55.17 | 100 | 92.30 |
| src/persistence/checkpoint.ts | 100 | 77.77 | 100 | 100 |
| src/scanner/pool.ts | 100 | 100 | 100 | 100 |
| src/scanner/rate-limiter.ts | 100 | 100 | 100 | 100 |
| src/scanner/tcp.ts | 97.61 | 93.75 | 100 | 100 |
| src/scanner/udp-probes.ts | 97.82 | 90.00 | 100 | 100 |
| src/scanner/udp.ts | 88.46 | 61.53 | 92.85 | 95.23 |
| src/targets/cidr.ts | 100 | 100 | 100 | 100 |
| src/targets/host.ts | 0 | 0 | 0 | 0 |
| src/targets/plan.ts | 100 | 100 | 100 | 100 |
| src/targets/shuffle.ts | 100 | 100 | 100 | 100 |

(`types.ts` has no runtime code and is omitted.)

## Gaps and risks

| Gap | Impact | Mitigation today |
|---|---|---|
| `cli.ts` has no automated tests (0%) | Wiring bugs (flag → option, stdout/stderr split, SIGINT, exit codes) would only show up in manual use | Every flag was exercised by hand; runs are logged in [BENCHMARKS.md](BENCHMARKS.md) Stages 1–6 |
| `host.ts` `resolveHost` untested (0%) | A DNS-resolution regression would go unnoticed | Small function (3 lines); exercised manually with `time.cloudflare.com` |
| UDP `closed` detection only reachable on Linux | On Windows the `ECONNREFUSED` → `closed` path never runs in tests; the test accepts `closed` *or* `open\|filtered` | Classification is unit-tested via `classifyUdpError`; see DECISIONS 023 |
| Only Windows has been run | Linux-specific behaviour (fast UDP `closed`, ICMP rate limiting, different SYN retransmit timings) is unverified | Add a Linux CI job (or run in a Docker/WSL container) |
| ICMP `EHOSTUNREACH` / `ENETUNREACH` paths | Only tested through the pure classifiers, not with real ICMP | The TEST-NET-1 test accepts `net-unreach` when the machine is offline |
| Low branch coverage in `report.ts` (55%) and `grep.ts` (50%) | Mostly untested optional-field combinations (product without service, IPv6 hosts in sorting) | Low risk; candidates for a property test over record shapes |

### Flakiness notes

- The TEST-NET-1 tests send one SYN toward 192.0.2.1. On most networks it is silently dropped
  (`no-response`). An offline machine gets `ENETUNREACH` instead. Both read `filtered`, and the
  tests accept either result.
- One rate-limiter test and the timeout tests use the real clock with generous margins
  (e.g. ≥ 90 ms for a 100 ms schedule). On a heavily loaded CI runner they are the most likely to flake.

## Recommended next tests

1. **CLI integration tests:** spawn `tsx src/cli.ts` against loopback servers. Assert the
   stdout JSON parses with `parseReport`, the `diff` exit codes are 0/1/2, and SIGINT
   with `--checkpoint` leaves a checkpoint that resumes.
2. **`resolveHost`:** an IP literal is returned unchanged; `localhost` resolves to a loopback address.
3. **Linux run:** execute the suite in a `node:22` container and assert the UDP closed-port test
   gets `closed` there (tighten the assertion per platform).

## Reproduce

```sh
npm install
npm run typecheck
npm run test:coverage   # text table in the terminal; coverage/coverage-summary.json on disk
```
