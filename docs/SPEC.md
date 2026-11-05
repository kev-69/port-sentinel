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

**Goal:** expand an IPv4 CIDR block into addresses with bit math, combine them with the port list, and scan the whole space in a pseudo-random order using O(1) memory.

- **IPv4 integer math** (`cidr.ts`)
  - `ipToInt("a.b.c.d")`: validate 4 octets in 0..255, then `((a<<24)|(b<<16)|(c<<8)|d) >>> 0`. The `>>> 0` is the whole point: `a<<24` for `a>=128` is a *negative* signed-32-bit number in JS, and `>>> 0` reinterprets the bits as unsigned.
  - `intToIp(n)`: the inverse, using `>>> 8` / `& 0xff`.
  - `parseCidr("192.168.1.0/24")` → `{ network, prefix, size, first, last }`.
    - mask for prefix `p`: `p===0 ? 0 : (0xFFFFFFFF << (32-p)) >>> 0`. Special-cased because JS shifts count mod 32, so `<<32` would be `<<0` (a classic trap).
    - `network = ip & mask` (host bits dropped, so `192.168.1.5/24` normalises to `192.168.1.0`).
    - `size = 2**(32-p)`, `first = network`, `last = network + size - 1`. Sizes and `last` are kept as plain doubles, not uint32, so `/0` (2^32) stays exact.
  - Range `[first, last]` is scanned **in full**, including the network and broadcast addresses, matching Nmap's default. A live host can answer on either.
- **Randomized order** (`shuffle.ts`): a Feistel permutation.
  - We need a bijection on `[0, n)` that we can walk lazily, because `/8 × 1000 ports` is 16 billion targets — generable, never storable. Fisher–Yates is out (needs the array).
  - Round the domain up to `2^bits` with even `bits`, split each index into equal halves, run 4 Feistel rounds with a seeded round function. A balanced Feistel is a bijection for *any* round function, so the output is always a permutation.
  - **Cycle-walking:** when a permuted value is `>= n` (the domain is bigger than `n`), feed it back through until it lands in range. Since the domain is `< 2n`, the expected number of walks is `< 2`.
  - Seeded, so a scan's order is reproducible (needed for resume in Stage 6).
- **Scan plan** (`plan.ts`): one linear index `i in [0, hosts*ports)` decodes to `(host = first + ⌊i/P⌋, port = ports[i % P])`. Shuffling that single space interleaves hosts *and* ports, so consecutive probes jump across the block instead of walking one host's ports in order.
- **CLI:** a `<target>` containing `/` is an IPv4 CIDR. `--seq` disables randomization; `--seed <n>` sets the permutation seed. `--max-hosts <n>` (default 4096) caps blast radius; a larger block is refused unless the cap is raised. The authorization reminder prints to stderr for every CIDR scan.
- **Non-goals:** IPv6 CIDR (would need BigInt), hostname lists, excluding network/broadcast.

## Stage 4: Banner grabbing and signatures

**Goal:** for an open TCP port, read what the service says and identify it with a *data-driven* signature file (regexes live in JSON, never in code), mirroring a small slice of Nmap's `nmap-service-probes`.

- **Why a separate phase.** Fingerprinting runs *after* the port scan, opening a fresh connection to each open port. This matches Nmap's `-sV` architecture and keeps `probeTcp` a pure port-state classifier. Trade-off: one extra connection per open port (acceptable — there are far fewer open ports than scanned ports).
- **Two kinds of probe** (the key idea from Nmap Chapter 7):
  - **NULL probe:** connect and *just listen*. Many services greet first — SSH, FTP, SMTP, POP3. Send nothing, read the banner.
  - **Send probes:** connect and send a payload, then read. HTTP says nothing until you send a request; Redis answers `PING` with `+PONG`. Each send-probe may list `ports` it applies to, so we don't send an HTTP GET to a mail server.
- **Signature file** ([signature.json](../src/fingerprint/signature.json)): `{ probes: [{ name, payload, ports?, rarity?, matches: [{ service, pattern, flags?, soft?, product?, version?, info? }] }] }`.
  - `payload` is a literal string (JSON escapes `\r\n`); empty means the NULL probe.
  - `pattern` is a JS regex *source* string, matched against the response decoded as latin1 (one byte ↔ one char, lossless for binary).
  - `product`/`version`/`info` are templates with `$1`..`$9` capture-group references, the equivalent of Nmap's `p/ v/ i/` fields.
  - `soft: true` is a *softmatch*: it names the service but lets later probes refine the version. A hard match stops probing.
- **Matching** (`matcher.ts`): pure and socket-free, so it unit-tests against captured banners. `compileSignatures` validates the file with zod and compiles each regex once; `matchResponse(sig, probeName, bytes)` returns the first hard match, else a retained softmatch, else null.
- **Grabbing** (`banner.ts`): `grabRaw` connects, optionally writes a payload, reads up to `maxBytes` (default 4096) until `bannerTimeoutMs` of quiet or FIN. Same settle-once / always-destroy discipline as `probeTcp`.
- **CLI:** `--banner` runs the fingerprint phase on open ports and prints `service`, `product/version`, and a printable, truncated banner.
- **Safety:** regexes come from a bundled file we control, but a bad pattern can catastrophically backtrack (ReDoS). Mitigations: match against a bounded buffer (≤ maxBytes), keep patterns anchored, and a test asserts every default pattern is anchored. (THREAT_MODEL: untrusted-signature risk.)
- **Non-goals:** TLS/HTTPS (would need a TLS handshake), Nmap's full match-intensity/rarity engine, SSL probe fallback.

## Stage 5: UDP probes (DNS, NTP)

**Goal:** probe UDP ports with protocol-correct payloads, because UDP has no handshake. A service answers only if the datagram is something it understands.

- **Why payloads matter.** TCP tells you a port is open at the transport layer (SYN/ACK). UDP has nothing like that: an empty or wrong datagram is usually dropped in silence by an *open* service. So the probe has to be a real request for that protocol.
- **Port states** (Nmap's UDP model):

  | Observation | state | reason |
  |---|---|---|
  | a reply that our parser validates | open | udp-response |
  | a reply that does not validate | open | udp-response (service unknown) |
  | `ECONNREFUSED` (ICMP port unreachable) | closed | port-unreach |
  | `EHOSTUNREACH` / `ENETUNREACH` | filtered | host-unreach / net-unreach |
  | silence until the deadline | **open\|filtered** | no-response |

  Silence is the inverse of TCP. In TCP it means *filtered*. In UDP it can equally mean "open but ignored our datagram" or "firewall dropped it", so we report both.
- **Connected sockets.** We call `socket.connect(port, host)` before sending. On Linux, ICMP errors are only delivered to a *connected* UDP socket. Connecting also makes the kernel drop datagrams from any other source.
- **Platform limit (measured 2026-11-05):** on Windows, a datagram to a closed loopback port produced silence, connected or not. libuv's `src/win/udp.c` ignores `WSAECONNRESET`/`WSAENETRESET` on receive ("a previous sendto operation failed; ignore this error"), so the ICMP port-unreachable never reaches JavaScript. **On Windows every closed UDP port reports `open|filtered`.** Linux reports `closed`.
- **DNS probe** (RFC 1035 §4.1): a 12-byte header (random 16-bit ID, flags `0x0100` = RD, QDCOUNT=1) plus one question: root name `.`, QTYPE=NS(2), QCLASS=IN(1). Asking for the root's name servers is a valid query every resolver and authoritative server can answer (or refuse) without us looking up a real name. A reply is accepted only if it is ≥12 bytes, the ID matches, and QR=1. We report RCODE and the answer count.
- **NTP probe** (RFC 5905 §7.3): 48 bytes. First byte `0x23` = LI 0, VN 4, Mode 3 (client). A random transmit timestamp goes in bytes 40–47. A reply is accepted only if it is ≥48 bytes, Mode=4 (server), and its *origin* timestamp (bytes 24–31) equals our transmit timestamp. The server echoes it back, which proves the reply answers *our* request. We report stratum and version.
- **Other ports:** an empty datagram. Most services ignore it, so expect `open|filtered`. That is honest, not a bug.
- **Retries:** silence is retried (default 1). Losing a datagram is normal for UDP, and Linux rate-limits ICMP port-unreachable to about 1/s by default (`net.ipv4.icmp_ratelimit`). That limit is why Nmap UDP scans are slow.
- **CLI:** `scan --udp` switches the transport for host and CIDR targets. Port 53 gets the DNS probe, 123 the NTP probe, the rest an empty datagram.
- **Non-goals:** SNMP/other probes, IPv6 DNS servers' `udp6` edge cases beyond choosing the socket family, raw ICMP reading (needs raw sockets, see Stage 7).

## Stage 6: Output formats, progress, resume, diff

## Stage 7: Study: why Nmap SYN scans need raw sockets
