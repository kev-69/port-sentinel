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

## Stage 3: CIDR parsing and randomized order

## Stage 4: Banner grabbing and signatures

## Stage 5: UDP probes (DNS, NTP)

## Stage 6: Output formats, progress, resume, diff

## Stage 7: Study: why Nmap SYN scans need raw sockets
