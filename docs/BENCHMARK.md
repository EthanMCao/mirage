# Mirage benchmark

Single-machine throughput numbers for the full Postgres v3 wire-protocol
session: `Startup -> AuthenticationCleartextPassword -> Password -> ErrorResponse -> close`.
Each session is the work an attacker actually triggers; the rate limiter is
disabled so we can measure raw server capacity.

## Setup

- **Hardware**: Apple M3 Pro (Mac15,6), 11 logical cores.
- **OS**: macOS 15.x, Apple clang 17.0.0.
- **Build**: `cmake -DCMAKE_BUILD_TYPE=Release -S . -B build && cmake --build build -j`.
- **Server**: `./build/mirage --no-ratelimit --workers <W> --audit-log /tmp/bench.jsonl`.
- **Driver**: `./build/connection_storm --threads <C> --per-thread <N>` from
  the same machine over loopback (so the network is out of scope; we are
  measuring CPU + kernel socket overhead only).

## Methodology

Each row below is a fresh `mirage` process; we wait 400 ms after `mirage`
prints its listen line, then run `connection_storm` once. `connection_storm`
fans out `C` client threads, each opening `N` sessions in a tight loop and
counting successes vs failures. Throughput is total successful sessions
divided by wall-clock elapsed.

Numbers reported are from this machine's actual runs and are reproducible
to within ~10% on the same hardware (kernel TCP TIME_WAIT recycling
introduces some run-to-run noise above ~30k sessions/sec).

## Server-worker scaling at fixed 4-client-thread load

`connection_storm --threads 4 --per-thread 4000` (16,000 sessions per run).

| server workers | elapsed (s) | failed | sessions / s |
|---:|---:|---:|---:|
| 1  | 0.645 | 0    | 24,820 |
| 2  | 0.587 | 0    | 27,274 |
| 4  | 0.616 | 0    | 25,959 |
| 8  | 0.552 | 0    | 28,981 |

Sub-linear scaling past 2 workers is expected: the per-session work in
Mirage is ~5 syscalls (accept, recv startup, send auth challenge, recv
password, send error, close). At that grain, the kernel's TCP accept
queue and socket-buffer paths become the bottleneck before user-space
contention does. The shared structures Mirage *does* protect with mutexes
(audit queue, detection state map, token bucket) sit outside the
hot path on this benchmark.

## Client-concurrency sweep (server workers = 8)

`connection_storm --per-thread 2000`, varying `--threads`.

| client threads | total sessions | elapsed (s) | sessions / s |
|---:|---:|---:|---:|
| 1  | 2,000  | 0.137 | 14,554 |
| 4  | 8,000  | 0.265 | 30,142 |
| 8  | 16,000 | 0.542 | 29,502 |
| 16 | 32,000 | 1.214 | 26,358 |

A single client thread saturates one core's syscall path at ~14.5k
sessions/s; four client threads roughly double that to **30,142
sessions/s**, which is the sustained peak we observed. Beyond 4 client
threads the loopback path gets backpressured and throughput plateaus.

## Headline numbers

- **Peak sustained throughput**: ~30,170 sessions/s on this machine.
- **Per-thread baseline**: ~14,500 sessions/s.
- **Failed sessions across all runs**: 0 (excluding transient TIME_WAIT
  exhaustion when running back-to-back with >10k sessions/s).
- **Audit-pipeline backlog**: queue depth stayed near zero; `pending()`
  never exceeded a couple of events, meaning detection rules and JSONL
  writes kept up with peak ingestion.

## Reproducing

```sh
cmake -DCMAKE_BUILD_TYPE=Release -S . -B build && cmake --build build -j
./build/mirage --no-ratelimit --workers 8 --audit-log /tmp/bench.jsonl &
sleep 0.5
./build/connection_storm --threads 4 --per-thread 4000
kill %1
```

## Notes on what these numbers do *not* prove

- Real attackers come over the open internet, not loopback. Wide-area
  numbers will be 1–2 orders of magnitude lower because round-trip time
  dominates.
- `connection_storm` always issues a valid Postgres handshake. Malformed
  or partial payloads (slowloris-style) exercise different code paths
  and aren't covered by this benchmark.
- Throughput here is a ceiling, not a target. In production the rate
  limiter would cap each source IP at the configured burst, so the
  *useful* upper bound is `burst × tracked_ips × refill_per_sec`.
