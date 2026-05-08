# Mirage

A multi-threaded honeypot in C++17 that speaks the PostgreSQL v3 wire protocol.
To attackers it looks like a real database; to defenders it produces a
high-fidelity, structured audit log of every probe, credential attempt, and
query — ready to ship into a SIEM.

## Why

Real database servers exposed to the internet get scanned constantly:
credential-spray bots, mass-port-scan tooling, and operators looking for
unpatched CVEs. Putting a Postgres honeypot in front of them means:

1. Probes hit the decoy first, so you see the attacker's tradecraft before
   they touch a real system.
2. Credentials, usernames, and queries the attacker tries are logged
   verbatim, giving threat-intel signal.
3. The honeypot is read-only and stateless — there is no real data to leak.

## What it does

- Listens on a TCP port (IPv4 or IPv6 dual-stack) and speaks Postgres
  protocol v3 — the same protocol `psql` and every Postgres client uses.
- Accepts a `StartupMessage`, requests cleartext password, harvests the
  attempt, and returns either an authentication failure or a fake success
  (configurable).
- For sessions that "log in," handles both the simple-query (`Q`) and
  the extended-query (`Parse`/`Bind`/`Describe`/`Execute`/`Sync`/`Close`)
  flows with canned one-row results, so libpq-based clients and ORMs
  keep talking past the first round trip.
- A per-IP token-bucket rate limiter at the accept layer drops abusive
  source IPs *before* any wire-protocol work runs.
- Pushes every event onto an in-process audit queue consumed by a dedicated
  detection thread.
- Detection thread runs sliding-window rules (connection-rate spikes, auth
  spray across users, suspicious-query keywords) and emits Wazuh-compatible
  JSONL. Decoders and rules are checked in under [`docs/wazuh/`](docs/wazuh).
- Sustains ~30k full sessions/sec on a single Apple M3 Pro at zero failure
  — see [`docs/BENCHMARK.md`](docs/BENCHMARK.md).

## Architecture

```
   ┌──────────────────┐
   │  accept() thread │  one main thread, blocks on accept()
   └────────┬─────────┘
            │ pushes accepted fd
            ▼
   ┌──────────────────┐
   │  worker pool (N) │  thread-pool drains the connection queue
   └────────┬─────────┘
            │ runs Session::run() per connection,
            │ enqueues AuditEvent for every wire event
            ▼
   ┌──────────────────┐
   │  audit thread    │  applies detection rules, writes JSONL
   └────────┬─────────┘
            │
            ▼
       audit.jsonl   (Wazuh-compatible structured log)
```

Concurrency primitives:
- `std::mutex` + `std::condition_variable` on both the connection queue
  and the audit queue (classic bounded MPSC pattern).
- `std::atomic<uint64_t>` counters for connection / query / detection
  totals exposed via the periodic stats line.
- Per-IP detection state guarded by a single `std::shared_mutex` (readers
  for stat dumps, writers when updating sliding windows).

## Build

```sh
cmake -S . -B build
cmake --build build -j
./build/mirage --help
```

CMake 3.16+, a C++17 compiler, and POSIX sockets (Linux or macOS).

### Docker

```sh
docker build -t mirage .
docker run --rm -p 55432:55432 -v $PWD/audit:/home/mirage mirage
```

### Fuzzing

The wire-protocol parser has a libFuzzer harness; built only with clang.

```sh
CC=clang CXX=clang++ cmake -S . -B build-fuzz \
  -DMIRAGE_FUZZ=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-fuzz -j --target fuzz_wire_protocol
./build-fuzz/fuzz/fuzz_wire_protocol -max_total_time=60
```

## Run

```sh
# Default: listen on 127.0.0.1:55432, four worker threads, audit log to ./audit.jsonl
./build/mirage

# Custom: dual-stack IPv6, 8 workers, tighter detection thresholds
./build/mirage \
  --host :: --port 5432 --workers 8 \
  --audit-log /var/log/mirage.jsonl \
  --detect-conn-rate 5 --detect-spray-users 3 \
  --ratelimit-burst 10 --ratelimit-refill 2

./build/mirage --help
```

Smoke test with `psql`:

```sh
PGPASSWORD=hunter2 psql -h 127.0.0.1 -p 55432 -U admin postgres -c 'select 1;'
tail -f audit.jsonl
```

## Detection rules

| rule              | window | trigger                                                 |
|-------------------|--------|---------------------------------------------------------|
| `conn_rate_spike` | 60s    | a single source IP opens > 10 connections               |
| `auth_spray`      | 300s   | a single source IP attempts > 5 distinct usernames      |
| `suspicious_query`| n/a    | a query touches `pg_shadow`, `pg_authid`, `pg_user`, or `information_schema.user_*` |

All thresholds are tunable via CLI flags (`--detect-conn-rate`,
`--detect-conn-window`, `--detect-spray-users`, `--detect-spray-window`)
and have safe defaults in `include/mirage/detection.hpp`. Detection rules
*alert* — the per-IP token-bucket rate limiter is what *drops* abusive
traffic at the accept layer.

## Audit log format

One JSON object per line; compatible with Wazuh's `localfile` JSON decoder.

```json
{"ts":"2026-05-08T20:14:03Z","event":"startup","src_ip":"203.0.113.7","src_port":52114,"user":"admin","database":"postgres"}
{"ts":"2026-05-08T20:14:03Z","event":"password","src_ip":"203.0.113.7","user":"admin","password":"hunter2"}
{"ts":"2026-05-08T20:14:03Z","event":"query","src_ip":"203.0.113.7","user":"admin","sql":"select 1"}
{"ts":"2026-05-08T20:14:03Z","event":"detection","rule":"conn_rate_spike","src_ip":"203.0.113.7","window_s":60,"count":11}
```

## Tests

```sh
ctest --test-dir build --output-on-failure
```

Suites cover the wire-protocol parser (simple + extended messages and
all backend frame builders), the detection sliding-window logic, the
per-IP rate limiter, and end-to-end `Session::run()` flows over a
socket pair (collect mode, accept mode, SSL decline, extended query,
EOF during startup).

## Status

Reference implementation. Single-node only. Read-only honeypot — never
point this at a real database, and never expose it on a port the
production database expects to use.
