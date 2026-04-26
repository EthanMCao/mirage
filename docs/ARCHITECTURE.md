# Mirage architecture

Mirage is a small program with a few clearly-bounded modules and a single
producer/consumer pipeline at its center. This doc walks through the data
flow and the concurrency contract for each piece.

## Data flow

```
   client ─TCP─▶ accept thread ─fd queue─▶ worker pool
                                              │
                                       wire protocol I/O
                                              │
                                          AuditEvent
                                              │
                                       audit MPSC queue
                                              │
                                          audit thread
                                          ├─ run detection rules
                                          └─ append to JSONL sink
```

The accept thread does nothing but `accept()`. Workers do all the wire
protocol, including blocking reads and writes. Workers never touch disk or
detection state directly — they only enqueue events. The audit thread is the
single owner of the JSONL file handle and the detection state, which is why
neither needs to be defended against producer concurrency.

## Modules

### `mirage::wire`

Pure protocol translation. Reads and writes the byte layout described in
[postgresql.org/docs/current/protocol-message-formats.html][1].

Frontend (client → server) messages we parse:
- StartupMessage (no tag, length-prefixed)
- 'p' PasswordMessage
- 'Q' Query
- 'X' Terminate

Backend (server → client) messages we emit:
- 'R' AuthenticationCleartextPassword / AuthenticationOk
- 'E' ErrorResponse (used for the auth-failed path)
- 'S' ParameterStatus (sent during the canned session setup)
- 'K' BackendKeyData
- 'Z' ReadyForQuery
- 'I' EmptyQueryResponse
- 'T' RowDescription + 'D' DataRow + 'C' CommandComplete (for the canned
  one-row response we return to every Query in `accept` mode)

We also gracefully decline SSLRequest / GSSEncRequest by replying `'N'` and
re-reading the next StartupMessage on the same socket.

[1]: https://www.postgresql.org/docs/current/protocol-message-formats.html

### `mirage::session`

State machine for one connection: startup → password → (fail | accept-loop).
In `collect` mode the connection drops as soon as we have the password.
In `accept` mode we hand back a fake successful handshake and keep serving
queries until the client terminates or times out.

### `mirage::audit`

A bounded `std::queue<Event>` defended by a single `std::mutex` and a
`std::condition_variable`. One consumer thread (`AuditPipeline::run`) waits
on the cv, drains the queue, runs detection rules, and writes one JSONL
record per event plus one per alert.

This is a textbook MPSC pattern. We deliberately did not pick a lock-free
queue: the producer rate is bounded by network I/O (microseconds per event
at the very fastest), and the consumer is dominated by `fsync`-grade
disk writes, so contention on the mutex is well below the noise floor.
A lock-free SPSC ring would be a sensible upgrade if multiple audit
threads were ever added per region.

### `mirage::detect`

Per-IP sliding-window state behind a `std::shared_mutex`:
- `on_connection`, `on_auth_attempt`, `on_query` are write paths
  (`std::unique_lock`)
- `snapshot()` is a read path (`std::shared_lock`) called from the periodic
  stats line in `main`

`shared_mutex` is the right primitive here because snapshot reads can be
taken concurrently without blocking each other while writes (state updates)
are exclusive.

### `mirage::log`

Thin JSONL sink: a single `std::ofstream` defended by a `std::mutex`,
flushed on every line so a kill -9 leaves the audit log truncated to the
last whole line rather than mid-record.

## Shutdown

`SIGINT` / `SIGTERM` set an atomic flag the main thread polls. On shutdown:

1. Main calls `Server::stop()`, which closes the listen fd. The accept
   thread sees `accept()` return -1 and exits its loop.
2. `Server::stop()` also flips `stop_requested_` under the queue mutex and
   notifies all workers. Workers drain any remaining queued connections
   (none, in practice — the queue is shallow) and exit.
3. `AuditPipeline::stop()` flips its own `stop_requested_` and notifies the
   audit thread, which drains any pending events before exiting.
4. The `JsonlSink` destructor flushes and closes the file handle.

All threads are joined explicitly; there are no detached threads.

## What's intentionally absent

- **No SSL / TLS.** Speaking TLS would require linking OpenSSL and replaying
  certificate handshakes; Mirage instead politely declines TLS and forces
  the client to fall back to cleartext, which is what bots do anyway.
- **No real auth backend.** Every credential fails (or every credential
  succeeds, in `accept` mode). The point is to harvest, not to authenticate.
- **No IPv6.** The accept loop binds AF_INET only. Trivial extension.
- **No structured rate limiter at the listen layer.** The connection-rate
  detection rule fires alerts but does not drop new connections. Adding
  a per-IP token bucket in the accept thread would be a clean follow-up.
