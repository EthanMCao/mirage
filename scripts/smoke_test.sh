#!/usr/bin/env bash
# Quick end-to-end smoke test: launch mirage, hit it with psql in both
# auth modes, and dump the resulting audit lines.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build"
BIN="$BUILD/mirage"
LOG="$ROOT/audit.smoke.jsonl"
PORT="${PORT:-55432}"

if [[ ! -x "$BIN" ]]; then
  echo "build first: cmake -S . -B build && cmake --build build -j" >&2
  exit 1
fi

if ! command -v psql >/dev/null 2>&1; then
  echo "psql not found; install postgres client first" >&2
  exit 1
fi

rm -f "$LOG"

run_with_mode() {
  local mode="$1"
  echo "=== auth-mode=$mode ==="
  "$BIN" --port "$PORT" --auth-mode "$mode" --audit-log "$LOG" &
  local pid=$!
  sleep 0.3

  set +e
  PGPASSWORD=hunter2 psql -h 127.0.0.1 -p "$PORT" -U admin postgres \
      -c 'select 1;' >/dev/null 2>&1
  set -e
  sleep 0.2

  kill -INT "$pid" || true
  wait "$pid" 2>/dev/null || true
}

run_with_mode collect
run_with_mode accept

echo "--- audit log ---"
cat "$LOG"
