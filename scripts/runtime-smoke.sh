#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "runtime smoke requires Linux" >&2
  exit 2
fi

if [[ ${EUID} -ne 0 ]]; then
  echo "runtime smoke must run as root (or equivalent BPF-capable privilege)" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

make clean all

work_dir="$(mktemp -d)"
agent_pid=""
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ -n "$agent_pid" ]] && kill -0 "$agent_pid" 2>/dev/null; then
    kill -TERM "$agent_pid" 2>/dev/null || true
    wait "$agent_pid" 2>/dev/null || true
  fi
  rm -rf "$work_dir"
}
trap cleanup EXIT

stdout_file="$work_dir/events.ndjson"
stderr_file="$work_dir/kernwatch.stderr"

./build/kernwatch --no-open >"$stdout_file" 2>"$stderr_file" &
agent_pid=$!

for _ in {1..30}; do
  if ! kill -0 "$agent_pid" 2>/dev/null; then
    echo "KernWatch exited before runtime smoke could begin" >&2
    cat "$stderr_file" >&2 || true
    exit 1
  fi
  sleep 0.1
done

/bin/echo kernwatch-runtime-smoke >/dev/null

python3 -m http.server 18080 --bind 127.0.0.1 >"$work_dir/http.log" 2>&1 &
server_pid=$!
for _ in {1..30}; do
  if curl -fsS http://127.0.0.1:18080/ >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "localhost HTTP server exited unexpectedly" >&2
    cat "$work_dir/http.log" >&2 || true
    exit 1
  fi
  sleep 0.1
done

sleep 0.5
kill -TERM "$agent_pid"
wait "$agent_pid"
agent_pid=""

kill "$server_pid" 2>/dev/null || true
wait "$server_pid" 2>/dev/null || true
server_pid=""

grep -q '"type":"exec"' "$stdout_file"
grep -q '"type":"connect"' "$stdout_file"
grep -q '^kernwatch: dropped_events=[0-9][0-9]*$' "$stderr_file"

python3 - "$stdout_file" <<'PY'
import json
import sys

path = sys.argv[1]
seen = set()
with open(path, "r", encoding="utf-8") as handle:
    for line_number, raw in enumerate(handle, 1):
        line = raw.strip()
        if not line:
            continue
        event = json.loads(line)
        if event.get("schema") != 1:
            raise SystemExit(f"line {line_number}: unexpected schema")
        seen.add(event.get("type"))

missing = {"exec", "connect"} - seen
if missing:
    raise SystemExit(f"missing event types: {sorted(missing)}")
PY

echo "runtime smoke: exec + connect telemetry verified"
