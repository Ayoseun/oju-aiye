#!/usr/bin/env bash
# End-to-end smoke test: real API + real CLI over HTTP, with a scripted stand-in model
# (replayllm) instead of Ollama. Needs only Go; no GPU, no model download.
#
#   scripts/e2e.sh                      # vulnerable (expect confirmed) + patched (expect refuted)
#   scripts/e2e.sh <dir> <expected>     # your own dir, expecting: confirmed | refuted | inconclusive
#
# Note: the stand-in model only "knows" the path-traversal scenario in testdata/scenarios,
# so custom targets only make sense if they contain a matching fileserve.Read.
set -euo pipefail
cd "$(dirname "$0")/.."

API_PORT="${E2E_PORT:-18080}"
LLM_ADDR="127.0.0.1:${REPLAY_PORT:-11435}"
export E2E_PORT="$API_PORT" REPLAY_BASE_URL="http://${LLM_ADDR}/v1"
export E2E_ARTIFACT_DIR="$(mktemp -d)"
export GOCACHE="${GOCACHE:-${TMPDIR:-/tmp}/oju-e2e-gocache}"   # shared with validation runs so repeat runs are fast
CLI=(./bin/cli --server "http://127.0.0.1:${API_PORT}")

mkdir -p bin
go build -o bin/ ./cmd/api ./cmd/cli ./cmd/replayllm

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$E2E_ARTIFACT_DIR"; }
trap cleanup EXIT

./bin/replayllm -addr "$LLM_ADDR" -scenario testdata/scenarios/traversal 2>/tmp/e2e-replay.log &
PIDS+=($!)
./bin/api -config configs/config.e2e.yaml >/tmp/e2e-api.log 2>&1 &
PIDS+=($!)

for _ in $(seq 1 50); do
  curl -fs "http://127.0.0.1:${API_PORT}/health/ready" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -fs "http://127.0.0.1:${API_PORT}/health/ready" >/dev/null || { echo "API did not become ready; see /tmp/e2e-api.log"; exit 1; }
echo "API ready (health probes models via replayllm)"

run_case() {  # <dir> <expected job status>
  local dir expected id status="" out
  dir="$(cd "$1" && pwd)"; expected="$2"
  out="$("${CLI[@]}" --authorized create "$dir" HEAD)"
  id="$(printf '%s' "$out" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)"
  [ -n "$id" ] || { echo "could not create job: $out"; return 1; }
  LAST_ID="$id"
  for _ in $(seq 1 120); do
    status="$("${CLI[@]}" inspect "$id" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)"
    case "$status" in confirmed|refuted|inconclusive|failed|cancelled) break ;; esac
    sleep 2
  done
  echo "== $(basename "$dir"): job $id -> $status (expected $expected)"
  "${CLI[@]}" report "$id" --format markdown | sed -n '1,25p'
  [ "$status" = "$expected" ]
}

check_console_surface() {  # <confirmed job id>
  local id="$1" base="http://127.0.0.1:${API_PORT}" html hdrs events report ref code
  echo "== console + API surface the web UI depends on"
  hdrs="$(curl -sI "$base/")"
  echo "$hdrs" | grep -qi '^content-security-policy:.*default-src .none' || { echo "FAIL: console is missing its CSP header"; return 1; }
  html="$(curl -s "$base/")"
  if printf '%s' "$html" | grep -Eqi '<script[^>]+src=|<link[^>]+href=|@import|url\('; then echo "FAIL: console loads an external resource"; return 1; fi
  events="$(curl -s "$base/api/v1/jobs/$id/events")"
  printf '%s' "$events" | grep -q '"transitions"' && printf '%s' "$events" | grep -q '"role":"scout"' || { echo "FAIL: /events is missing transitions or tasks"; return 1; }
  report="$(curl -s "$base/api/v1/jobs/$id/report")"
  printf '%s' "$report" | grep -q '"validation_plan"' || { echo "FAIL: report findings lack validation_plan"; return 1; }
  ref="$(printf '%s' "$report" | grep -o 'artifact://[0-9a-f]\{64\}' | head -1 | sed 's#artifact://##')"
  [ -n "$ref" ] || { echo "FAIL: no validation artifact reference in report"; return 1; }
  curl -s "$base/api/v1/artifacts/$ref" | grep -q 'FAIL' || { echo "FAIL: artifact endpoint did not return the failing test output"; return 1; }
  code="$(curl -s -o /dev/null -w '%{http_code}' "$base/api/v1/artifacts/not-a-hash")"
  [ "$code" = "400" ] || { echo "FAIL: malformed artifact id returned HTTP $code, want 400"; return 1; }
  curl -s "$base/api/v1/system" | grep -q '"data_leaves_machine":false' || { echo "FAIL: /api/v1/system should report a fully local setup for the e2e config"; return 1; }
  echo "ok: CSP present, no external resources, /events, /report plan, /artifacts (and its input check), /system"
}

rc=0
if [ "$#" -ge 2 ]; then
  run_case "$1" "$2" || rc=1
else
  run_case testdata/targets/traversal-vulnerable confirmed || rc=1
  VULN_ID="$LAST_ID"
  run_case testdata/targets/traversal-patched refuted || rc=1
  check_console_surface "$VULN_ID" || rc=1
fi
[ "$rc" -eq 0 ] && echo "E2E PASSED" || { echo "E2E FAILED (logs: /tmp/e2e-api.log /tmp/e2e-replay.log)"; exit 1; }
