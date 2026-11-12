#!/usr/bin/env bash
# Run one real audit against a real model and print the report.
#
#   scripts/audit.sh [target-directory]
#
# Defaults to the bundled vulnerable fixture (testdata/targets/traversal-vulnerable), which
# contains a path-traversal bug in fileserve.Read. Point it at any directory you are authorized
# to audit:
#
#   scripts/audit.sh /path/to/repo
#
# Requires the API to be running (make run-api / make run-api-mac / make run-api-free).
set -uo pipefail

cd "$(dirname "$0")/.."

TARGET="${1:-testdata/targets/traversal-vulnerable}"
SERVER="${SERVER:-http://localhost:8080}"
CLI="${CLI:-./bin/cli}"
POLL_SECONDS="${POLL_SECONDS:-3}"
# Optional scope manifest: which paths are in scope and which findings are already known.
SCOPE="${SCOPE:-}"

if [[ ! -d "$TARGET" ]]; then
  echo "target directory not found: $TARGET" >&2
  exit 1
fi
if [[ ! -x "$CLI" ]]; then
  echo "CLI not built: run 'make build' first" >&2
  exit 1
fi

ABS_TARGET="$(cd "$TARGET" && pwd)"

echo "==> target: $ABS_TARGET"
echo "==> server: $SERVER"

RESPONSE="$($CLI --server "$SERVER" --authorized ${SCOPE:+--scope "$SCOPE"} create "$ABS_TARGET" HEAD)"
JOB_ID="$(printf '%s' "$RESPONSE" | sed -nE 's/.*"id"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -1)"

if [[ -z "$JOB_ID" ]]; then
  echo "could not create job. server said:" >&2
  printf '%s\n' "$RESPONSE" >&2
  exit 1
fi

echo "==> job: $JOB_ID"
echo

TERMINAL="confirmed refuted inconclusive failed cancelled"
LAST_STATUS=""

while true; do
  DETAILS="$($CLI --server "$SERVER" inspect "$JOB_ID" 2>/dev/null)"
  STATUS="$(printf '%s' "$DETAILS" | sed -nE 's/.*"status"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -1)"

  if [[ -n "$STATUS" && "$STATUS" != "$LAST_STATUS" ]]; then
    printf '[%s] %s\n' "$(date +%H:%M:%S)" "$STATUS"
    LAST_STATUS="$STATUS"
  fi

  for t in $TERMINAL; do
    if [[ "$STATUS" == "$t" ]]; then
      break 2
    fi
  done

  sleep "$POLL_SECONDS"
done

echo
echo "==> final status: $STATUS"
echo
"$CLI" --server "$SERVER" report "$JOB_ID" --format markdown
