#!/usr/bin/env bash
# Quick manual check of a running DockGate instance.
# Usage: DOCKGATE=http://127.0.0.1:2375 ./examples/smoke-test.sh
set -euo pipefail

DOCKGATE="${DOCKGATE:-http://127.0.0.1:2375}"

req() { # method path [json-body]
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -s -o /dev/null -w "%{http_code}" -X "$method" \
      -H 'Content-Type: application/json' -d "$body" "$DOCKGATE$path"
  else
    curl -s -o /dev/null -w "%{http_code}" -X "$method" "$DOCKGATE$path"
  fi
}

echo "Target: $DOCKGATE"
printf '%-45s %s\n' "GET  /_ping (expect 200)"                 "$(req GET  /_ping)"
printf '%-45s %s\n' "GET  /v1.43/containers/json (expect 200)" "$(req GET  /v1.43/containers/json)"
printf '%-45s %s\n' "POST create ubuntu (expect 403)"          "$(req POST /v1.43/containers/create '{"Image":"ubuntu:22.04"}')"
printf '%-45s %s\n' "POST create privileged (expect 403)"      "$(req POST /v1.43/containers/create '{"Image":"nginx","HostConfig":{"Privileged":true}}')"
printf '%-45s %s\n' "POST exec (expect 403)"                   "$(req POST /v1.43/containers/x/exec '{"Cmd":["sh"]}')"
printf '%-45s %s\n' "POST networks/create (expect 403)"        "$(req POST /v1.43/networks/create '{"Name":"x"}')"
