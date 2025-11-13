#!/usr/bin/env bash
# demo.sh — stand up the backend, replay the curl LOLBin chain over HTTP, and
# show that N alerts collapse into ONE correlated investigation.
set -euo pipefail
cd "$(dirname "$0")"

TOKEN="${SENTINELX_TOKEN:-demo}"
ADDR="${ADDR:-:8080}"
BASE="http://localhost${ADDR}"

echo ">> building sentinelx"
go build -o ./bin/sentinelx ./cmd/sentinelx

echo ">> starting backend on ${ADDR}"
SENTINELX_TOKEN="$TOKEN" ./bin/sentinelx serve --addr "$ADDR" --rules ./rules &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
  curl -sf "${BASE}/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done

pp() { if command -v jq >/dev/null 2>&1; then jq "$@"; else cat; fi; }
auth() { curl -s -H "Authorization: Bearer ${TOKEN}" "$@"; }

echo ">> logging in (analyst token gate — see /v1/login):"
curl -s -X POST "${BASE}/v1/login" -H 'Content-Type: application/json' \
  --data "{\"token\":\"${TOKEN}\"}" | pp .

echo ">> replaying scenario: tests/scenarios/curl_lolbin.json"
curl -s -X POST "${BASE}/v1/ingest" \
  -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
  --data @tests/scenarios/curl_lolbin.json | pp .

echo ">> investigations (expect exactly one):"
auth "${BASE}/v1/investigations" | pp '.[] | {id, risk: .risk_score, root: .root_guid, techniques, detections: .detection_count, events: .event_count}'

echo ">> investigation #1 timeline (ordered, each event is evidence):"
auth "${BASE}/v1/investigations/1" | pp '.timeline[] | {ts, type, image, detail}'

echo ">> investigation #1 detections (what fired + how to fix it):"
auth "${BASE}/v1/investigations/1" | pp '.detections[] | {rule: .rule_id, technique, events: .event_ids, remediation}'

echo ">> grounded narrative (LLM-optional, injection-hardened, off the detection path):"
auth "${BASE}/v1/investigations/1/narrative" | pp '{rejected, text}'

echo ">> evidence chain integrity:"
auth "${BASE}/v1/audit/verify" | pp .

echo ">> done."
