# SentinelX

Self-hosted EDR + lightweight SIEM whose differentiator is **correlation and
narrative**, not raw collection. It turns many endpoint events into few
**investigations** by reasoning over a per-host provenance graph, and it defends
against the failure mode that makes naive correlation useless — dependency
explosion.

> Status: v1 is a working system end to end. A **real Linux eBPF agent** traces
> process (`execve`), network (`inet_sock_set_state`) and file (`openat` write)
> telemetry → normalize → provenance graph + detect → correlate →
> **Postgres-durable** stores → HTTP API → **React UI**, with a tamper-evident
> evidence chain, an injection-hardened narrative layer, and a **Triage Agent** tool-using loop with sandbox reproduction and anti-confound evaluation.

## Quickstart

```bash
make test                 # unit + e2e + narrator red-team + triage + benchmark
SENTINELX_TOKEN=demo ./demo.sh   # backend up, replay attack, print investigation + narrative
make bench                # alert-reduction ratio + precision/recall over labeled scenarios
make triage-eval          # held-out eval set: accuracy, FPR, failure taxonomy, confound resilience
make coverage             # MITRE ATT&CK coverage from the ruleset
make ui                   # serve API + React UI at http://localhost:8080

# real eBPF agent (Linux, needs root to load BPF):
make agent && sudo ./bin/sentinelx-agent --backend http://localhost:8080 --token demo

# Postgres durability (rewarm on restart):
SENTINELX_PG="host=/var/run/postgresql dbname=sentinelx" make ui
SENTINELX_TEST_PG="..." make test-pg   # live integration + durability tests

# offline, no server:
go run ./cmd/sentinelx replay --rules ./rules tests/scenarios/curl_lolbin.json
go run ./cmd/sentinelx triage --rules ./rules tests/scenarios/curl_lolbin.json
go run ./cmd/sentinelx bench  --rules ./rules --dir tests/scenarios/bench
go run ./cmd/sentinelx eval   --rules ./rules
```

### Verified live this build

- **eBPF agent** loaded on kernel 6.19, traced real `execve` via a tracepoint +
  ring buffer, forwarded to the backend; a real `/tmp/sx_payload` execution fired
  `exec_from_tmp` → one investigation (risk 87, T1204.002 + T1059.004).
- **Network + file tracers** (new): `inet_sock_set_state` (outbound TCP →
  `net.connect`) and write-intent `openat` (→ `file.write`). Loaded live on
  kernel 6.x; a real `curl http://1.1.1.1/ -o /tmp/x` produced
  `net.connect raddr=1.1.1.1 rport=80` and `file.write path=/tmp/x` from the same
  `curl` pid (same `start_ticks` → same process node). The live run also caught a
  wrong port byte-swap the unit test had masked (the tracepoint already
  `ntohs()`'s the port); fixed and re-verified.
- **`download_exec_beacon` graph pattern, end to end from the live agent**: with
  the agent streaming to the backend, `cp /usr/bin/curl /tmp/sxdemo` then running
  `/tmp/sxdemo http://1.1.1.1/` raised **one** investigation (risk 100) whose
  detections were `exec_from_tmp`, `lolbin_curl_download`, and the graph pattern
  `download_exec_beacon` (T1105+T1071) — the dropped image was executed and
  beaconed, correlated across the write/exec/connect edges, not replay. A second
  pattern, `credential_read_exfil` (secret read → outbound connection), is
  complete and unit/pipeline-tested but validated via replay only: the live agent
  does not emit `file.read` yet (read-opens are too high-volume to trace naively),
  so it cannot be driven end to end from the kernel until that telemetry exists. tool-using loop (`read_graph_context`, `sandbox_exec`, `query_sentinelx_api`) that reproduces command chains in an isolated environment and produces structured verdicts with an anti-confound check (`"did I just believe the attacker's own narration?"`).
- **Held-out eval set**: benchmark harness reporting accuracy (80%), false-positive rate (50%), failure taxonomy (`MisclassifiedBenign`), and 100% confound resilience.
- **Postgres 17**: ingest → kill backend → restart → **rewarmed 7 events** → the
  investigation was restored and served over HTTP.
- **UI**: served by the backend (`/`), renders the investigation list, provenance
  graph (SVG), timeline, auditable risk breakdown, grounded narrative, and Triage Agent verdict card.

### Benchmark (real numbers, not adjectives)

```
SCENARIO                 LABEL       RAW   DET   INV   REDUCE  OUTCOME
curl_lolbin_exec_from_tmp malicious     7     5     1    5.00x  TP
wget_tmp_exec            malicious     6     4     1    4.00x  TP
benign_admin_session     benign        4     0     0    0.00x  TN
benign_curl_update       benign        4     1     1    1.00x  FP
multi_stage_intrusion    malicious     9     6     1    6.00x  TP

alert-reduction (malicious): 5.00x  (15 detections -> 3 investigations)
precision: 0.75  recall: 1.00  (TP=3 FP=1 TN=1 FN=0)
```

## Architecture & Triage Loop

```
SentinelX detection (provenance graph node/chain)
        │
        ▼
  Triage Agent (tool-using loop)
        │
   ┌────┼────────────────┐
   ▼    ▼                ▼
 Read   Sandbox exec     Query SentinelX
 graph  (reproduce the   API for related
 context command chain,  events / process
        isolated env)    lineage
   │
   ▼
Structured verdict:
 { exploitable: bool, confidence, evidence[], reproduction_steps[],
   confound_check: "did I just believe the attacker's own narration?" }
        │
        ▼
Held-out eval set → accuracy, false-positive rate, failure taxonomy
```

Seams (interface + simple impl first): `Collector`, `Bus`, `EventStore`,
`InvestigationStore`, `GraphStore`, `Search`, `ObjectStore`, `Narrator`, `SandboxExecutor`, `TriageAgent`, `EvalHarness`.

## Layout

| path | purpose |
|---|---|
| `backend/correlate` | **the core** — provenance graph, weighted correlation, scoring, and graph patterns (cross-event shapes the single-event rules can't express): `download_exec_beacon` (an image another process wrote is executed and beacons out) and `credential_read_exfil` (a process reads a secret file then connects out). Patterns are registered in `pattern.go` and fire once per process |
| `backend/normalize` | agent telemetry → canonical Event (Linux `ProcGUID` synthesis) |
| `backend/detect` | deterministic rules-as-code engine (LLM-free) |
| `backend/collect` | Collector seam: file-replay + real Linux `/proc` collector |
| `backend/triage` | **triage agent** — tool-using loop (`ReadGraphContext`, `SandboxExec`, `QuerySentinelXAPI`), anti-confound check, held-out eval set |
| `backend/correlate` → `backend/narrate` | injection-hardened grounded narrator (LLM optional, off the detection path) |
| `backend/bench` | labeled-scenario benchmark: reduction ratio + precision/recall |
| `backend/store` | Event/Investigation stores (in-memory now, Postgres behind iface) |
| `backend/audit` | hash-chained tamper-evident evidence log |
| `backend/pipeline` | the wired vertical slice |
| `backend/api` | HTTP/JSON API + DTOs |
| `cmd/sentinelx` | single binary: `serve`, `rules`, `replay`, `bench`, `triage`, `eval` |
| `agent/` | **real Linux eBPF agent** (separate module): `execve` + `inet_sock_set_state` (net.connect) + `openat`-write (file.write) tracepoints, each a ring buffer streamed via cilium/ebpf |
| `frontend/` | build-free React UI (vendored React+htm), served by the backend |
| `rules/` | detection-as-code (`*.json`) |

License: Apache-2.0.
