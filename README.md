# SentinelX

Self-hosted EDR + lightweight SIEM whose differentiator is **correlation and
narrative**, not raw collection. It turns many endpoint events into few
**investigations** by reasoning over a per-host provenance graph, and it defends
against the failure mode that makes naive correlation useless — dependency
explosion.

> Status: v1 is a working system end to end. A **real Linux eBPF agent** traces
> process (`execve`), network (`inet_sock_set_state`) and file (`openat` write,
> plus secret-only read) telemetry → normalize → provenance graph + detect →
> correlate →
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
- **Live eBPF tracers** — `execve`, `inet_sock_set_state` (→ `net.connect`),
  write-intent `openat` (→ `file.write`), and secret read `openat` (→ `file.read`,
  gated in-kernel to `/etc/` and dot-dirs, then held to an exact allowlist in
  userspace so only credential reads are forwarded). All loaded live on kernel
  6.x. A real `curl http://1.1.1.1/ -o /tmp/x` produced `net.connect raddr=1.1.1.1
  rport=80` and `file.write path=/tmp/x` from the same pid — and the live run
  caught a wrong port byte-swap the unit test had masked (the tracepoint already
  `ntohs()`'s the port); fixed and re-verified.
- **All three graph patterns, end to end from the live agent** (agent → backend,
  not replay):
  - `download_exec_beacon` (T1105+T1071): `cp /usr/bin/curl /tmp/sxdemo` then
    running `/tmp/sxdemo http://1.1.1.1/` raised one investigation (risk 100)
    correlated across the write/exec/connect edges.
  - `credential_read_exfil` (T1552.001+T1041): a process that read
    `~/.ssh/id_rsa` and then connected out fired the pattern, citing the live
    read and connect events.
  - `drop_and_spawn` (T1105+T1059): a process that wrote a binary and spawned it
    fired the pattern — which also surfaced a real gap: the agent wasn't sending
    `parent_start_ticks`, so lineage keyed to a phantom parent node; fixed, and
    the spawned-edge now links to the true parent.
  - `dropped_persistence` (T1547+T1053.003): `cp /usr/bin/dd /tmp/sxp` then
    running it to write a systemd-user unit fired the pattern.
  - `connection_fanout` (T1046): one process connecting to 25 distinct hosts
    (a `192.0.2.0/24` sweep) fired the pattern — a structural, degree-based
    signal (breadth over socket nodes) rather than a linear chain.
- **Race-free process identity (CO-RE)**: a process's `ProcGUID` keys off its
  start time. Reading that from `/proc` in userspace was racy — a dropper that
  exits in microseconds is gone before enrichment, returns `start=0`, and splits
  into a phantom node that breaks correlation. The agent now reads
  `task->start_boottime` (and the real parent's pid + start) **in-kernel via
  CO-RE**, at event time, so identity is exact regardless of process lifetime.
  Verified: three back-to-back instant-exit droppers each fired
  `dropped_persistence`, and all five graph patterns fire in one combined run.
  This is the only place the agent uses CO-RE; everything else stays vmlinux-free.
- **Triage Agent**: tool-using loop (`read_graph_context`, `sandbox_exec`, `query_sentinelx_api`) that reproduces command chains in an isolated environment and produces structured verdicts with an anti-confound check (`"did I just believe the attacker's own narration?"`).
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
| `backend/correlate` | **the core** — provenance graph, weighted correlation, scoring, and graph patterns (cross-event shapes the single-event rules can't express): `download_exec_beacon` (an image another process wrote is executed and beacons out), `credential_read_exfil` (a process reads a secret file then connects out), `drop_and_spawn` (a process writes an executable and spawns it), `dropped_persistence` (a dropped image writes to a persistence location — cron/systemd/rc/authorized_keys), and `connection_fanout` (one process connects to many distinct hosts — scanning/spraying). Patterns are registered in `pattern.go` and fire once per process |
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
| `agent/` | **real Linux eBPF agent** (separate module): `execve` + `inet_sock_set_state` (net.connect) + `openat` (file.write, and secret-only file.read) tracepoints, each a ring buffer streamed via cilium/ebpf |
| `frontend/` | build-free React UI (vendored React+htm), served by the backend |
| `rules/` | detection-as-code (`*.json`) |

License: Apache-2.0.
