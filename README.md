# SentinelX

Self-hosted EDR + lightweight SIEM whose differentiator is **correlation and
narrative**, not raw collection. It turns many endpoint events into few
**investigations** by reasoning over a per-host provenance graph, and it defends
against the failure mode that makes naive correlation useless — dependency
explosion.

> Status: v1 is a working system end to end. A **real Linux eBPF agent** streams
> live execve telemetry → normalize → provenance graph + detect → correlate →
> **Postgres-durable** stores → HTTP API → **React UI**, with a tamper-evident
> evidence chain and an injection-hardened narrative layer. Verified live on a
> 6.19 kernel and Postgres 17. See **Honest status** for what remains.

## Quickstart

```bash
make test                 # unit + e2e + narrator red-team + benchmark
SENTINELX_TOKEN=demo ./demo.sh   # backend up, replay attack, print investigation + narrative
make bench                # alert-reduction ratio + precision/recall over labeled scenarios
make coverage             # MITRE ATT&CK coverage from the ruleset
make ui                   # serve API + React UI at http://localhost:8080

# real eBPF agent (Linux, needs root to load BPF):
make agent && sudo ./bin/sentinelx-agent --backend http://localhost:8080 --token demo

# Postgres durability (rewarm on restart):
SENTINELX_PG="host=/var/run/postgresql dbname=sentinelx" make ui
SENTINELX_TEST_PG="..." make test-pg   # live integration + durability tests

# offline, no server:
go run ./cmd/sentinelx replay --rules ./rules tests/scenarios/curl_lolbin.json
go run ./cmd/sentinelx bench  --rules ./rules --dir tests/scenarios/bench
```

### Verified live this build

- **eBPF agent** loaded on kernel 6.19, traced real `execve` via a tracepoint +
  ring buffer, forwarded to the backend; a real `/tmp/sx_payload` execution fired
  `exec_from_tmp` → one investigation (risk 87, T1204.002 + T1059.004).
- **Postgres 17**: ingest → kill backend → restart → **rewarmed 7 events** → the
  investigation was restored and served over HTTP.
- **UI**: served by the backend (`/`), renders the investigation list, provenance
  graph (SVG), timeline, auditable risk breakdown, and grounded narrative.

### Benchmark (real numbers, not adjectives)

```
SCENARIO                 LABEL       RAW   DET   INV   REDUCE  OUTCOME
curl_lolbin_exec_from_tmp malicious     7     4     1    4.00x  TP
wget_tmp_exec            malicious     6     3     1    3.00x  TP
benign_admin_session     benign        4     0     0    0.00x  TN
benign_curl_update       benign        4     1     1    1.00x  FP
multi_stage_intrusion    malicious     9     6     1    6.00x  TP

alert-reduction (malicious): 4.33x  (13 detections -> 3 investigations)
precision: 0.75  recall: 1.00  (TP=3 FP=1 TN=1 FN=0)
```

`multi_stage_intrusion` is a realistic kill chain — reverse shell → SSH key
theft → cron persistence → history clearing — that exercises 6 of the
17 detection rules across 6 different MITRE techniques, and still collapses
into a single investigation. The curl_lolbin scenario also picked up a 4th
detection versus the original 3: its C2 callback (port 4444) is itself now
caught by `suspicious_c2_port` — a real demonstration of the wider coverage,
not a fluke.

The FP is honest: the `lolbin_curl_download` rule fires on a benign `curl https`
update. The benchmark surfaces exactly this precision cost instead of hiding it.

`demo.sh` ingests `tests/scenarios/curl_lolbin.json` over HTTP and shows one
correlated investigation with a risk score, ordered timeline, MITRE tags, and a
verified tamper-evident evidence chain.

## What it does (worked example)

A Linux ingress-tool-transfer + exec-from-tmp chain — `curl` downloads to
`/tmp/payload`, `chmod +x`, execute, C2 beacon — trips **3 detections** (T1105,
T1222.002, T1204.002/T1059.004). Instead of 3 scattered alerts you get **1
investigation** (risk 100), because all three share process lineage and a rare
write-then-exec causal edge. A second, independent session under the *same* sshd
reusing the *same* `curl` binary does **not** merge in — sshd is a fan-out hub and
the shared binary is a fan-in hub / common-edge boundary.

## Architecture

```
agent (eBPF, [stub]) --mTLS--> ingest --> normalize --> per-host provenance graph
                                                   \--> detect (rules-as-code)
                                                          \--> correlate (weighted
                                                               best-first, hub +
                                                               rarity boundaries)
                                                                 \--> stores + audit
                                                                        \--> HTTP API
```

Seams (interface + simple impl first): `Collector`, `Bus`, `EventStore`,
`InvestigationStore`, `GraphStore`, `Search`, `ObjectStore`, `Narrator`.

## Layout

| path | purpose |
|---|---|
| `backend/correlate` | **the core** — provenance graph, weighted correlation, scoring |
| `backend/normalize` | agent telemetry → canonical Event (Linux `ProcGUID` synthesis) |
| `backend/detect` | deterministic rules-as-code engine (LLM-free) |
| `backend/collect` | Collector seam: file-replay + real Linux `/proc` collector |
| `backend/correlate` → `backend/narrate` | injection-hardened grounded narrator (LLM optional, off the detection path) |
| `backend/bench` | labeled-scenario benchmark: reduction ratio + precision/recall |
| `backend/store` | Event/Investigation stores (in-memory now, Postgres behind iface) |
| `backend/audit` | hash-chained tamper-evident evidence log |
| `backend/pipeline` | the wired vertical slice |
| `backend/api` | HTTP/JSON API + DTOs |
| `backend/store` (`postgres.go`) | durable EventStore/InvestigationStore + rewarm |
| `cmd/sentinelx` | single binary: `serve`, `rules`, `replay`, `bench` |
| `agent/` | **real Linux eBPF agent** (separate module): execve tracepoint + ring buffer via cilium/ebpf |
| `frontend/` | build-free React UI (vendored React+htm), served by the backend |
| `rules/` | detection-as-code (`*.json`) |
| `deploy/` | Dockerfile, docker-compose, Postgres schema |
| `docs/adr`, `docs/design` | decision records, correlation writeup, self-threat-model |
| `tests/` | e2e replay + scenarios + Postgres durability test |
| `.github/workflows` | CI: fmt/vet/test/coverage + attack replay + MITRE + Postgres + agent build |

## Honest status (real vs. stubbed)

**Real, runnable, tested today:**
- Normalization, provenance graph, rarity weighting, hub + rarity boundaries.
- Correlation with over/under-merge guards (unit + e2e tests green).
- Auditable per-factor risk scoring; hash-chained audit log with `Verify`.
- Rules-as-code engine + MITRE coverage report.
- Collector seam with a runnable file-replay collector and a real Linux `/proc`
  collector (tested against this host's own process table).
- Injection-hardened grounded **narrator**, off the detection path, with a
  red-team test suite that plants prompt-injection payloads.
- Benchmark harness with labeled scenarios → alert-reduction ratio +
  precision/recall.
- HTTP API (ingest / list / detail-with-timeline / narrative / audit-verify /
  stats). CI runs fmt/vet/test/coverage + attack replay + MITRE report.
- One-command demo; `replay` and `bench` subcommands.

- **Real Linux eBPF agent** (`agent/`): loads BPF bytecode, attaches the execve
  tracepoint, streams over a ring buffer, forwards to the backend. Verified live.
- **Postgres persistence** with restart-safe rewarm (ADR-0004), live-tested.
- **React UI** served by the backend.
- **Multi-tenant data isolation** (ADR-0005): per-tenant API tokens, per-tenant
  provenance graphs/correlators/baselines/stats/audit chains. Two tenants
  monitoring identically named hosts never collide. Verified at every layer
  (in-memory, Postgres SQL-level, full HTTP) plus a live two-tenant browser check.

**Interface-only / next milestones:**
- eBPF coverage beyond execve: file/network/dns hooks (ADR-0003 maps them; the
  agent currently traces execve, `/proc` collector is the dependency-free fallback).
- NATS JetStream bus for scale-out (in-process today; `Bus` seam defined).
- Graph persistence in Postgres (today the graph is rebuilt by rewarm, not stored).
- Real-LLM `narrate.Model` behind the existing guard layer (guard + deterministic
  model ship today).
- Larger public-dataset benchmark (Atomic Red Team / Caldera captures).
- Multi-user-per-tenant accounts, SSO, self-serve signup, per-tenant compute
  quotas — deliberately out of scope for ADR-0005 (see its "What this is NOT").

Everything marked `[VERIFY]` in code/docs (eBPF hook names, `start_time` source,
literature venues) must be confirmed against sources before it ships.

## Security defaults (v1, not "phase 3")
- Agents authenticate with **mTLS**; analysts with a **per-tenant API token**
  (`SENTINELX_TENANTS`, never a config file — see ADR-0005). Real multi-user
  SSO/OIDC per tenant is still a post-v1 item.
- **Multi-tenant data isolation**: every event/detection/investigation carries a
  tenant id set from the authenticated caller, never from agent-supplied data.
  Provenance graphs, correlators, rarity baselines, stats, and the audit log are
  all scoped per tenant — two tenants monitoring identically named hosts never
  collide or leak into each other. Verified at every layer: in-memory
  (`TestCrossTenantIsolation`), Postgres SQL-level (`TestPGCrossTenantIsolation`),
  and full HTTP (`TestAPI_CrossTenantIsolation`).
- Evidence log is **append-only + hash-chained**, one independently-verifiable
  chain per tenant (`/v1/audit/verify`).
- Detection core is **deterministic and LLM-free**.
- Container runs as **nonroot / distroless**.

License: Apache-2.0.
