# ADR-0002: Provenance-graph correlation with explosion mitigation

Status: accepted · Date: 2026-07-08

## Context
Alert fatigue is the problem. The naive fix — grouping alerts by time + entity —
either under-merges (the alert storm the analyst already drowns in) or
over-merges via a long-lived, high-degree process (systemd, sshd) or a common
shared object (`/usr/bin/curl` executed by everything) until every investigation
is one blob. This "dependency explosion" is the documented failure mode of
provenance analysis (BackTracker, SLEUTH, HOLMES, NoDoze, PrioTracker — venues
`[VERIFY]`).

## Decision
Model telemetry as a per-host provenance graph (processes/files/sockets/dns/
modules as nodes; spawn/write/read/exec/connect/resolve/load as timestamped,
rarity-weighted edges). Correlate by a **weighted best-first walk** of a
detection's causal neighborhood, with two boundary mechanisms:

1. **Hub termination** — a node whose in- OR out-degree exceeds `HubDegree` is a
   hub (high-fanout process OR high-fanin shared binary). Traversal settles it
   as a boundary but never expands through it, and boundary nodes never
   contribute investigation membership.
2. **Rarity boundary** — an edge below `CommonWeight` is common; a common edge
   cannot bridge two investigations.

Merges are driven by rare causal edges (write-then-exec) and shared lineage
roots. Scoring is an auditable per-factor sum, every factor citing event ids.

## Consequences
- Over-merge and under-merge are both defended, demonstrably (see
  `correlate/correlator_test.go`: 3→1 plus an over-merge guard).
- The core is deterministic and LLM-free — the trust property.
- Risk: window/weight tuning. Failing signal: alert-reduction ratio → 1:1
  (under-merge) or one investigation spanning multiple hosts (over-merge).

## Rejected
- Pure temporal+entity grouping: the over/under-merge trap above.
- ML/embedding correlation for v1: not explainable-by-construction; would put a
  black box on the trust path.
