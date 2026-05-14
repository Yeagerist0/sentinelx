# Correlation & provenance subsystem

This is the intellectual core of SentinelX: turning many causally-related events
into few investigations without falling into dependency explosion. Code lives in
`backend/correlate/`.

## Problem

An analyst does not have an "alert problem," they have a *grouping* problem. A
single intrusion emits dozens of individually-suspicious events. Two failure
modes bracket any grouping scheme:

- **Under-merge**: emit one alert per suspicious event → the storm that causes
  alert fatigue.
- **Over-merge**: connect everything transitively → one long-lived process
  (systemd, sshd) or one shared object (`/usr/bin/curl`, `/bin/bash`, a common
  DLL) bridges unrelated activity and every investigation becomes one blob. This
  is *dependency explosion*, the documented failure mode of provenance analysis
  (BackTracker; SLEUTH; HOLMES; NoDoze; PrioTracker; ATLAS; DEPCOMM; UNICORN;
  RAIN — venues/years `[VERIFY]`).

## Model

Per host, a provenance graph:
- **Nodes**: process (keyed by the stable `ProcGUID`), file, socket, dns, module.
- **Edges**: `spawned`, `wrote`, `read`, `executed`, `connected`, `resolved`,
  `loaded` — each timestamped, carrying the source event id, and weighted by
  rarity.

**Rarity weight** (`baseline.go`): for each `(image|rel|kind)` key,
`w = clamp(1 - count/total, 0.05, 1.0)`. Common edges → ~0.05, unseen → 1.0. This
is the anomaly signal, learned online (NoDoze/PrioTracker in spirit).

## Algorithm (`correlator.go`)

A detection seeds correlation on its anchor process. `expand` runs a **weighted
best-first walk** (min-heap on path cost, `cost += 1 - weight`), so the *rarest*
paths are followed first and common noise dies within the cost budget. The walk
is bounded by:

- **time window** (`±Window` around the seed),
- **cost budget** (`CostBudget`),
- **node cap** (`MaxNodes`, last-resort over-merge guard),
- **hub termination**: a node whose in- or out-degree exceeds `HubDegree` is a
  boundary — settled but never expanded through, never a membership contributor.
  In-degree matters as much as out-degree: a binary executed by many processes is
  a shared bridge exactly like a high-fanout process.
- **rarity boundary**: an edge below `CommonWeight` is common; the node it
  reaches is a boundary. Two investigations can never merge across a common edge.

**Merge logic**: a seed joins an existing investigation if its subgraph touches a
non-boundary member node, or if it shares a **lineage root** (walk `spawned`
in-edges up to the first hub) — the latter is a force-merge that survives the
time window, defeating under-merge. Boundary contacts (a shared `sshd`, a shared
`/usr/bin/curl`) do **not** cause merges, defeating over-merge.

**Growth**: `Observe` attaches later non-seed events whose process is already a
member (a C2 beacon after the exec that tripped the rule), so investigations grow
as activity continues, then close on idle.

## Scoring (`score.go`) — explainable by construction

`risk = clamp( Σ_d base(d)·ctx(d) · novelty , 0, 100)`, returned alongside a
`[]ScoreFactor` where every factor cites the event ids it is grounded in. The
score *is* its breakdown; the UI renders "why", not a bare number.

## Worked result

The replayed Linux chain (`tests/scenarios/curl_lolbin.json`): 7 raw events, 3
detections (T1105, T1222.002, T1204.002/T1059.004) → **1 investigation**, risk
100, ordered timeline, tamper-evident evidence chain. Alert-reduction 3→1 (7→1 on
raw events). See `tests/e2e_test.go` and `correlate/correlator_test.go` (which
also asserts the over-merge guard with a second session under the same sshd).

## Limits (honest)

- Rarity boundaries depend on a warm baseline; a cold fleet treats everything as
  rare until it learns. Mitigation: ship a seed baseline; alert on baseline age.
- Full version-graph pruning (BackTracker-style time-ordered read/write
  dependency reduction) is a documented extension point in `expand`, not yet
  implemented — v1 uses the time window + causal edges.
- Window/weight thresholds are per-deploy tunables; there is no auto-tuner yet.
