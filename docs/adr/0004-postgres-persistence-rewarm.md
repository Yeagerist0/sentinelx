# ADR-0004: Postgres persistence via event-log + rewarm

Status: accepted · Date: 2026-07-09

## Context
The correlation engine keeps a per-host provenance graph in memory (ADR-0001).
That is fast and bounded, but a restart loses all state. We need durability
without moving the hot graph into the database.

## Decision
Persist the **event log as the source of truth** and treat investigations as a
**materialized view**. On startup with `SENTINELX_PG` set, the backend replays
every persisted event through the same pipeline (`Engine.Rewarm`) to rebuild the
in-memory graph and re-materialize investigations. Persistence sits behind the
existing `EventStore` / `InvestigationStore` interfaces (`store.PGEventStore`,
`store.PGInvestigationStore`); the in-memory stores remain the default.

- Events: `INSERT ... ON CONFLICT DO NOTHING` (idempotent, so replay is safe).
- Investigations: upsert of the serializable projection (summary + score_factors
  JSON + technique/detection/event id arrays). The live node graph is **not**
  stored — it is deterministically rebuilt by rewarm.
- Migrations run under a `pg_advisory_xact_lock` so concurrent starts don't race
  on the `pg_type` catalog (`CREATE TABLE IF NOT EXISTS` is not race-safe).

## Consequences
- Durable across restarts, proven by `TestPGDurabilityRewarm` and an HTTP
  restart demo (ingest → kill → restart → rewarm restores the investigation).
- The event log is the audit-friendly ground truth; investigations can always be
  recomputed from it, which also means a rule change can be back-tested by replay.
- Cost: rewarm is O(events) at startup. Fine at v1 scale; the scale-out path
  snapshots graph/investigation state and replays only the tail.
- Limitation: a Postgres-loaded investigation served *before* rewarm completes
  would have an empty graph view; we rewarm fully before serving.

## Rejected
- Persisting the live pointer graph (cyclic `Node<->Edge`) directly: awkward to
  serialize and redundant with the replayable event log.
- Write-through of every graph mutation: high write amplification for no gain
  over event replay at this scale.
