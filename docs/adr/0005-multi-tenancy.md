# ADR-0005: Multi-tenant data isolation

Status: accepted · Date: 2026-07-20

## Context

SentinelX v1 was architected for one customer: a single shared bearer token
gated the API, and per-host state (provenance graphs, correlators, the rarity
baseline, the audit log) was keyed only by hostname. That's fine for one
self-hosted deployment. It breaks the moment there is a second customer:
nothing in the data model, the correlation engine, or the store layer
distinguished "whose" data anything was. Two customers each monitoring a host
named `web-01` — an extremely common name — would have their provenance
graphs, correlators, and even investigation ids collide in the same process,
and the store had no column to separate them even if the in-memory state
somehow didn't collide.

This is the dangerous mistake to get wrong early: retrofitting isolation after
real customer data has already commingled is far worse than building it in
before there's a second tenant. So this is scoped deliberately narrow —
**data isolation only**, not the full SaaS product.

## Decision

Every `Event`, `Detection`, and `Investigation` carries a `TenantID`, set by
the backend from the authenticated caller at ingest time — **never** trusted
from agent-supplied data, so a compromised or misconfigured agent cannot claim
to belong to a different tenant.

**Isolation boundaries, each independently enforced:**

- **Correlation state**: `pipeline.Engine` keys its per-host graphs and
  correlators by `tenantHostKey(tenantID, host)`, not host alone. Two tenants
  with identically named hosts get entirely separate provenance graphs.
- **Rarity baseline**: kept per-tenant, not global. Sharing rarity learning
  across tenants would mean one tenant's activity volume dulls or sharpens
  another tenant's detection sensitivity — a real behavioral leak even though
  no event content crosses the boundary.
- **Audit log**: one hash-chained `audit.Log` per tenant, not one global
  chain. Each tenant gets an independently verifiable evidence trail; a
  tenant's entry count is not observable by any other tenant.
- **Stats**: per-tenant counters, not one global struct — a tenant cannot
  infer another tenant's event/detection volume from `/v1/stats`.
- **Store queries**: `InvestigationStore` gained `GetForTenant`/`ListByTenant`
  alongside the existing unscoped `Get`/`List` (kept only for internal engine
  use — Rewarm's status-snapshot spans every tenant by design). The Postgres
  implementation filters in SQL (`WHERE tenant_id = $1`), not
  fetch-then-check, so a guessed id never leaves the database. The API layer
  uses the tenant-scoped methods exclusively.
- **Auth**: `backend/tenant.Store` resolves a bearer token to a `Tenant{ID,
  Name}`. One token per tenant. A request with an unrecognized token gets
  401; a request for another tenant's investigation id gets 404 — never a
  403, so the API never confirms whether the id exists at all.
- **Investigation ids**: stayed a single global counter across all tenants
  (not per-tenant). This is a deliberate simplification: ids are never
  enumerable cross-tenant via the API (every lookup is tenant-scoped), so a
  shared id space leaks nothing and avoids extra bookkeeping.

**Config**: `SENTINELX_TENANTS="id:name:token,id:name:token,..."` env var.
Unset falls back to a single `default` tenant using the legacy
`SENTINELX_TOKEN`, so existing single-tenant deployments and the demo are
unaffected.

## What this is NOT

- **Not self-serve signup.** Tenants are configured by whoever runs the
  backend, not created by an onboarding flow.
- **Not multi-user-per-tenant RBAC.** One token per tenant means every
  analyst at a customer org shares one credential today — same limitation the
  single-tenant version had, just now scoped per-org instead of globally.
- **Not SSO/OIDC.** Still a bearer token, not an identity provider
  integration.
- **Not compute isolation.** All tenants share one `pipeline.Engine` process
  and one Postgres instance. A noisy-neighbor tenant can still affect another
  tenant's latency (no per-tenant rate limiting or resource quotas yet). Real
  compute isolation at scale is a distributed-correlation problem, a separate
  and larger undertaking.
- **Not per-tenant custom detection rules.** The rule set (`detect.Engine`)
  is shared across every tenant in v1.

These are legitimate, lower-risk features for later — lower-risk because
getting them wrong costs a feature gap, not a customer's data appearing in
another customer's dashboard.

## Consequences

- A tenant can never read, list, or modify another tenant's investigations —
  proven by tests at every layer: `TestCrossTenantIsolation` (pipeline,
  in-memory), `TestPGCrossTenantIsolation` (Postgres, SQL-level), and
  `TestAPI_CrossTenantIsolation` (full HTTP round trip) — plus a live,
  browser-verified check with two tenants monitoring identically named hosts.
- Fixed a real latent bug found while building this: `PGInvestigationStore
  .Upsert`/`PGEventStore.Put` silently discarded every SQL error. A failed
  write would previously vanish with zero visibility. Both now log failures.
- Cost: every store call site had to be re-audited to use the tenant-scoped
  method. The unscoped `Get`/`List` methods remain on the interface for the
  two legitimate internal cases (Rewarm, and SetStatus's live-correlator
  lookup, which independently re-verifies tenant ownership before touching
  anything) — any new caller reaching for `Get`/`List` directly should be
  treated as a code-review red flag.

## Rejected

- **Tenant ID embedded in the API token itself** (e.g. a signed JWT) instead
  of a lookup table: adds a dependency (JWT library, key management) for no
  real benefit at this scale — a lookup table is simpler to reason about and
  to revoke.
- **Per-tenant investigation id sequences**: would need a global id→tenant
  index anyway to make ids collision-free across tenants during Rewarm/merge
  paths, at which point the global counter is simpler and strictly
  equivalent from a leakage standpoint.
- **Row-level security (Postgres RLS)** instead of explicit `WHERE tenant_id
  = $1` filtering: RLS is a real option for scale-out but adds session-
  variable plumbing (`SET app.tenant_id`) that has to be threaded through
  pgx's connection pooling correctly or it silently fails open. Explicit
  filtering is more code but the failure mode of a missing `WHERE` clause is
  a compile-time-visible, code-reviewable diff, not a runtime session-state
  bug.
