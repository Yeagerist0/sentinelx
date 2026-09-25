// Package pipeline is the v1 vertical slice: agent event -> normalize -> graph +
// detect -> correlate -> stores + audit. It runs in-process (no bus) at the
// 50-endpoint scale; the Bus seam is where NATS slots in for scale-out.
//
// Multi-tenancy: every operation is scoped by a tenantID supplied by the
// caller (the API layer resolves it from the authenticated request — it is
// never trusted from agent-supplied data). Per-host provenance graphs,
// correlators, rarity baselines, operational stats, and the tamper-evident
// audit log are all keyed by tenant so two tenants monitoring identically
// named hosts (e.g. both have a "web-01") never collide or leak into each
// other. See docs/adr/0005-multi-tenancy.md for the design and its honest
// boundaries (this is data isolation, not the full SaaS story — no per-tenant
// compute quotas or billing yet).
package pipeline

import (
	"errors"
	"fmt"
	"sync"

	"sentinelx/backend/audit"
	"sentinelx/backend/correlate"
	"sentinelx/backend/detect"
	"sentinelx/backend/normalize"
	"sentinelx/backend/store"
)

// DefaultTenant is the tenant id used by single-tenant deployments and
// offline tooling (replay, bench, demo.sh) that has no real multi-tenant
// auth to resolve a tenant from.
const DefaultTenant = "default"

// Stats are the operational counters exposed for health/metrics, one set per
// tenant so a tenant never observes another tenant's volume.
type Stats struct {
	Events         int64
	Detections     int64
	Investigations int64
	Dropped        int64 // unknown-kind / normalize failures (schema drift signal)
	SeqGaps        int64 // per-host sequence discontinuities (event-loss signal)
}

// Engine owns per-(tenant,host) graphs and correlators and the shared
// baseline/ruleset. rules is intentionally NOT per-tenant: the deterministic
// rule set is the same for every tenant in v1 (per-tenant custom rules is a
// post-v1 feature, see the ADR).
type Engine struct {
	mu        sync.Mutex
	baselines map[string]*correlate.Baseline // keyed by tenantID
	params    correlate.Params
	scorer    *correlate.Scorer
	rules     *detect.Engine
	graphs    map[string]*correlate.Graph      // keyed by tenantHostKey(tenant, host)
	cors      map[string]*correlate.Correlator // keyed by tenantHostKey(tenant, host)
	dets      map[int64]correlate.Detection    // detection ids are globally unique (one *detect.Engine); filtered by tenant on read
	patSeen   map[string]bool                  // graph-pattern dedup: tenant|host|ruleID|procGUID already fired
	nextInvID int64                            // globally unique investigation ids; fine since ids are never enumerable cross-tenant via the API
	stats     map[string]*Stats                // keyed by tenantID
	audits    map[string]*audit.Log            // keyed by tenantID — each tenant gets its own independently-verifiable hash chain

	Events store.EventStore
	Invs   store.InvestigationStore
}

// New builds an engine with in-memory stores.
func New(rules *detect.Engine, scorer *correlate.Scorer) *Engine {
	return NewWithStores(rules, scorer, store.NewMemEventStore(), store.NewMemInvestigationStore())
}

// NewWithStores builds an engine with caller-supplied stores (e.g. Postgres for
// durability). The provenance graph working set stays in memory (ADR-0001);
// durability comes from replaying persisted events via Rewarm on startup.
func NewWithStores(rules *detect.Engine, scorer *correlate.Scorer, events store.EventStore, invs store.InvestigationStore) *Engine {
	return &Engine{
		baselines: map[string]*correlate.Baseline{},
		params:    correlate.DefaultParams(),
		scorer:    scorer,
		rules:     rules,
		graphs:    map[string]*correlate.Graph{},
		cors:      map[string]*correlate.Correlator{},
		dets:      map[int64]correlate.Detection{},
		patSeen:   map[string]bool{},
		stats:     map[string]*Stats{},
		audits:    map[string]*audit.Log{},
		Events:    events,
		Invs:      invs,
	}
}

// tenantHostKey composites a tenant and host into one map key. A NUL separator
// is used so no tenant/host string combination can collide (tenant "a" + host
// "b\x00c" cannot be confused with tenant "a\x00b" + host "c").
func tenantHostKey(tenantID, host string) string {
	return tenantID + "\x00" + host
}

// hostState returns (creating if needed) the graph/correlator for one
// tenant's host, and that tenant's own rarity baseline. Baselines are
// per-tenant, not global: sharing rarity learning across tenants would mean
// one tenant's activity volume dulls or sharpens another tenant's detection
// sensitivity — a subtle but real cross-tenant leak of behavioral signal even
// though no event content crosses the boundary. Caller must hold e.mu.
func (e *Engine) hostState(tenantID, host string) (*correlate.Graph, *correlate.Correlator) {
	b, ok := e.baselines[tenantID]
	if !ok {
		b = correlate.NewBaseline()
		e.baselines[tenantID] = b
	}
	key := tenantHostKey(tenantID, host)
	g, ok := e.graphs[key]
	if !ok {
		g = correlate.NewGraph(host, b, e.params.HubDegree)
		e.graphs[key] = g
		// idGen is shared across every tenant+host's Correlator (all calls happen
		// under e.mu, held for the duration of Process) so investigation ids are
		// unique across the whole deployment.
		e.cors[key] = correlate.NewCorrelator(g, e.params, e.scorer, e.nextInvestigationID)
	}
	return g, e.cors[key]
}

func (e *Engine) nextInvestigationID() int64 {
	e.nextInvID++
	return e.nextInvID
}

// statsFor returns (creating if needed) a tenant's stats. Caller must hold e.mu.
func (e *Engine) statsFor(tenantID string) *Stats {
	s, ok := e.stats[tenantID]
	if !ok {
		s = &Stats{}
		e.stats[tenantID] = s
	}
	return s
}

// auditFor returns (creating if needed) a tenant's audit log. Caller must
// hold e.mu — use AuditLog from outside the engine's own locked methods.
func (e *Engine) auditFor(tenantID string) *audit.Log {
	a, ok := e.audits[tenantID]
	if !ok {
		a = audit.New()
		e.audits[tenantID] = a
	}
	return a
}

// AuditLog returns the given tenant's tamper-evident audit log. Safe to call
// without already holding the engine's lock (used by the API layer and tests).
func (e *Engine) AuditLog(tenantID string) *audit.Log {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.auditFor(tenantID)
}

// Ingest normalizes one agent event and processes it end to end, returning the
// investigation ids it touched. tenantID comes from the authenticated caller,
// never from the agent payload itself — an agent cannot claim to belong to a
// different tenant. Safe for concurrent callers.
func (e *Engine) Ingest(tenantID string, a normalize.AgentEvent) ([]int64, error) {
	ev, err := normalize.Normalize(a)
	if err != nil {
		e.mu.Lock()
		e.statsFor(tenantID).Dropped++
		e.mu.Unlock()
		return nil, err
	}
	ev.TenantID = tenantID
	return e.Process(ev), nil
}

// Rewarm replays already-normalized events (e.g. loaded from Postgres on
// startup) to rebuild the in-memory provenance graph and re-materialize
// investigations after a restart. Each event already carries the TenantID it
// was persisted with, so this single call correctly rebuilds state for every
// tenant at once. Persistence is idempotent, so replaying is safe.
//
// Correlation recomputes every investigation from scratch and always opens it
// as "open" — it has no way to know an analyst previously resolved or
// dismissed it. So any non-open status already sitting in the store (an
// analyst decision from before the restart) is snapshotted first and
// reapplied after replay, instead of being silently clobbered back to "open".
func (e *Engine) Rewarm(evs []correlate.Event) {
	type prevState struct{ tenant, status string }
	prevStatus := map[int64]prevState{}
	for _, inv := range e.Invs.List() {
		if inv.Status != "" && inv.Status != correlate.StatusOpen {
			prevStatus[inv.ID] = prevState{inv.TenantID, inv.Status}
		}
	}
	for _, ev := range evs {
		e.Process(ev)
	}
	for id, p := range prevStatus {
		_ = e.SetStatus(p.tenant, id, p.status) // best-effort: the investigation may no longer recur
	}
}

// Process runs the post-normalize path: persist, graph, detect, correlate.
// ev.TenantID must already be set (by Ingest for live traffic, or by
// persistence for Rewarm).
func (e *Engine) Process(ev correlate.Event) []int64 {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.Events.Put(ev)
	st := e.statsFor(ev.TenantID)
	st.Events++
	al := e.auditFor(ev.TenantID)
	al.Appendf("event", ev.ID, "%s|%s|%s", ev.HostID, ev.Type, ev.ProcGUID)

	g, cor := e.hostState(ev.TenantID, ev.HostID)
	g.AddEvent(ev)

	// Grow any existing investigation this process already belongs to, even when
	// the event trips no rule (post-detection C2 beacons, follow-on file writes).
	if id := cor.Observe(ev.ProcGUID, ev.ID, ev.TS); id != 0 {
		if inv, ok := cor.Investigations()[id]; ok {
			e.Invs.Upsert(inv)
		}
	}

	dets := e.rules.Eval(ev)
	touched := make([]int64, 0, len(dets))
	for _, d := range dets {
		st.Detections++
		e.dets[d.ID] = d
		al.Appendf("detection", d.RuleID, "%s|%s|%v", d.HostID, d.ProcGUID, d.Technique)
		invID := cor.Seed(d)
		inv, ok := cor.Investigations()[invID]
		if !ok {
			continue // unreachable: Seed always returns a live investigation
		}
		e.Invs.Upsert(inv)
		al.Appendf("investigation", fmt.Sprintf("%d", inv.ID), "risk=%d dets=%d", inv.RiskScore, len(inv.Detections))
		touched = append(touched, invID)
	}
	// Graph-pattern pass: cross-event shapes the single-event rule engine cannot
	// express (they need the provenance graph). Runs on the process this event
	// just touched, after its edge is in the graph, and fires once per process.
	if node := g.Node(ev.ProcGUID); node != nil {
		if hit, ok := correlate.DownloadExecBeacon(node); ok {
			key := tenantHostKey(ev.TenantID, ev.HostID) + "\x00" + hit.RuleID + "\x00" + hit.ProcGUID
			if !e.patSeen[key] {
				e.patSeen[key] = true
				d := e.rules.SynthDetection(hit, ev.TenantID, ev.HostID, ev.TS)
				st.Detections++
				e.dets[d.ID] = d
				al.Appendf("detection", d.RuleID, "%s|%s|%v", d.HostID, d.ProcGUID, d.Technique)
				invID := cor.Seed(d)
				if inv, ok := cor.Investigations()[invID]; ok {
					e.Invs.Upsert(inv)
					al.Appendf("investigation", fmt.Sprintf("%d", inv.ID), "risk=%d dets=%d", inv.RiskScore, len(inv.Detections))
					touched = append(touched, invID)
				}
			}
		}
	}

	// Tenant-scoped count: List() spans every tenant, ListByTenant does not.
	st.Investigations = int64(len(e.Invs.ListByTenant(ev.TenantID)))
	return touched
}

// Stats returns a snapshot of one tenant's counters.
func (e *Engine) Stats(tenantID string) Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s, ok := e.stats[tenantID]; ok {
		return *s
	}
	return Stats{}
}

var validStatuses = map[string]bool{
	correlate.StatusOpen:      true,
	correlate.StatusResolved:  true,
	correlate.StatusDismissed: true,
}

// ErrInvalidStatus and ErrInvestigationNotFound let callers (the HTTP layer)
// distinguish a 400 from a 404 without string-matching error text.
// ErrInvestigationNotFound is also returned when the investigation exists but
// belongs to a different tenant — the caller must never be able to tell the
// difference between "doesn't exist" and "exists but isn't yours".
var (
	ErrInvalidStatus         = errors.New("pipeline: invalid status")
	ErrInvestigationNotFound = errors.New("pipeline: investigation not found")
)

// SetStatus applies an analyst action — resolve, dismiss as false-positive, or
// reopen — to an investigation, logs it to that tenant's tamper-evident audit
// trail, and persists it. It updates the live correlator's copy first when the
// investigation is still in memory (the common case), so ongoing correlation
// growth can't silently overwrite the analyst's decision on its next Upsert;
// see Rewarm for how this survives a restart.
//
// Known limitation: a dismissed/resolved investigation that keeps absorbing
// new correlated activity does not automatically reopen. Analysts must reopen
// it manually if new evidence warrants it.
func (e *Engine) SetStatus(tenantID string, id int64, status string) error {
	if !validStatuses[status] {
		return fmt.Errorf("%w: %q", ErrInvalidStatus, status)
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	var inv *correlate.Investigation
	for _, cor := range e.cors {
		got, ok := cor.Investigations()[id]
		if !ok {
			continue
		}
		if got.TenantID != tenantID {
			continue // exists, but belongs to a different tenant: never touch or leak it
		}
		inv = got
		break
	}
	if inv == nil {
		got, ok := e.Invs.GetForTenant(tenantID, id)
		if !ok {
			return fmt.Errorf("%w: %d", ErrInvestigationNotFound, id)
		}
		inv = got
	}
	inv.Status = status
	e.Invs.Upsert(inv)
	e.auditFor(tenantID).Appendf("investigation_status", fmt.Sprintf("%d", id), "status=%s", status)
	return nil
}

// Detections returns the full detection detail (rule, technique, matched
// events, remediation) for the given ids, scoped to tenantID — any id
// belonging to a different tenant is silently dropped rather than returned.
// This map is rebuilt by re-running detection during Rewarm, so it survives a
// restart the same way investigations do.
func (e *Engine) Detections(tenantID string, ids []int64) []correlate.Detection {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]correlate.Detection, 0, len(ids))
	for _, id := range ids {
		if d, ok := e.dets[id]; ok && d.TenantID == tenantID {
			out = append(out, d)
		}
	}
	return out
}

// GraphFor returns the provenance graph for a tenant's host.
func (e *Engine) GraphFor(tenantID, host string) *correlate.Graph {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := tenantHostKey(tenantID, host)
	return e.graphs[key]
}

// Rules returns the engine's detection rules engine.
func (e *Engine) Rules() *detect.Engine { return e.rules }

// Scorer returns the engine's correlator scorer.
func (e *Engine) Scorer() *correlate.Scorer { return e.scorer }
