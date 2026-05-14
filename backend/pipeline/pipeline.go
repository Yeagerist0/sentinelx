// Package pipeline is the v1 vertical slice: agent event -> normalize -> graph +
// detect -> correlate -> stores + audit. It runs in-process (no bus) at the
// 50-endpoint scale; the Bus seam is where NATS slots in for scale-out.
package pipeline

import (
	"fmt"
	"sync"

	"sentinelx/backend/audit"
	"sentinelx/backend/correlate"
	"sentinelx/backend/detect"
	"sentinelx/backend/normalize"
	"sentinelx/backend/store"
)

// Stats are the operational counters exposed for health/metrics.
type Stats struct {
	Events         int64
	Detections     int64
	Investigations int64
	Dropped        int64 // unknown-kind / normalize failures (schema drift signal)
	SeqGaps        int64 // per-host sequence discontinuities (event-loss signal)
}

// Engine owns per-host graphs and correlators and the shared baseline/ruleset.
type Engine struct {
	mu       sync.Mutex
	baseline *correlate.Baseline
	params   correlate.Params
	scorer   *correlate.Scorer
	rules    *detect.Engine
	graphs   map[string]*correlate.Graph
	cors     map[string]*correlate.Correlator

	Events store.EventStore
	Invs   store.InvestigationStore
	Audit  *audit.Log
	stats  Stats
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
		baseline: correlate.NewBaseline(),
		params:   correlate.DefaultParams(),
		scorer:   scorer,
		rules:    rules,
		graphs:   map[string]*correlate.Graph{},
		cors:     map[string]*correlate.Correlator{},
		Events:   events,
		Invs:     invs,
		Audit:    audit.New(),
	}
}

func (e *Engine) hostState(host string) (*correlate.Graph, *correlate.Correlator) {
	g, ok := e.graphs[host]
	if !ok {
		g = correlate.NewGraph(host, e.baseline, e.params.HubDegree)
		e.graphs[host] = g
		e.cors[host] = correlate.NewCorrelator(g, e.params, e.scorer)
	}
	return g, e.cors[host]
}

// Ingest normalizes one agent event and processes it end to end, returning the
// investigation ids it touched. Safe for concurrent callers.
func (e *Engine) Ingest(a normalize.AgentEvent) ([]int64, error) {
	ev, err := normalize.Normalize(a)
	if err != nil {
		e.mu.Lock()
		e.stats.Dropped++
		e.mu.Unlock()
		return nil, err
	}
	return e.Process(ev), nil
}

// Rewarm replays already-normalized events (e.g. loaded from Postgres on
// startup) to rebuild the in-memory provenance graph and re-materialize
// investigations after a restart. Persistence is idempotent, so replaying is safe.
func (e *Engine) Rewarm(evs []correlate.Event) {
	for _, ev := range evs {
		e.Process(ev)
	}
}

// Process runs the post-normalize path: persist, graph, detect, correlate.
func (e *Engine) Process(ev correlate.Event) []int64 {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.Events.Put(ev)
	e.stats.Events++
	e.Audit.Appendf("event", ev.ID, "%s|%s|%s", ev.HostID, ev.Type, ev.ProcGUID)

	g, cor := e.hostState(ev.HostID)
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
		e.stats.Detections++
		e.Audit.Appendf("detection", d.RuleID, "%s|%s|%v", d.HostID, d.ProcGUID, d.Technique)
		invID := cor.Seed(d)
		inv, ok := cor.Investigations()[invID]
		if !ok {
			continue // unreachable: Seed always returns a live investigation
		}
		e.Invs.Upsert(inv)
		e.Audit.Appendf("investigation", fmt.Sprintf("%d", inv.ID), "risk=%d dets=%d", inv.RiskScore, len(inv.Detections))
		touched = append(touched, invID)
	}
	e.stats.Investigations = int64(len(cor.Investigations()))
	return touched
}

// Stats returns a snapshot of the counters.
func (e *Engine) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stats
}
