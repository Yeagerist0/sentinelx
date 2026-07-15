// Package pipeline is the v1 vertical slice: agent event -> normalize -> graph +
// detect -> correlate -> stores + audit. It runs in-process (no bus) at the
// 50-endpoint scale; the Bus seam is where NATS slots in for scale-out.
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
	mu        sync.Mutex
	baseline  *correlate.Baseline
	params    correlate.Params
	scorer    *correlate.Scorer
	rules     *detect.Engine
	graphs    map[string]*correlate.Graph
	cors      map[string]*correlate.Correlator
	dets      map[int64]correlate.Detection // full detection detail, for the "what fired + how to fix" drill-down
	nextInvID int64                         // shared across every per-host Correlator — see correlate.Correlator doc

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
		dets:     map[int64]correlate.Detection{},
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
		// idGen is shared across every host's Correlator (all calls happen under
		// e.mu, held for the duration of Process) so investigation ids are unique
		// fleet-wide, not just per host.
		e.cors[host] = correlate.NewCorrelator(g, e.params, e.scorer, e.nextInvestigationID)
	}
	return g, e.cors[host]
}

func (e *Engine) nextInvestigationID() int64 {
	e.nextInvID++
	return e.nextInvID
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
//
// Correlation recomputes every investigation from scratch and always opens it
// as "open" — it has no way to know an analyst previously resolved or
// dismissed it. So any non-open status already sitting in the store (an
// analyst decision from before the restart) is snapshotted first and
// reapplied after replay, instead of being silently clobbered back to "open".
func (e *Engine) Rewarm(evs []correlate.Event) {
	prevStatus := map[int64]string{}
	for _, inv := range e.Invs.List() {
		if inv.Status != "" && inv.Status != correlate.StatusOpen {
			prevStatus[inv.ID] = inv.Status
		}
	}
	for _, ev := range evs {
		e.Process(ev)
	}
	for id, status := range prevStatus {
		_ = e.SetStatus(id, status) // best-effort: the investigation may no longer recur
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
		e.dets[d.ID] = d
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
	// Global count, not this host's local correlator map: investigations live
	// across many per-host correlators, so summing only the last-touched one
	// would undercount every other host's fleet-wide.
	e.stats.Investigations = int64(len(e.Invs.List()))
	return touched
}

// Stats returns a snapshot of the counters.
func (e *Engine) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stats
}

var validStatuses = map[string]bool{
	correlate.StatusOpen:      true,
	correlate.StatusResolved:  true,
	correlate.StatusDismissed: true,
}

// ErrInvalidStatus and ErrInvestigationNotFound let callers (the HTTP layer)
// distinguish a 400 from a 404 without string-matching error text.
var (
	ErrInvalidStatus         = errors.New("pipeline: invalid status")
	ErrInvestigationNotFound = errors.New("pipeline: investigation not found")
)

// SetStatus applies an analyst action — resolve, dismiss as false-positive, or
// reopen — to an investigation, logs it to the tamper-evident audit trail, and
// persists it. It updates the live correlator's copy first when the
// investigation is still in memory (the common case), so ongoing correlation
// growth can't silently overwrite the analyst's decision on its next Upsert;
// see Rewarm for how this survives a restart.
//
// Known limitation: a dismissed/resolved investigation that keeps absorbing
// new correlated activity does not automatically reopen. Analysts must reopen
// it manually if new evidence warrants it.
func (e *Engine) SetStatus(id int64, status string) error {
	if !validStatuses[status] {
		return fmt.Errorf("%w: %q", ErrInvalidStatus, status)
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	var inv *correlate.Investigation
	for _, cor := range e.cors {
		if got, ok := cor.Investigations()[id]; ok {
			inv = got
			break
		}
	}
	if inv == nil {
		got, ok := e.Invs.Get(id)
		if !ok {
			return fmt.Errorf("%w: %d", ErrInvestigationNotFound, id)
		}
		inv = got
	}
	inv.Status = status
	e.Invs.Upsert(inv)
	e.Audit.Appendf("investigation_status", fmt.Sprintf("%d", id), "status=%s", status)
	return nil
}

// Detections returns the full detection detail (rule, technique, matched
// events, remediation) for the given ids. This map is rebuilt by re-running
// detection during Rewarm, so it survives a restart the same way investigations
// do; missing ids are skipped rather than erroring.
func (e *Engine) Detections(ids []int64) []correlate.Detection {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]correlate.Detection, 0, len(ids))
	for _, id := range ids {
		if d, ok := e.dets[id]; ok {
			out = append(out, d)
		}
	}
	return out
}
