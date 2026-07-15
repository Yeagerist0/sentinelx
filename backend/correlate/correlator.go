package correlate

import (
	"container/heap"
	"slices"
	"time"
)

// Params tunes the correlation engine. Defaults come from DefaultParams.
type Params struct {
	Window       time.Duration // include edges within +/- Window of the seed
	CostBudget   float64       // total path cost (sum of 1-weight) before a branch stops
	MaxNodes     int           // hard subgraph cap — over-merge guard of last resort
	HubDegree    int           // out-degree above which a node is a hub boundary
	CommonWeight float64       // edges below this weight are common → boundary
	IdleClose    time.Duration // investigation closes after this much inactivity
}

// DefaultParams are tuned for the v1 50-endpoint / 1k EPS target.
func DefaultParams() Params {
	return Params{
		Window:       10 * time.Minute,
		CostBudget:   6.0,
		MaxNodes:     400,
		HubDegree:    50,
		CommonWeight: 0.2,
		IdleClose:    30 * time.Minute,
	}
}

// Correlator groups detections into investigations over a single host's graph.
// It is not safe for concurrent use; the backend runs one per host shard.
//
// Investigation IDs come from the injected idGen, NOT a local counter: a
// per-Correlator counter would hand out the same id (1, 2, 3...) on every
// host, and a store keyed only by that numeric id would silently overwrite
// one host's investigation with another's. idGen must be shared across every
// Correlator in a deployment (pipeline.Engine owns one and injects it into
// each per-host Correlator it creates).
type Correlator struct {
	graph  *Graph
	params Params
	scorer *Scorer
	idGen  func() int64

	invs   map[int64]*Investigation
	member map[string]int64 // nodeID -> invID (boundary nodes are never members)
	dets   map[int64]Detection
}

// NewCorrelator builds a correlator over graph g. idGen must return a globally
// unique id on each call — see the Correlator doc comment for why a local
// per-host counter is unsafe.
func NewCorrelator(g *Graph, p Params, s *Scorer, idGen func() int64) *Correlator {
	return &Correlator{
		graph:  g,
		params: p,
		scorer: s,
		idGen:  idGen,
		invs:   map[int64]*Investigation{},
		member: map[string]int64{},
		dets:   map[int64]Detection{},
	}
}

// Investigations returns the current open+closed investigations.
func (c *Correlator) Investigations() map[int64]*Investigation { return c.invs }

// Observe attaches a non-seed event to an existing investigation when its acting
// process is already a member, so investigations grow as related activity
// arrives (e.g. a C2 beacon after the exec that tripped the rule), not only when
// a new rule fires. Returns the investigation id, or 0 if the process is not
// under investigation.
func (c *Correlator) Observe(procGUID, eventID string, ts time.Time) int64 {
	id, ok := c.member[procGUID]
	if !ok {
		return 0
	}
	inv := c.invs[id]
	inv.EventIDs[eventID] = true
	if ts.After(inv.LastSeen) {
		inv.LastSeen = ts
	}
	return id
}

// Seed grows or opens exactly one investigation from a detection. It returns the
// investigation id the detection landed in.
func (c *Correlator) Seed(d Detection) int64 {
	anchor := c.mustNode(d.ProcGUID, d.HostID, d.RuleID)
	sub := c.expand(anchor, d.TS)

	// Eligibility: existing investigations touched by non-boundary nodes, plus a
	// force-merge on the anchor's lineage root (survives the time window).
	elig := map[int64]bool{}
	for id := range sub.nodes {
		if iv, ok := c.member[id]; ok {
			elig[iv] = true
		}
	}
	root := c.lineageRoot(anchor)
	if iv, ok := c.member[root.ID]; ok {
		elig[iv] = true
	}

	var target *Investigation
	if len(elig) == 0 {
		target = c.openInvestigation(d, root)
	} else {
		target = c.mergeEligible(elig)
	}
	c.attach(target, d, sub)
	c.rescore(target)
	return target.ID
}

type expandResult struct {
	nodes    map[string]*Node // expandable, mergeable
	boundary map[string]*Node // hubs and common-edge terminals (not mergeable)
}

// expand performs a weighted best-first walk of the causal neighborhood of
// anchor, bounded by time window, cost budget, node cap, hub termination, and
// the rarity boundary. Boundary nodes are settled but never expanded through and
// never contribute investigation membership.
func (c *Correlator) expand(anchor *Node, anchorTS time.Time) expandResult {
	res := expandResult{nodes: map[string]*Node{}, boundary: map[string]*Node{}}
	visited := map[string]bool{}
	pq := &minPQ{}
	heap.Init(pq)
	heap.Push(pq, pqItem{node: anchor, cost: 0, bridge: 1.0})

	for pq.Len() > 0 {
		it := heap.Pop(pq).(pqItem)
		if visited[it.node.ID] {
			continue
		}
		visited[it.node.ID] = true

		isBoundary := (it.node.IsHub && it.node != anchor) || it.bridge < c.params.CommonWeight
		if isBoundary {
			res.boundary[it.node.ID] = it.node
			continue // settle only — do not expand through it
		}
		res.nodes[it.node.ID] = it.node
		if len(res.nodes) >= c.params.MaxNodes {
			continue // cap reached: stop growing this investigation
		}

		for _, e := range incident(it.node) {
			other := e.Dst
			if e.Dst == it.node {
				other = e.Src
			}
			if visited[other.ID] {
				continue
			}
			if !within(e.TS, anchorTS, c.params.Window) {
				continue
			}
			nc := it.cost + (1.0 - e.Weight)
			if nc > c.params.CostBudget {
				continue
			}
			heap.Push(pq, pqItem{node: other, cost: nc, bridge: e.Weight})
		}
	}
	return res
}

// lineageRoot walks up spawned-edges to the top non-hub ancestor. It stops at a
// hub (e.g. sshd/systemd) so lineage never bridges through shared infrastructure.
func (c *Correlator) lineageRoot(n *Node) *Node {
	cur := n
	for {
		var parent *Node
		for _, e := range cur.In {
			if e.Rel == RelSpawned {
				parent = e.Src
				break
			}
		}
		if parent == nil || parent.IsHub {
			return cur
		}
		cur = parent
	}
}

func (c *Correlator) openInvestigation(d Detection, root *Node) *Investigation {
	inv := &Investigation{
		ID:        c.idGen(),
		HostID:    d.HostID,
		RootGUID:  root.ID,
		Status:    "open",
		FirstSeen: d.TS,
		LastSeen:  d.TS,
		EventIDs:  map[string]bool{},
		Nodes:     map[string]*Node{},
	}
	c.invs[inv.ID] = inv
	return inv
}

func (c *Correlator) mergeEligible(elig map[int64]bool) *Investigation {
	ids := make([]int64, 0, len(elig))
	for id := range elig {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	target := c.invs[ids[0]]
	for _, id := range ids[1:] {
		other := c.invs[id]
		for nid, n := range other.Nodes {
			target.Nodes[nid] = n
			c.member[nid] = target.ID
		}
		for eid := range other.EventIDs {
			target.EventIDs[eid] = true
		}
		target.Detections = append(target.Detections, other.Detections...)
		target.TechniqueSet = unionStr(target.TechniqueSet, other.TechniqueSet)
		if other.FirstSeen.Before(target.FirstSeen) {
			target.FirstSeen = other.FirstSeen
		}
		if other.LastSeen.After(target.LastSeen) {
			target.LastSeen = other.LastSeen
		}
		delete(c.invs, id)
	}
	return target
}

func (c *Correlator) attach(target *Investigation, d Detection, sub expandResult) {
	for nid, n := range sub.nodes {
		target.Nodes[nid] = n
		c.member[nid] = target.ID
		// Pull every event on this node's incident edges into the investigation so
		// the timeline is complete, not just the events that tripped a rule.
		for _, e := range incident(n) {
			target.EventIDs[e.EventID] = true
		}
	}
	for _, eid := range d.EventIDs {
		target.EventIDs[eid] = true
	}
	target.Detections = append(target.Detections, d.ID)
	c.dets[d.ID] = d
	target.TechniqueSet = unionStr(target.TechniqueSet, d.Technique)
	if d.TS.Before(target.FirstSeen) {
		target.FirstSeen = d.TS
	}
	if d.TS.After(target.LastSeen) {
		target.LastSeen = d.TS
	}
}

func (c *Correlator) rescore(target *Investigation) {
	dets := make([]Detection, 0, len(target.Detections))
	for _, id := range target.Detections {
		dets = append(dets, c.dets[id])
	}
	target.RiskScore, target.ScoreFactors = c.scorer.Score(target, dets)
}

func (c *Correlator) mustNode(guid, host, label string) *Node {
	if n := c.graph.Node(guid); n != nil {
		return n
	}
	n := c.graph.getOrCreate(guid, KindProcess, label)
	n.HostID = host
	return n
}

func incident(n *Node) []*Edge {
	out := make([]*Edge, 0, len(n.Out)+len(n.In))
	out = append(out, n.Out...)
	out = append(out, n.In...)
	return out
}

func within(a, b time.Time, w time.Duration) bool {
	d := a.Sub(b)
	if d < 0 {
		d = -d
	}
	return d <= w
}

func unionStr(a, b []string) []string {
	seen := map[string]bool{}
	for _, s := range a {
		seen[s] = true
	}
	out := append([]string{}, a...)
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}
