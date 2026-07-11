package api

import (
	"sort"
	"time"

	"sentinelx/backend/correlate"
	"sentinelx/backend/store"
)

// The internal Investigation embeds the live provenance graph, whose Node<->Edge
// pointers are cyclic and cannot be JSON-encoded. These DTOs are the flat,
// serializable view the API returns, and they also join event ids into a
// timeline the UI can render directly.

type invSummary struct {
	ID         int64     `json:"id"`
	Host       string    `json:"host"`
	Root       string    `json:"root_guid"`
	Status     string    `json:"status"`
	Risk       int       `json:"risk_score"`
	Techniques []string  `json:"techniques"`
	Detections int       `json:"detection_count"`
	Events     int       `json:"event_count"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

type nodeDTO struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
	IsHub bool   `json:"is_hub"`
}

type edgeDTO struct {
	Src     string    `json:"src"`
	Dst     string    `json:"dst"`
	Rel     string    `json:"rel"`
	TS      time.Time `json:"ts"`
	EventID string    `json:"event_id"`
	Weight  float64   `json:"weight"`
}

type eventDTO struct {
	ID      string    `json:"id"`
	TS      time.Time `json:"ts"`
	Type    string    `json:"type"`
	Image   string    `json:"image"`
	Cmdline string    `json:"cmdline,omitempty"`
	Detail  string    `json:"detail,omitempty"`
}

// detectionDTO is the "what fired, and how do I fix it" drill-down for one
// detection: the rule that matched, the MITRE technique(s), the exact events
// that triggered it, and analyst-facing remediation guidance from the rule.
type detectionDTO struct {
	ID          int64     `json:"id"`
	RuleID      string    `json:"rule_id"`
	Technique   []string  `json:"technique"`
	Severity    int       `json:"severity"`
	TS          time.Time `json:"ts"`
	EventIDs    []string  `json:"event_ids"`
	Remediation string    `json:"remediation"`
}

type invDetail struct {
	invSummary
	ScoreFactors     []correlate.ScoreFactor `json:"score_factors"`
	DetectionIDs     []int64                 `json:"detection_ids"`
	DetectionsDetail []detectionDTO          `json:"detections"`
	Nodes            []nodeDTO               `json:"nodes"`
	Edges            []edgeDTO               `json:"edges"`
	Timeline         []eventDTO              `json:"timeline"`
}

func summarize(inv *correlate.Investigation) invSummary {
	return invSummary{
		ID: inv.ID, Host: inv.HostID, Root: inv.RootGUID, Status: inv.Status,
		Risk: inv.RiskScore, Techniques: inv.TechniqueSet,
		Detections: len(inv.Detections), Events: len(inv.EventIDs),
		FirstSeen: inv.FirstSeen, LastSeen: inv.LastSeen,
	}
}

func detail(inv *correlate.Investigation, events store.EventStore, dets []correlate.Detection) invDetail {
	d := invDetail{invSummary: summarize(inv), ScoreFactors: inv.ScoreFactors, DetectionIDs: inv.Detections}
	for _, det := range dets {
		d.DetectionsDetail = append(d.DetectionsDetail, detectionDTO{
			ID: det.ID, RuleID: det.RuleID, Technique: det.Technique, Severity: det.Severity,
			TS: det.TS, EventIDs: det.EventIDs, Remediation: det.Remediation,
		})
	}
	sort.Slice(d.DetectionsDetail, func(i, j int) bool { return d.DetectionsDetail[i].TS.Before(d.DetectionsDetail[j].TS) })

	// Nodes + edges (dedup edges by id; include boundary endpoints referenced by
	// an edge so the graph is not dangling).
	nodeSet := map[string]*correlate.Node{}
	seenEdge := map[int64]bool{}
	for _, n := range inv.Nodes {
		nodeSet[n.ID] = n
	}
	for _, n := range inv.Nodes {
		for _, e := range append(append([]*correlate.Edge{}, n.Out...), n.In...) {
			if seenEdge[e.ID] {
				continue
			}
			seenEdge[e.ID] = true
			nodeSet[e.Src.ID] = e.Src
			nodeSet[e.Dst.ID] = e.Dst
			d.Edges = append(d.Edges, edgeDTO{
				Src: e.Src.ID, Dst: e.Dst.ID, Rel: string(e.Rel),
				TS: e.TS, EventID: e.EventID, Weight: e.Weight,
			})
		}
	}
	for _, n := range nodeSet {
		d.Nodes = append(d.Nodes, nodeDTO{ID: n.ID, Kind: string(n.Kind), Label: n.Label, IsHub: n.IsHub})
	}
	sort.Slice(d.Nodes, func(i, j int) bool { return d.Nodes[i].ID < d.Nodes[j].ID })
	sort.Slice(d.Edges, func(i, j int) bool { return d.Edges[i].TS.Before(d.Edges[j].TS) })

	// Timeline from the joined events, ordered by time.
	for id := range inv.EventIDs {
		if ev, ok := events.Get(id); ok {
			d.Timeline = append(d.Timeline, eventDTO{
				ID: ev.ID, TS: ev.TS, Type: string(ev.Type),
				Image: ev.ProcImage, Cmdline: ev.Cmdline, Detail: objectDetail(ev),
			})
		}
	}
	sort.Slice(d.Timeline, func(i, j int) bool { return d.Timeline[i].TS.Before(d.Timeline[j].TS) })
	return d
}

func objectDetail(ev correlate.Event) string {
	switch ev.Type {
	case correlate.FileWrite, correlate.FileRead, correlate.ModuleLoad:
		return ev.FilePath
	case correlate.NetConnect:
		return ev.RemoteAddr
	case correlate.DNSQuery:
		return ev.DNSName
	}
	return ""
}
