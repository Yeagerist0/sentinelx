package correlate

import (
	"fmt"
	"time"
)

// Graph is a per-host provenance graph. v1 keeps the working set in memory and
// (in the full backend) evicts cold nodes to Postgres via a GraphStore
// interface; this package holds only the in-memory core.
type Graph struct {
	HostID    string
	nodes     map[string]*Node
	baseline  *Baseline
	hubDegree int
	nextEdge  int64
}

// NewGraph builds an empty per-host graph. hubDegree is the in- or out-degree
// above which a node becomes a hub (traversal boundary).
func NewGraph(hostID string, b *Baseline, hubDegree int) *Graph {
	return &Graph{HostID: hostID, nodes: map[string]*Node{}, baseline: b, hubDegree: hubDegree}
}

// Node returns the node with id, or nil.
func (g *Graph) Node(id string) *Node { return g.nodes[id] }

// Len returns the node count (used in tests/metrics).
func (g *Graph) Len() int { return len(g.nodes) }

func (g *Graph) getOrCreate(id string, kind NodeKind, label string) *Node {
	if n, ok := g.nodes[id]; ok {
		if n.Label == "" && label != "" {
			n.Label = label
		}
		return n
	}
	n := &Node{ID: id, HostID: g.HostID, Kind: kind, Label: label}
	g.nodes[id] = n
	return n
}

func (g *Graph) addEdge(src, dst *Node, rel Rel, ts time.Time, eventID, key string) *Edge {
	w := g.baseline.Weight(key)
	g.baseline.Observe(key)
	e := &Edge{ID: g.nextEdge, Src: src, Dst: dst, Rel: rel, TS: ts, EventID: eventID, Weight: w}
	g.nextEdge++
	src.Out = append(src.Out, e)
	dst.In = append(dst.In, e)
	src.DegreeOut++
	dst.DegreeIn++
	// A hub is a shared-infrastructure node: a high-fanout process (systemd,
	// sshd) OR a high-fanin object (a binary executed by many processes). Either
	// terminates traversal so it can never bridge unrelated activity.
	if !src.IsHub && src.DegreeOut > g.hubDegree {
		src.IsHub = true
	}
	if !dst.IsHub && dst.DegreeIn > g.hubDegree {
		dst.IsHub = true
	}
	return e
}

func edgeKey(image string, rel Rel, kind NodeKind) string {
	return image + "|" + string(rel) + "|" + string(kind)
}

func fileID(host, path string) string { return "file:" + host + ":" + path }
func sockID(host, addr string, port int) string {
	return fmt.Sprintf("sock:%s:%s:%d", host, addr, port)
}
func dnsID(name string) string       { return "dns:" + name }
func moduleID(host, p string) string { return "mod:" + host + ":" + p }

// AddEvent folds one normalized event into the provenance graph, creating nodes
// and a typed, rarity-weighted edge. Ingest calls this for every event before
// detection runs, so the graph is warm when a seed arrives.
func (g *Graph) AddEvent(e Event) {
	switch e.Type {
	case ProcessStart:
		p := g.getOrCreate(e.ProcGUID, KindProcess, e.ProcImage)
		if e.ParentGUID != "" {
			par := g.getOrCreate(e.ParentGUID, KindProcess, "")
			g.addEdge(par, p, RelSpawned, e.TS, e.ID, edgeKey(e.ProcImage, RelSpawned, KindProcess))
		}
		if e.ProcImage != "" {
			f := g.getOrCreate(fileID(e.HostID, e.ProcImage), KindFile, e.ProcImage)
			g.addEdge(p, f, RelExecuted, e.TS, e.ID, edgeKey(e.ProcImage, RelExecuted, KindFile))
		}
	case FileWrite, FileRead:
		p := g.getOrCreate(e.ProcGUID, KindProcess, e.ProcImage)
		f := g.getOrCreate(fileID(e.HostID, e.FilePath), KindFile, e.FilePath)
		rel := RelWrote
		if e.Type == FileRead {
			rel = RelRead
		}
		g.addEdge(p, f, rel, e.TS, e.ID, edgeKey(e.ProcImage, rel, KindFile))
	case NetConnect:
		p := g.getOrCreate(e.ProcGUID, KindProcess, e.ProcImage)
		s := g.getOrCreate(sockID(e.HostID, e.RemoteAddr, e.RemotePort), KindSocket,
			fmt.Sprintf("%s:%d", e.RemoteAddr, e.RemotePort))
		g.addEdge(p, s, RelConnected, e.TS, e.ID, edgeKey(e.ProcImage, RelConnected, KindSocket))
	case DNSQuery:
		p := g.getOrCreate(e.ProcGUID, KindProcess, e.ProcImage)
		d := g.getOrCreate(dnsID(e.DNSName), KindDNS, e.DNSName)
		g.addEdge(p, d, RelResolved, e.TS, e.ID, edgeKey(e.ProcImage, RelResolved, KindDNS))
	case ModuleLoad:
		p := g.getOrCreate(e.ProcGUID, KindProcess, e.ProcImage)
		m := g.getOrCreate(moduleID(e.HostID, e.FilePath), KindModule, e.FilePath)
		g.addEdge(p, m, RelLoaded, e.TS, e.ID, edgeKey(e.ProcImage, RelLoaded, KindModule))
	case ProcessStop:
		// no edge; lifecycle only
	}
}
