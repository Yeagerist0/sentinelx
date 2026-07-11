package correlate

import "time"

// EventType enumerates the v1 normalized event types. On Linux these map to
// eBPF hooks: process_start=sched_process_exec, process_stop=sched_process_exit,
// file_write/read=LSM file_open|VFS, net_connect=tcp_connect/cgroup connect4,
// dns_query=UDP :53 heuristic, module_load=init_module. [VERIFY hook names]
type EventType string

const (
	ProcessStart EventType = "process_start"
	ProcessStop  EventType = "process_stop"
	FileWrite    EventType = "file_write"
	FileRead     EventType = "file_read"
	NetConnect   EventType = "net_connect"
	DNSQuery     EventType = "dns_query"
	ModuleLoad   EventType = "module_load"
)

// Event is a normalized telemetry record. ProcGUID is a stable process key.
// On Linux it is synthesized as hash(boot_id, pid, start_time_ticks) because
// Linux has no Sysmon-style ProcessGuid; on Windows it is Sysmon ProcessGuid.
type Event struct {
	ID         string
	HostID     string
	TS         time.Time
	Type       EventType
	ProcGUID   string
	ParentGUID string
	ProcImage  string
	Cmdline    string
	// object fields — only the relevant ones are set per Type
	FilePath   string
	RemoteAddr string
	RemotePort int
	DNSName    string
	Raw        map[string]any
}

// NodeKind is the type of a provenance-graph node.
type NodeKind string

const (
	KindProcess NodeKind = "process"
	KindFile    NodeKind = "file"
	KindSocket  NodeKind = "socket"
	KindDNS     NodeKind = "dns"
	KindModule  NodeKind = "module"
)

// Rel is the type of a provenance edge.
type Rel string

const (
	RelSpawned   Rel = "spawned"
	RelWrote     Rel = "wrote"
	RelRead      Rel = "read"
	RelExecuted  Rel = "executed"
	RelConnected Rel = "connected"
	RelResolved  Rel = "resolved"
	RelLoaded    Rel = "loaded"
)

// Node is a provenance-graph node. Out/In hold incident edges. DegreeOut and
// IsHub drive hub-based explosion mitigation.
type Node struct {
	ID        string
	HostID    string
	Kind      NodeKind
	Label     string
	DegreeOut int
	DegreeIn  int
	IsHub     bool
	Out       []*Edge
	In        []*Edge
}

// Edge is a timestamped provenance edge carrying the event that produced it and
// a rarity Weight in [0.05, 1.0] (higher = rarer/more anomalous).
type Edge struct {
	ID      int64
	Src     *Node
	Dst     *Node
	Rel     Rel
	TS      time.Time
	EventID string
	Weight  float64
}

// Detection is a rule hit. It seeds correlation: the anchor is ProcGUID and the
// exact triggering events are EventIDs.
type Detection struct {
	ID        int64
	RuleID    string
	RuleVer   string
	HostID    string
	ProcGUID  string
	EventIDs  []string
	Technique []string // MITRE ATT&CK ids
	Severity  int      // rule base severity 1..100
	TS        time.Time
	DedupKey  string
}

// ScoreFactor is one auditable contribution to an investigation's risk score.
// Every factor traces back to concrete event ids (Events) — the score IS its
// breakdown, not an opaque weight.
type ScoreFactor struct {
	Factor  string
	Base    int
	Mult    float64
	Contrib int
	Events  []string
	Note    string
}

// Investigation is a correlated group of detections/events over one host's
// provenance subgraph.
type Investigation struct {
	ID           int64
	HostID       string
	RootGUID     string
	Status       string // "open" | "closed"
	FirstSeen    time.Time
	LastSeen     time.Time
	RiskScore    int
	ScoreFactors []ScoreFactor
	TechniqueSet []string
	Detections   []int64
	EventIDs     map[string]bool
	Nodes        map[string]*Node
}
