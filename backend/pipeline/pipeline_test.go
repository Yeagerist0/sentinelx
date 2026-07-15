package pipeline

import (
	"testing"
	"time"

	"sentinelx/backend/correlate"
	"sentinelx/backend/detect"
	"sentinelx/backend/normalize"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	rules, err := detect.NewEngine(detect.Default())
	if err != nil {
		t.Fatal(err)
	}
	sc := correlate.NewScorer()
	sc.CtxMult["T1204.002"] = 1.15
	return New(rules, sc)
}

// exec fires an exec_from_tmp detection on a fresh host+process, seeding
// exactly one investigation on that host's correlator.
func exec(host string, pid int, ts int64) normalize.AgentEvent {
	return normalize.AgentEvent{
		ID: host + "-e1", HostID: host, BootID: "b", Kind: "exec",
		PID: pid, StartTicks: int64(pid), TSUnixNs: ts, Exe: "/tmp/payload",
	}
}

// TestCrossHostInvestigationIDsDoNotCollide is a regression test: each host's
// Correlator used to keep its own investigation-id counter starting at 1, so
// the FIRST investigation on every host got id=1 and the store (keyed only by
// that numeric id) silently overwrote one host's investigation with another's.
// With N hosts each producing one investigation, the store must end up with N
// distinct investigations, not 1.
func TestCrossHostInvestigationIDsDoNotCollide(t *testing.T) {
	eng := newTestEngine(t)
	hosts := []string{"host-a", "host-b", "host-c"}
	seen := map[int64]bool{}

	for i, h := range hosts {
		ids, err := eng.Ingest(exec(h, 100+i, time.Now().UnixNano()))
		if err != nil {
			t.Fatalf("ingest %s: %v", h, err)
		}
		if len(ids) != 1 {
			t.Fatalf("host %s: want 1 investigation touched, got %d", h, len(ids))
		}
		if seen[ids[0]] {
			t.Fatalf("investigation id %d reused across hosts — cross-host collision", ids[0])
		}
		seen[ids[0]] = true
	}

	all := eng.Invs.List()
	if len(all) != len(hosts) {
		t.Fatalf("want %d investigations in the store (one per host), got %d — cross-host overwrite", len(hosts), len(all))
	}
	byHost := map[string]bool{}
	for _, inv := range all {
		byHost[inv.HostID] = true
	}
	for _, h := range hosts {
		if !byHost[h] {
			t.Fatalf("host %s missing from store — its investigation was overwritten", h)
		}
	}

	if st := eng.Stats(); st.Investigations != int64(len(hosts)) {
		t.Fatalf("Stats().Investigations = %d, want %d (fleet-wide count)", st.Investigations, len(hosts))
	}
}
