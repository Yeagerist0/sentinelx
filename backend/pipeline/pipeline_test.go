package pipeline

import (
	"errors"
	"testing"
	"time"

	"sentinelx/backend/correlate"
	"sentinelx/backend/detect"
	"sentinelx/backend/normalize"
)

const tenantA = "tenant-a"
const tenantB = "tenant-b"

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
		ids, err := eng.Ingest(tenantA, exec(h, 100+i, time.Now().UnixNano()))
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

	if st := eng.Stats(tenantA); st.Investigations != int64(len(hosts)) {
		t.Fatalf("Stats().Investigations = %d, want %d (fleet-wide count)", st.Investigations, len(hosts))
	}
}

// TestCrossTenantIsolation is the core multi-tenancy guarantee: two different
// tenants monitoring a host with the IDENTICAL name must never collide, leak
// into, or be reachable from each other, at any layer — the graph/correlator,
// the investigation store, stats, or the audit log.
func TestCrossTenantIsolation(t *testing.T) {
	eng := newTestEngine(t)
	ts := time.Now().UnixNano()

	idsA, err := eng.Ingest(tenantA, exec("web-01", 100, ts))
	if err != nil || len(idsA) != 1 {
		t.Fatalf("tenant A ingest: ids=%v err=%v", idsA, err)
	}
	idsB, err := eng.Ingest(tenantB, exec("web-01", 100, ts))
	if err != nil || len(idsB) != 1 {
		t.Fatalf("tenant B ingest: ids=%v err=%v", idsB, err)
	}

	// Same hostname, same pid, same timestamp: without tenant scoping these
	// would land in the same graph and (worse) the same investigation.
	if idsA[0] == idsB[0] {
		t.Fatalf("both tenants got the same investigation id %d — cross-tenant collision", idsA[0])
	}

	invA, ok := eng.Invs.GetForTenant(tenantA, idsA[0])
	if !ok || invA.TenantID != tenantA {
		t.Fatalf("tenant A cannot fetch its own investigation via GetForTenant: ok=%v", ok)
	}
	if _, ok := eng.Invs.GetForTenant(tenantB, idsA[0]); ok {
		t.Fatal("tenant B could fetch tenant A's investigation by guessing its id")
	}
	if _, ok := eng.Invs.GetForTenant(tenantA, idsB[0]); ok {
		t.Fatal("tenant A could fetch tenant B's investigation by guessing its id")
	}

	listA := eng.Invs.ListByTenant(tenantA)
	if len(listA) != 1 || listA[0].ID != idsA[0] {
		t.Fatalf("tenant A's list leaked or missed investigations: %+v", listA)
	}
	listB := eng.Invs.ListByTenant(tenantB)
	if len(listB) != 1 || listB[0].ID != idsB[0] {
		t.Fatalf("tenant B's list leaked or missed investigations: %+v", listB)
	}

	// Detections are keyed globally (one detect.Engine) but Detections() must
	// filter by tenant, never returning another tenant's detection detail.
	detsA := eng.Detections(tenantA, listB[0].Detections)
	if len(detsA) != 0 {
		t.Fatalf("tenant A retrieved tenant B's detection detail: %+v", detsA)
	}

	// Stats must not leak volume across tenants.
	if st := eng.Stats(tenantA); st.Events != 1 || st.Investigations != 1 {
		t.Fatalf("tenant A stats polluted: %+v", st)
	}
	if st := eng.Stats(tenantB); st.Events != 1 || st.Investigations != 1 {
		t.Fatalf("tenant B stats polluted: %+v", st)
	}

	// Each tenant gets its own independently-verifiable audit chain.
	if ok, _ := eng.AuditLog(tenantA).Verify(); !ok {
		t.Fatal("tenant A audit chain broken")
	}
	if ok, _ := eng.AuditLog(tenantB).Verify(); !ok {
		t.Fatal("tenant B audit chain broken")
	}
	if eng.AuditLog(tenantA).Len() != eng.AuditLog(tenantB).Len() {
		t.Fatalf("audit chains diverged in length for symmetric ingests: A=%d B=%d",
			eng.AuditLog(tenantA).Len(), eng.AuditLog(tenantB).Len())
	}

	// SetStatus must not let a tenant act on another tenant's investigation.
	if err := eng.SetStatus(tenantB, idsA[0], correlate.StatusResolved); !errors.Is(err, ErrInvestigationNotFound) {
		t.Fatalf("tenant B was able to modify tenant A's investigation status: err=%v", err)
	}
	if inv, _ := eng.Invs.GetForTenant(tenantA, idsA[0]); inv.Status != correlate.StatusOpen {
		t.Fatalf("tenant A's investigation status was mutated by tenant B's attempt: %q", inv.Status)
	}
}

func TestSetStatus(t *testing.T) {
	eng := newTestEngine(t)
	ids, err := eng.Ingest(tenantA, exec("h1", 200, time.Now().UnixNano()))
	if err != nil || len(ids) != 1 {
		t.Fatalf("seed investigation: ids=%v err=%v", ids, err)
	}
	id := ids[0]

	if err := eng.SetStatus(tenantA, id, "bogus"); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("want ErrInvalidStatus, got %v", err)
	}
	if err := eng.SetStatus(tenantA, 99999, correlate.StatusResolved); !errors.Is(err, ErrInvestigationNotFound) {
		t.Fatalf("want ErrInvestigationNotFound, got %v", err)
	}

	if err := eng.SetStatus(tenantA, id, correlate.StatusResolved); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	inv, ok := eng.Invs.GetForTenant(tenantA, id)
	if !ok || inv.Status != correlate.StatusResolved {
		t.Fatalf("status not persisted: ok=%v status=%q", ok, inv.Status)
	}

	// The audit trail must record the analyst action.
	if ok, _ := eng.AuditLog(tenantA).Verify(); !ok {
		t.Fatal("audit chain broken after SetStatus")
	}

	if err := eng.SetStatus(tenantA, id, correlate.StatusOpen); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if inv, _ := eng.Invs.GetForTenant(tenantA, id); inv.Status != correlate.StatusOpen {
		t.Fatalf("reopen did not stick: %q", inv.Status)
	}
}

// TestSetStatusSurvivesRewarm is the scenario the whole design revolves
// around: correlation always recomputes an investigation as "open" from
// scratch, so a naive Rewarm would silently undo an analyst's resolve/dismiss
// decision on every restart. Rewarm must snapshot and reapply it instead.
func TestSetStatusSurvivesRewarm(t *testing.T) {
	eng := newTestEngine(t)
	ev := exec("h1", 300, time.Now().UnixNano())
	ids, err := eng.Ingest(tenantA, ev)
	if err != nil || len(ids) != 1 {
		t.Fatalf("seed investigation: ids=%v err=%v", ids, err)
	}
	id := ids[0]

	if err := eng.SetStatus(tenantA, id, correlate.StatusDismissed); err != nil {
		t.Fatalf("dismiss: %v", err)
	}

	// Simulate a restart: replay the same persisted events against the SAME
	// store (as a real restart would replay from Postgres into a fresh
	// in-memory graph, but reusing e.Invs which holds the last-persisted rows).
	norm, err := normalize.Normalize(ev)
	if err != nil {
		t.Fatal(err)
	}
	norm.TenantID = tenantA // Ingest sets this from the authenticated caller; Normalize alone does not
	eng.Rewarm([]correlate.Event{norm})

	inv, ok := eng.Invs.GetForTenant(tenantA, id)
	if !ok {
		t.Fatal("investigation vanished after rewarm")
	}
	if inv.Status != correlate.StatusDismissed {
		t.Fatalf("rewarm reset analyst status: got %q, want %q", inv.Status, correlate.StatusDismissed)
	}
}

// TestDownloadExecBeaconPattern drives the full download → execute → beacon chain
// through the pipeline and asserts the graph-pattern detection fires and lands in
// an investigation, citing the write and the beacon as evidence. This is the
// cross-event shape the single-event rule engine cannot express on its own.
func TestDownloadExecBeaconPattern(t *testing.T) {
	eng := newTestEngine(t)
	ts := time.Now().UnixNano()
	host := "web-01"
	ev := func(id, kind string, pid int, exe, path, raddr string, rport, ppid int) normalize.AgentEvent {
		return normalize.AgentEvent{
			ID: id, HostID: host, BootID: "b", Kind: kind, PID: pid, StartTicks: int64(pid),
			PPID: ppid, ParentStartTicks: int64(ppid), TSUnixNs: ts, Exe: exe,
			Path: path, RAddr: raddr, RPort: rport,
		}
	}
	seq := []normalize.AgentEvent{
		ev("1", "exec", 101, "/usr/bin/curl", "", "", 0, 10),
		ev("2", "net.connect", 101, "/usr/bin/curl", "", "203.0.113.5", 80, 0),
		ev("3", "file.write", 101, "/usr/bin/curl", "/tmp/payload", "", 0, 0),
		ev("4", "exec", 103, "/tmp/payload", "", "", 0, 10),
		ev("5", "net.connect", 103, "/tmp/payload", "", "203.0.113.5", 4444, 0),
	}
	for _, a := range seq {
		if _, err := eng.Ingest(tenantA, a); err != nil {
			t.Fatalf("ingest %s: %v", a.ID, err)
		}
	}

	// gather every detection across this tenant's investigations.
	var beacon *correlate.Detection
	for _, inv := range eng.Invs.ListByTenant(tenantA) {
		for _, d := range eng.Detections(tenantA, inv.Detections) {
			if d.RuleID == "download_exec_beacon" {
				dd := d
				beacon = &dd
			}
		}
	}
	if beacon == nil {
		t.Fatal("download_exec_beacon detection never fired end to end")
	}
	if beacon.ProcGUID != normalize.ProcGUID("b", 103, 103) {
		t.Errorf("anchored on %q, want the payload process", beacon.ProcGUID)
	}
	if len(beacon.EventIDs) != 2 || beacon.EventIDs[0] != "3" || beacon.EventIDs[1] != "5" {
		t.Errorf("EventIDs = %v, want [3 5] (write, beacon)", beacon.EventIDs)
	}

	// idempotent: replaying the same events must not fire the pattern twice.
	before := eng.Stats(tenantA).Detections
	for _, a := range seq {
		if _, err := eng.Ingest(tenantA, a); err != nil {
			t.Fatal(err)
		}
	}
	count := 0
	for _, inv := range eng.Invs.ListByTenant(tenantA) {
		for _, d := range eng.Detections(tenantA, inv.Detections) {
			if d.RuleID == "download_exec_beacon" {
				count++
			}
		}
	}
	if count != 1 {
		t.Errorf("download_exec_beacon present %d times after replay, want 1 (dedup broken)", count)
	}
	_ = before
}

// TestCredentialReadExfilPattern drives read-secret → connect-out through the
// pipeline and asserts the credential_read_exfil graph pattern fires end to end.
func TestCredentialReadExfilPattern(t *testing.T) {
	eng := newTestEngine(t)
	ts := time.Now().UnixNano()
	host := "web-01"
	ev := func(id, kind, path, raddr string, rport int) normalize.AgentEvent {
		return normalize.AgentEvent{
			ID: id, HostID: host, BootID: "b", Kind: kind, PID: 200, StartTicks: 200,
			TSUnixNs: ts, Exe: "/usr/bin/python3", Path: path, RAddr: raddr, RPort: rport,
		}
	}
	seq := []normalize.AgentEvent{
		ev("1", "exec", "", "", 0),
		ev("2", "file.read", "/home/alice/.ssh/id_rsa", "", 0),
		ev("3", "net.connect", "", "198.51.100.7", 443),
	}
	for _, a := range seq {
		if _, err := eng.Ingest(tenantA, a); err != nil {
			t.Fatalf("ingest %s: %v", a.ID, err)
		}
	}

	var found *correlate.Detection
	for _, inv := range eng.Invs.ListByTenant(tenantA) {
		for _, d := range eng.Detections(tenantA, inv.Detections) {
			if d.RuleID == "credential_read_exfil" {
				dd := d
				found = &dd
			}
		}
	}
	if found == nil {
		t.Fatal("credential_read_exfil never fired end to end")
	}
	if len(found.EventIDs) != 2 || found.EventIDs[0] != "2" || found.EventIDs[1] != "3" {
		t.Errorf("EventIDs = %v, want [2 3] (read, connect)", found.EventIDs)
	}
}
