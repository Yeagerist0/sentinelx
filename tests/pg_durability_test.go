package tests

import (
	"context"
	"os"
	"testing"

	"sentinelx/backend/collect"
	"sentinelx/backend/correlate"
	"sentinelx/backend/detect"
	"sentinelx/backend/pipeline"
	"sentinelx/backend/store"
)

// TestPGDurabilityRewarm proves an investigation survives a backend restart:
// ingest through engine A (Postgres-backed), then build a FRESH engine B on the
// same database, rewarm from persisted events, and assert the investigation is
// back. Runs only when SENTINELX_TEST_PG is set.
func TestPGDurabilityRewarm(t *testing.T) {
	dsn := os.Getenv("SENTINELX_TEST_PG")
	if dsn == "" {
		t.Skip("set SENTINELX_TEST_PG to run Postgres durability test")
	}
	pg, err := store.OpenPG(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open pg: %v", err)
	}
	defer pg.Close()
	// This package shares a Postgres instance with backend/store's tests, which
	// don't reset it after themselves. Investigation ids restart from 1 in every
	// fresh in-memory Engine, so a leftover row from another test's inv_id=1
	// would otherwise be silently updated in place (its tenant_id preserved on
	// conflict, by design — see PGInvestigationStore.Upsert) rather than created
	// fresh, breaking this test's own counting.
	if err := pg.Reset(context.Background()); err != nil {
		t.Fatalf("reset: %v", err)
	}

	newEng := func() *pipeline.Engine {
		rules, _ := detect.NewEngine(detect.Default())
		sc := correlate.NewScorer()
		sc.CtxMult["T1204.002"] = 1.15
		return pipeline.NewWithStores(rules, sc, pg.Events(), pg.Investigations())
	}

	const tenantID = "acme"

	// --- engine A: ingest the scenario, then "crash" ---
	rc, err := collect.ReplayFile(repoPath(t, "tests/scenarios/curl_lolbin.json"))
	if err != nil {
		t.Fatal(err)
	}
	engA := newEng()
	if err := rc.Run(tenantID, engA); err != nil {
		t.Fatal(err)
	}
	if got := len(engA.Invs.ListByTenant(tenantID)); got != 1 {
		t.Fatalf("engine A: want 1 investigation, got %d", got)
	}

	// --- engine B: fresh in-memory state, same DB, rewarm ---
	engB := newEng()
	if got := engB.Stats(tenantID).Events; got != 0 {
		t.Fatalf("engine B should start cold, saw %d events", got)
	}
	prior, err := pg.Events().All()
	if err != nil {
		t.Fatal(err)
	}
	engB.Rewarm(prior)

	invs := engB.Invs.ListByTenant(tenantID)
	if len(invs) != 1 {
		t.Fatalf("after rewarm: want 1 investigation, got %d", len(invs))
	}
	// 4, not 3: the scenario's C2 callback (port 4444) is itself caught by the
	// broadened ruleset's suspicious_c2_port rule.
	if invs[0].RiskScore != 100 || len(invs[0].Detections) != 4 {
		t.Fatalf("rewarmed investigation wrong: risk=%d dets=%d", invs[0].RiskScore, len(invs[0].Detections))
	}
	if invs[0].TenantID != tenantID {
		t.Fatalf("rewarmed investigation lost its tenant id: got %q, want %q", invs[0].TenantID, tenantID)
	}
	t.Logf("durability: investigation survived restart via rewarm of %d events (risk=%d)", len(prior), invs[0].RiskScore)
}
