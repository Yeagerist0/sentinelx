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

	newEng := func() *pipeline.Engine {
		rules, _ := detect.NewEngine(detect.Default())
		sc := correlate.NewScorer()
		sc.CtxMult["T1204.002"] = 1.15
		return pipeline.NewWithStores(rules, sc, pg.Events(), pg.Investigations())
	}

	// --- engine A: ingest the scenario, then "crash" ---
	rc, err := collect.ReplayFile(repoPath(t, "tests/scenarios/curl_lolbin.json"))
	if err != nil {
		t.Fatal(err)
	}
	engA := newEng()
	if err := rc.Run(engA); err != nil {
		t.Fatal(err)
	}
	if got := len(engA.Invs.List()); got != 1 {
		t.Fatalf("engine A: want 1 investigation, got %d", got)
	}

	// --- engine B: fresh in-memory state, same DB, rewarm ---
	engB := newEng()
	if got := engB.Stats().Events; got != 0 {
		t.Fatalf("engine B should start cold, saw %d events", got)
	}
	prior, err := pg.Events().All()
	if err != nil {
		t.Fatal(err)
	}
	engB.Rewarm(prior)

	invs := engB.Invs.List()
	if len(invs) != 1 {
		t.Fatalf("after rewarm: want 1 investigation, got %d", len(invs))
	}
	if invs[0].RiskScore != 100 || len(invs[0].Detections) != 3 {
		t.Fatalf("rewarmed investigation wrong: risk=%d dets=%d", invs[0].RiskScore, len(invs[0].Detections))
	}
	t.Logf("durability: investigation survived restart via rewarm of %d events (risk=%d)", len(prior), invs[0].RiskScore)
}
