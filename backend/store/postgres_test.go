package store

import (
	"context"
	"os"
	"testing"
	"time"

	"sentinelx/backend/correlate"
)

// These run only when SENTINELX_TEST_PG points at a Postgres DSN.
func pgOrSkip(t *testing.T) *PG {
	t.Helper()
	dsn := os.Getenv("SENTINELX_TEST_PG")
	if dsn == "" {
		t.Skip("set SENTINELX_TEST_PG to run Postgres integration tests")
	}
	pg, err := OpenPG(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open pg: %v", err)
	}
	// clean slate
	pg.pool.Exec(context.Background(), "TRUNCATE event, investigation")
	t.Cleanup(pg.Close)
	return pg
}

func TestPGEventRoundTrip(t *testing.T) {
	pg := pgOrSkip(t)
	es := pg.Events()
	ev := correlate.Event{ID: "e1", HostID: "h", TS: time.Unix(1700000000, 0).UTC(),
		Type: correlate.ProcessStart, ProcGUID: "g1", ProcImage: "/tmp/x", Cmdline: "/tmp/x"}
	es.Put(ev)
	es.Put(ev) // idempotent
	if es.Count() != 1 {
		t.Fatalf("want 1 event, got %d", es.Count())
	}
	got, ok := es.Get("e1")
	if !ok || got.ProcImage != "/tmp/x" || got.Type != correlate.ProcessStart {
		t.Fatalf("round-trip failed: %+v ok=%v", got, ok)
	}
}

func TestPGInvestigationRoundTrip(t *testing.T) {
	pg := pgOrSkip(t)
	is := pg.Investigations()
	inv := &correlate.Investigation{
		ID: 1, HostID: "h", RootGUID: "g1", Status: "open",
		FirstSeen: time.Unix(1700000000, 0).UTC(), LastSeen: time.Unix(1700000010, 0).UTC(),
		RiskScore: 88, TechniqueSet: []string{"T1105", "T1204.002"},
		Detections: []int64{1, 2, 3}, EventIDs: map[string]bool{"e1": true, "e2": true},
		ScoreFactors: []correlate.ScoreFactor{{Factor: "detection:x", Base: 65, Contrib: 65}},
	}
	is.Upsert(inv)
	inv.RiskScore = 90
	is.Upsert(inv) // update path

	got, ok := is.Get(1)
	if !ok || got.RiskScore != 90 || len(got.Detections) != 3 || len(got.EventIDs) != 2 {
		t.Fatalf("investigation round-trip failed: %+v ok=%v", got, ok)
	}
	if len(got.ScoreFactors) != 1 || got.ScoreFactors[0].Base != 65 {
		t.Fatalf("score factors not persisted: %+v", got.ScoreFactors)
	}
	if len(is.List()) != 1 {
		t.Fatalf("List want 1, got %d", len(is.List()))
	}
}
