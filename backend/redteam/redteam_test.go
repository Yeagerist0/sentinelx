package redteam

import (
	"path/filepath"
	"runtime"
	"testing"

	"sentinelx/backend/bench"
	"sentinelx/backend/correlate"
	"sentinelx/backend/detect"
	"sentinelx/backend/narrate"
	"sentinelx/backend/pipeline"
)

func newEngine() *pipeline.Engine {
	rules, _ := detect.NewEngine(detect.Default())
	sc := correlate.NewScorer()
	sc.CtxMult["T1204.002"] = 1.15
	return pipeline.New(rules, sc)
}

func fixtures(t *testing.T) ([]bench.Scenario, PayloadFile) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..", "tests", "redteam")
	scen, err := bench.LoadDir(filepath.Join(root, "scenarios"))
	if err != nil || len(scen) == 0 {
		t.Fatalf("scenarios: %v (%d)", err, len(scen))
	}
	pf, err := LoadPayloads(filepath.Join(root, "payloads.json"))
	if err != nil || len(pf.Payloads) != 66 {
		t.Fatalf("payloads: %v (%d)", err, len(pf.Payloads))
	}
	return scen, pf
}

// The deterministic GroundedModel never omits and never drafts an invalid
// statement, so the harness must report zero omission and zero rejections for
// it. If this fails, either the harness or the narrator's allow-list is wrong
// (it caught a real bug: file_read events were being rejected as "mistyped").
func TestHarnessOnDeterministicModelIsClean(t *testing.T) {
	scen, pf := fixtures(t)
	rep := Run(scen, pf, Config{NewEngine: newEngine, Model: narrate.GroundedModel{}, Repeats: 1})
	if rep.TrialsValid < 40 {
		t.Fatalf("too few valid trials to mean anything: %d (skipped %v)", rep.TrialsValid, rep.SkippedByReason)
	}
	if rep.InjectedOmission.K != 0 || rep.InjectedCovered.K != 0 || rep.CriticalOmission.K != 0 {
		t.Fatalf("deterministic model omitted events: injected=%+v covered=%+v critical=%+v", rep.InjectedOmission, rep.InjectedCovered, rep.CriticalOmission)
	}
	if rep.RejectedRate.K != 0 {
		t.Fatalf("deterministic model produced rejected statements: %+v", rep.RejectedRate)
	}
	if rep.RiskUnchanged.K != rep.RiskUnchanged.N {
		t.Fatalf("an injected payload changed the trusted risk sentence: %+v", rep.RiskUnchanged)
	}
	if rep.NotExposed != 32 {
		t.Fatalf("expected 32 corpus payloads (cmdline/registry/user_agent) to be unexposed, got %d", rep.NotExposed)
	}
}

// A model that drops events must be caught by the harness, and the coverage
// guard must restore every detection-cited event.
func TestHarnessDetectsOmissionAndCoverageGuardFixesIt(t *testing.T) {
	scen, pf := fixtures(t)
	rep := Run(scen, pf, Config{NewEngine: newEngine, Model: dropAllEvents{}, Repeats: 1, MaxTrials: 12})
	if rep.InjectedOmission.K == 0 {
		t.Fatalf("harness failed to notice a model that drops events: %+v", rep.InjectedOmission)
	}
	if rep.InjectedCovered.K != 0 {
		t.Fatalf("coverage guard should restore every detection-cited event, still omitted: %+v", rep.InjectedCovered)
	}
}

// dropAllEvents narrates nothing but the risk line.
type dropAllEvents struct{}

func (dropAllEvents) Draft(v narrate.InvestigationView) []narrate.Statement {
	if len(v.Events) == 0 {
		return nil
	}
	return []narrate.Statement{{Kind: narrate.KindRisk, EventIDs: []string{v.Events[0].ID}}}
}
