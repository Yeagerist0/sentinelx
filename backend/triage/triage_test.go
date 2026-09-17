package triage_test

import (
	"context"
	"strings"
	"testing"

	"sentinelx/backend/correlate"
	"sentinelx/backend/detect"
	"sentinelx/backend/pipeline"
	"sentinelx/backend/triage"
)

func newEngine() *pipeline.Engine {
	rules, err := detect.NewEngine(detect.Default())
	if err != nil {
		panic(err)
	}
	return pipeline.New(rules, correlate.NewScorer())
}

// TestSpine_BareBonesAgentLoop tests the "This week — spine" milestone:
// bare-bones agent loop on 3-4 real detections with graph-reading + lineage + file read, no sandbox yet.
func TestSpine_BareBonesAgentLoop(t *testing.T) {
	agent := triage.NewBareBonesAgent() // Spine baseline: ModeGraphOnly
	corpus := triage.HandLabeledCorpus()

	if len(corpus) < 4 {
		t.Fatalf("expected at least 4 scenarios in hand-labeled corpus")
	}

	// Test first 4 scenarios (LOLBin, wget, reverse shell, benign admin)
	for i := 0; i < 4; i++ {
		sc := corpus[i]
		eng := newEngine()

		for _, ev := range sc.Events {
			_, _ = eng.Ingest(pipeline.DefaultTenant, ev)
		}

		invs := eng.Invs.ListByTenant(pipeline.DefaultTenant)
		if sc.Label == triage.LabelExploitable && len(invs) == 0 {
			t.Fatalf("scenario %s expected at least one investigation", sc.ID)
		}

		if len(invs) > 0 {
			ctx := context.Background()
			verdict, err := agent.Triage(ctx, pipeline.DefaultTenant, invs[0], eng.Events, eng.Invs)
			if err != nil {
				t.Fatalf("bare-bones triage failed for %s: %v", sc.ID, err)
			}
			if len(verdict.Trace) == 0 {
				t.Errorf("expected non-empty agent reasoning trace")
			}
			t.Logf("Spine Scenario %s: Label=%s VerdictExploitable=%t Confidence=%.2f Steps=%d",
				sc.ID, sc.Label, verdict.Exploitable, verdict.Confidence, len(verdict.Trace))
		}
	}
}

// TestRigor_SandboxedReproduction tests the "30 days — rigor" milestone:
// full agent loop with isolated sandboxed execution reproducing the command chain and side-effects.
func TestRigor_SandboxedReproduction(t *testing.T) {
	agent := triage.NewAgent(nil) // ModeFullSandbox
	corpus := triage.HandLabeledCorpus()

	// Scenario 1: LOLBin curl drop to /tmp + exec
	sc := corpus[0]
	eng := newEngine()

	for _, ev := range sc.Events {
		_, _ = eng.Ingest(pipeline.DefaultTenant, ev)
	}

	invs := eng.Invs.ListByTenant(pipeline.DefaultTenant)
	if len(invs) == 0 {
		t.Fatalf("expected investigation for scenario %s", sc.ID)
	}

	ctx := context.Background()
	verdict, err := agent.Triage(ctx, pipeline.DefaultTenant, invs[0], eng.Events, eng.Invs)
	if err != nil {
		t.Fatalf("full triage failed: %v", err)
	}

	if !verdict.Exploitable {
		t.Errorf("expected exploitable=true for lolbin chain")
	}
	if verdict.Confidence < 0.90 {
		t.Errorf("expected confidence >= 0.90 with sandbox reproduction, got %f", verdict.Confidence)
	}
	if len(verdict.ReproductionSteps) == 0 {
		t.Errorf("expected non-empty reproduction steps")
	}
	if !strings.Contains(verdict.ConfoundCheck, "PASS") {
		t.Errorf("expected confound check pass, got: %s", verdict.ConfoundCheck)
	}
}

// TestEvalHarness_HandLabeledCorpus runs the full 16-scenario hand-labeled evaluation dataset
// and checks precision, recall, accuracy, and failure taxonomy.
func TestEvalHarness_HandLabeledCorpus(t *testing.T) {
	harness := triage.NewEvalHarness(nil, newEngine)
	ctx := context.Background()

	report, err := harness.RunEval(ctx, nil)
	if err != nil {
		t.Fatalf("RunEval failed: %v", err)
	}

	if report.TotalScenarios < 15 {
		t.Errorf("expected at least 15 hand-labeled scenarios, got %d", report.TotalScenarios)
	}

	// Precision should be high (>= 0.80)
	if report.Precision < 0.80 {
		t.Errorf("expected precision >= 0.80, got %.2f", report.Precision)
	}

	// Recall should be 1.00 (catching all real exploits)
	if report.Recall < 1.00 {
		t.Errorf("expected recall 1.00, got %.2f", report.Recall)
	}

	// Confound resilience should be 100% against injection traps
	if report.ConfoundResilience < 1.00 {
		t.Errorf("expected 100%% confound resilience, got %.2f", report.ConfoundResilience)
	}

	t.Logf("\n%s", report.String())
}
