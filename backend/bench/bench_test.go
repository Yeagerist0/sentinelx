package bench

import (
	"path/filepath"
	"runtime"
	"testing"

	"sentinelx/backend/correlate"
	"sentinelx/backend/detect"
	"sentinelx/backend/pipeline"
)

func newEngine() *pipeline.Engine {
	rules, _ := detect.NewEngine(detect.Default())
	sc := correlate.NewScorer()
	sc.CtxMult["T1204.002"] = 1.15
	return pipeline.New(rules, sc)
}

// The benchmark over the shipped scenarios must show real alert reduction and
// perfect recall (both malicious chains raise an investigation).
func TestBenchmarkNumbers(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(file), "..", "..", "tests", "scenarios", "bench")
	scen, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("load scenarios: %v", err)
	}
	if len(scen) < 5 {
		t.Fatalf("expected >=5 scenarios, got %d", len(scen))
	}
	rep := Run(scen, newEngine)

	if rep.Reduction < 2.0 {
		t.Fatalf("alert-reduction ratio too low: %.2f", rep.Reduction)
	}
	if rep.Recall != 1.0 {
		t.Fatalf("recall = %.2f, want 1.0 (a malicious chain went undetected)", rep.Recall)
	}
	if rep.TP != 3 {
		t.Fatalf("want 3 true positives, got %d", rep.TP)
	}
	t.Logf("reduction=%.2fx precision=%.2f recall=%.2f TP=%d FP=%d TN=%d FN=%d",
		rep.Reduction, rep.Precision, rep.Recall, rep.TP, rep.FP, rep.TN, rep.FN)
}
