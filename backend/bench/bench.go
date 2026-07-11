// Package bench replays labeled attack/benign scenarios through a fresh pipeline
// and reports real numbers: detections fired, investigations produced, the
// alert-reduction ratio (the metric that operationalizes "solves alert
// fatigue"), and precision/recall against ground-truth labels. No unbenchmarked
// adjectives — this is the evidence.
package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"sentinelx/backend/collect"
	"sentinelx/backend/normalize"
	"sentinelx/backend/pipeline"
)

// GroundTruth labels a scenario.
type GroundTruth struct {
	Malicious  bool     `json:"malicious"`  // should this raise at least one investigation?
	Techniques []string `json:"techniques"` // techniques the attack should surface (optional)
}

// Scenario is a named, labeled event sequence.
type Scenario struct {
	Name        string                 `json:"name"`
	GroundTruth GroundTruth            `json:"ground_truth"`
	Events      []normalize.AgentEvent `json:"events"`
}

// ScenarioResult is the per-scenario outcome.
type ScenarioResult struct {
	Name           string
	Malicious      bool
	RawEvents      int
	Detections     int
	Investigations int
	Reduction      float64 // detections / investigations (>=1; higher = more grouping)
	Outcome        string  // TP | FP | TN | FN
}

// Report aggregates results.
type Report struct {
	Results         []ScenarioResult
	TotalRaw        int
	TotalDetections int
	TotalInvs       int
	Reduction       float64 // malicious detections / malicious investigations
	MalDetections   int     // detections across malicious scenarios
	MalInvs         int     // investigations across malicious scenarios
	Precision       float64
	Recall          float64
	TP, FP, TN, FN  int
}

// LoadDir reads every *.json scenario in dir.
func LoadDir(dir string) ([]Scenario, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var out []Scenario
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var s Scenario
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if s.Name == "" {
			s.Name = strings.TrimSuffix(filepath.Base(p), ".json")
		}
		out = append(out, s)
	}
	return out, nil
}

// Run replays each scenario through a fresh engine built by newEngine.
func Run(scenarios []Scenario, newEngine func() *pipeline.Engine) Report {
	var rep Report
	var malDet, malInv int
	for _, sc := range scenarios {
		eng := newEngine()
		rc := &replaySlice{sc.Events}
		_ = rc.Run(eng)

		st := eng.Stats()
		invs := len(eng.Invs.List())
		res := ScenarioResult{
			Name: sc.Name, Malicious: sc.GroundTruth.Malicious,
			RawEvents: len(sc.Events), Detections: int(st.Detections), Investigations: invs,
		}
		if invs > 0 {
			res.Reduction = float64(st.Detections) / float64(invs)
		}
		raised := invs > 0
		switch {
		case sc.GroundTruth.Malicious && raised:
			res.Outcome = "TP"
			rep.TP++
			malDet += int(st.Detections)
			malInv += invs
		case sc.GroundTruth.Malicious && !raised:
			res.Outcome = "FN"
			rep.FN++
		case !sc.GroundTruth.Malicious && raised:
			res.Outcome = "FP"
			rep.FP++
		default:
			res.Outcome = "TN"
			rep.TN++
		}
		rep.Results = append(rep.Results, res)
		rep.TotalRaw += len(sc.Events)
		rep.TotalDetections += int(st.Detections)
		rep.TotalInvs += invs
	}
	rep.MalDetections, rep.MalInvs = malDet, malInv
	if malInv > 0 {
		rep.Reduction = float64(malDet) / float64(malInv)
	}
	if rep.TP+rep.FP > 0 {
		rep.Precision = float64(rep.TP) / float64(rep.TP+rep.FP)
	}
	if rep.TP+rep.FN > 0 {
		rep.Recall = float64(rep.TP) / float64(rep.TP+rep.FN)
	}
	return rep
}

// String renders a plain-text report table.
func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-24s %-9s %5s %5s %5s %8s  %s\n", "SCENARIO", "LABEL", "RAW", "DET", "INV", "REDUCE", "OUTCOME")
	for _, res := range r.Results {
		label := "benign"
		if res.Malicious {
			label = "malicious"
		}
		fmt.Fprintf(&b, "%-24s %-9s %5d %5d %5d %7.2fx  %s\n",
			res.Name, label, res.RawEvents, res.Detections, res.Investigations, res.Reduction, res.Outcome)
	}
	fmt.Fprintf(&b, "\nalert-reduction (malicious): %.2fx  (%d detections -> %d investigations)\n",
		r.Reduction, r.MalDetections, r.MalInvs)
	fmt.Fprintf(&b, "precision: %.2f  recall: %.2f  (TP=%d FP=%d TN=%d FN=%d)\n",
		r.Precision, r.Recall, r.TP, r.FP, r.TN, r.FN)
	return b.String()
}

// replaySlice adapts an in-memory event slice to collect.Sink without touching
// the filesystem.
type replaySlice struct{ events []normalize.AgentEvent }

func (r *replaySlice) Run(s collect.Sink) error {
	for _, e := range r.events {
		_, _ = s.Ingest(e)
	}
	return nil
}
