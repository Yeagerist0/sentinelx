package correlate

import (
	"fmt"
	"math"
	"strings"
)

// Scorer computes an investigation's risk score as an auditable sum of
// per-detection contributions times context multipliers, plus a novelty factor
// derived from rare provenance edges. Every returned ScoreFactor cites the
// events it is grounded in, so the UI can render "why", not just a number.
type Scorer struct {
	// CtxMult multiplies a detection's base severity when the named technique is
	// present in the investigation (e.g. exec-from-tmp in a shell chain).
	CtxMult map[string]float64
}

// NewScorer returns a scorer with no extra context multipliers.
func NewScorer() *Scorer { return &Scorer{CtxMult: map[string]float64{}} }

// Score returns the clamped 0..100 risk score and its factor breakdown.
func (s *Scorer) Score(inv *Investigation, dets []Detection) (int, []ScoreFactor) {
	factors := make([]ScoreFactor, 0, len(dets)+1)
	total := 0.0

	for _, d := range dets {
		mult := 1.0
		for _, t := range d.Technique {
			if m, ok := s.CtxMult[t]; ok && m > mult {
				mult = m
			}
		}
		contrib := int(math.Round(float64(d.Severity) * mult))
		factors = append(factors, ScoreFactor{
			Factor:  "detection:" + d.RuleID,
			Base:    d.Severity,
			Mult:    mult,
			Contrib: contrib,
			Events:  d.EventIDs,
			Note:    strings.Join(d.Technique, ","),
		})
		total += float64(contrib)
	}

	// Novelty: rare edges (weight > 0.8) in the investigation's subgraph raise
	// confidence that this is real, not routine.
	rare := 0
	for _, n := range inv.Nodes {
		for _, e := range n.Out {
			if e.Weight > 0.8 {
				rare++
			}
		}
	}
	if rare > 0 {
		nov := 1.0 + math.Min(0.2, float64(rare)*0.02)
		total *= nov
		factors = append(factors, ScoreFactor{
			Factor: "novelty:rare_edges",
			Mult:   nov,
			Note:   fmt.Sprintf("%d rare provenance edges", rare),
		})
	}

	score := int(math.Min(100, math.Round(total)))
	return score, factors
}
