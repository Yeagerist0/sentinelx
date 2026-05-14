package correlate

// Baseline learns how common each (image|rel|kind) edge is across the fleet and
// converts that into a rarity weight. Common edges get a low weight (near 0.05);
// rare or never-seen edges get a high weight (up to 1.0). This is the anomaly
// signal used by both traversal cost and the rarity boundary, in the spirit of
// NoDoze/PrioTracker anomaly-weighted provenance paths. [VERIFY venues/years]
//
// v1 keeps counts in memory; the scale-out path persists them to Postgres and
// ages them with a decay window.
type Baseline struct {
	counts map[string]int
	total  int
}

// NewBaseline returns an empty baseline where every key is maximally rare.
func NewBaseline() *Baseline {
	return &Baseline{counts: map[string]int{}}
}

// Observe records one occurrence of an edge key.
func (b *Baseline) Observe(key string) {
	b.counts[key]++
	b.total++
}

// Weight returns the rarity weight for a key in [0.05, 1.0]. Unseen keys and
// empty baselines return 1.0 (treat the unknown as anomalous).
func (b *Baseline) Weight(key string) float64 {
	if b.total == 0 {
		return 1.0
	}
	r := 1.0 - float64(b.counts[key])/float64(b.total)
	return clampF(r, 0.05, 1.0)
}

func clampF(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
