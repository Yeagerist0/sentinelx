package correlate

// pqItem is a frontier entry for the weighted best-first expansion.
// cost is the accumulated path cost (sum of 1-weight); bridge is the weight of
// the edge used to reach node (decides the rarity boundary at settle time).
type pqItem struct {
	node   *Node
	cost   float64
	bridge float64
}

// minPQ is a min-heap on cost, so we always expand the rarest (lowest-cost)
// path first — anomalous edges are followed far, common noise dies quickly.
type minPQ []pqItem

func (p minPQ) Len() int           { return len(p) }
func (p minPQ) Less(i, j int) bool { return p[i].cost < p[j].cost }
func (p minPQ) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p *minPQ) Push(x any)        { *p = append(*p, x.(pqItem)) }
func (p *minPQ) Pop() any {
	old := *p
	n := len(old)
	it := old[n-1]
	*p = old[:n-1]
	return it
}
