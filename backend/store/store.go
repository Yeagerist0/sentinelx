// Package store holds the persistence interfaces (EventStore, InvestigationStore)
// with in-memory implementations shipping first. The Postgres implementations
// live behind the same interfaces; see deploy/schema.sql for the DDL.
package store

import (
	"sort"
	"sync"

	"sentinelx/backend/correlate"
)

// EventStore persists normalized events (evidence).
type EventStore interface {
	Put(correlate.Event)
	Get(id string) (correlate.Event, bool)
	Count() int
}

// InvestigationStore persists correlated investigations.
type InvestigationStore interface {
	Upsert(*correlate.Investigation)
	Get(id int64) (*correlate.Investigation, bool)
	List() []*correlate.Investigation
}

// MemEventStore is an in-memory EventStore.
type MemEventStore struct {
	mu sync.RWMutex
	m  map[string]correlate.Event
}

func NewMemEventStore() *MemEventStore { return &MemEventStore{m: map[string]correlate.Event{}} }

func (s *MemEventStore) Put(e correlate.Event) {
	s.mu.Lock()
	s.m[e.ID] = e
	s.mu.Unlock()
}

func (s *MemEventStore) Get(id string) (correlate.Event, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.m[id]
	return e, ok
}

func (s *MemEventStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}

// MemInvestigationStore is an in-memory InvestigationStore.
type MemInvestigationStore struct {
	mu sync.RWMutex
	m  map[int64]*correlate.Investigation
}

func NewMemInvestigationStore() *MemInvestigationStore {
	return &MemInvestigationStore{m: map[int64]*correlate.Investigation{}}
}

func (s *MemInvestigationStore) Upsert(inv *correlate.Investigation) {
	s.mu.Lock()
	s.m[inv.ID] = inv
	s.mu.Unlock()
}

func (s *MemInvestigationStore) Get(id int64) (*correlate.Investigation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inv, ok := s.m[id]
	return inv, ok
}

func (s *MemInvestigationStore) List() []*correlate.Investigation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*correlate.Investigation, 0, len(s.m))
	for _, inv := range s.m {
		out = append(out, inv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
