// Package audit is the tamper-evident evidence log: an append-only, hash-chained
// record so an attacker who compromises the backend cannot silently rewrite
// history. Each entry commits to the previous entry's hash (a Merkle-linked
// chain); Verify walks the chain and reports the first break.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Entry is one link in the chain.
type Entry struct {
	Seq         int64     `json:"seq"`
	TS          time.Time `json:"ts"`
	Kind        string    `json:"kind"`
	Ref         string    `json:"ref"`
	PayloadHash string    `json:"payload_hash"`
	PrevHash    string    `json:"prev_hash"`
	ThisHash    string    `json:"this_hash"`
}

// Log is an in-memory hash-chained audit log. The Postgres implementation writes
// the same rows to an append-only table with the chain enforced by a trigger.
type Log struct {
	mu      sync.Mutex
	entries []Entry
	head    string
	now     func() time.Time
}

// New returns an empty log with a genesis head.
func New() *Log {
	return &Log{head: "genesis", now: time.Now}
}

func hashHex(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Append commits a payload to the chain and returns the new entry.
func (l *Log) Append(kind, ref string, payload []byte) Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	ph := hashHex(string(payload))
	seq := int64(len(l.entries) + 1)
	ts := l.now().UTC()
	this := hashHex(l.head, ph, ts.Format(time.RFC3339Nano), kind, ref)
	e := Entry{Seq: seq, TS: ts, Kind: kind, Ref: ref, PayloadHash: ph, PrevHash: l.head, ThisHash: this}
	l.entries = append(l.entries, e)
	l.head = this
	return e
}

// Head returns the current chain head hash.
func (l *Log) Head() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.head
}

// Len returns the number of entries.
func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// Verify recomputes the chain and returns (true, 0) if intact, else (false, seq)
// of the first tampered entry.
func (l *Log) Verify() (bool, int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := "genesis"
	for _, e := range l.entries {
		want := hashHex(prev, e.PayloadHash, e.TS.Format(time.RFC3339Nano), e.Kind, e.Ref)
		if want != e.ThisHash || e.PrevHash != prev {
			return false, e.Seq
		}
		prev = e.ThisHash
	}
	return true, 0
}

// Appendf is a convenience for structured refs.
func (l *Log) Appendf(kind, ref string, format string, args ...any) Entry {
	return l.Append(kind, ref, []byte(fmt.Sprintf(format, args...)))
}
