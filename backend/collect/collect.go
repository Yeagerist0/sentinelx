// Package collect is the agent-side collection seam. A Collector produces
// AgentEvents and hands them to a Sink (the pipeline). The production collector
// is eBPF (ADR-0003); this package ships two runnable collectors today:
//
//   - ReplayCollector: streams AgentEvents from a JSON array or JSONL source.
//     Powers the demo, the benchmark, and offline reprocessing.
//   - ProcCollector: a dependency-free Linux /proc poller for process_start
//     events. A dev/fallback collector — it cannot see file/network activity
//     (that needs eBPF/auditd) and misses very short-lived processes.
package collect

import (
	"encoding/json"
	"io"
	"os"
	"strings"

	"sentinelx/backend/normalize"
)

// Sink consumes agent events. *pipeline.Engine satisfies it.
type Sink interface {
	Ingest(normalize.AgentEvent) ([]int64, error)
}

// Collector produces events into a Sink until done.
type Collector interface {
	Run(Sink) error
}

// ReplayCollector streams AgentEvents from a JSON array or newline-delimited
// JSON (JSONL) reader.
type ReplayCollector struct {
	events []normalize.AgentEvent
}

// NewReplayCollector parses events from r (JSON array first, JSONL fallback).
func NewReplayCollector(r io.Reader) (*ReplayCollector, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return parseEvents(b)
}

// ReplayFile parses a scenario file.
func ReplayFile(path string) (*ReplayCollector, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseEvents(b)
}

func parseEvents(b []byte) (*ReplayCollector, error) {
	var arr []normalize.AgentEvent
	if err := json.Unmarshal(b, &arr); err == nil {
		return &ReplayCollector{events: arr}, nil
	}
	// JSONL fallback
	var out []normalize.AgentEvent
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e normalize.AgentEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return &ReplayCollector{events: out}, nil
}

// Events returns the parsed events (used by the benchmark).
func (c *ReplayCollector) Events() []normalize.AgentEvent { return c.events }

// Run feeds every parsed event to the sink in order.
func (c *ReplayCollector) Run(s Sink) error {
	for _, e := range c.events {
		if _, err := s.Ingest(e); err != nil {
			// A single bad event should not abort a replay; the pipeline counts it.
			continue
		}
	}
	return nil
}
