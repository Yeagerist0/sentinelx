// Package detect is the deterministic, LLM-free rule engine. Rules are
// detection-as-code (JSON under /rules), versioned and testable. A rule matches
// a single normalized event; multi-event behavior is the correlation engine's
// job, not the detector's.
package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"sentinelx/backend/correlate"
)

// Rule is one detection, loaded from a .json file in /rules.
type Rule struct {
	ID              string   `json:"id"`
	Version         string   `json:"version"`
	Technique       []string `json:"technique"`
	Severity        int      `json:"severity"`
	EventType       string   `json:"event_type"`       // matches correlate.EventType
	ImageRegex      string   `json:"image_regex"`      // matches ProcImage
	CmdlineRegex    string   `json:"cmdline_regex"`    // matches Cmdline
	CmdlineContains []string `json:"cmdline_contains"` // all substrings must be present
	PathPrefix      string   `json:"path_prefix"`      // ProcImage prefix (e.g. /tmp/)
}

type compiled struct {
	Rule
	imageRe *regexp.Regexp
	cmdRe   *regexp.Regexp
}

// Engine evaluates rules against events and assigns unique detection ids.
type Engine struct {
	mu     sync.Mutex
	rules  []compiled
	nextID int64
}

// NewEngine compiles a set of rules.
func NewEngine(rs []Rule) (*Engine, error) {
	e := &Engine{}
	for _, r := range rs {
		c := compiled{Rule: r}
		if r.ImageRegex != "" {
			re, err := regexp.Compile(r.ImageRegex)
			if err != nil {
				return nil, fmt.Errorf("rule %s image_regex: %w", r.ID, err)
			}
			c.imageRe = re
		}
		if r.CmdlineRegex != "" {
			re, err := regexp.Compile(r.CmdlineRegex)
			if err != nil {
				return nil, fmt.Errorf("rule %s cmdline_regex: %w", r.ID, err)
			}
			c.cmdRe = re
		}
		e.rules = append(e.rules, c)
	}
	return e, nil
}

// Load reads every *.json rule file in dir and compiles them.
func Load(dir string) (*Engine, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	var rs []Rule
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var r Rule
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		rs = append(rs, r)
	}
	return NewEngine(rs)
}

// Eval returns every detection the event triggers.
func (e *Engine) Eval(ev correlate.Event) []correlate.Detection {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []correlate.Detection
	for _, r := range e.rules {
		if !r.match(ev) {
			continue
		}
		e.nextID++
		out = append(out, correlate.Detection{
			ID:        e.nextID,
			RuleID:    r.ID,
			RuleVer:   r.Version,
			HostID:    ev.HostID,
			ProcGUID:  ev.ProcGUID,
			EventIDs:  []string{ev.ID},
			Technique: r.Technique,
			Severity:  r.Severity,
			TS:        ev.TS,
			DedupKey:  r.ID + "|" + ev.ProcGUID,
		})
	}
	return out
}

// Techniques returns the distinct MITRE techniques the ruleset covers (feeds the
// CI coverage report).
func (e *Engine) Techniques() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range e.rules {
		for _, t := range r.Technique {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

func (r compiled) match(ev correlate.Event) bool {
	if r.EventType != "" && string(ev.Type) != r.EventType {
		return false
	}
	if r.imageRe != nil && !r.imageRe.MatchString(ev.ProcImage) {
		return false
	}
	if r.PathPrefix != "" && !strings.HasPrefix(ev.ProcImage, r.PathPrefix) {
		return false
	}
	for _, s := range r.CmdlineContains {
		if !strings.Contains(ev.Cmdline, s) {
			return false
		}
	}
	if r.cmdRe != nil && !r.cmdRe.MatchString(ev.Cmdline) {
		return false
	}
	return true
}

// Default returns the built-in v1 ruleset in code — identical to /rules/*.json —
// so tests and the demo run without a rules directory on disk.
func Default() []Rule {
	return []Rule{
		{
			ID: "lolbin_curl_download", Version: "1", Technique: []string{"T1105"}, Severity: 65,
			EventType: "process_start", ImageRegex: `(curl|wget)$`, CmdlineContains: []string{"http"},
		},
		{
			ID: "chmod_then_exec", Version: "1", Technique: []string{"T1222.002"}, Severity: 55,
			EventType: "process_start", ImageRegex: `chmod$`, CmdlineContains: []string{"+x"},
		},
		{
			ID: "exec_from_tmp", Version: "1", Technique: []string{"T1204.002", "T1059.004"}, Severity: 70,
			EventType: "process_start", PathPrefix: "/tmp/",
		},
	}
}
