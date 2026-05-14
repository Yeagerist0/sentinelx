package detect

import (
	"testing"
	"time"

	"sentinelx/backend/correlate"
)

func mkEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(Default())
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	return e
}

func TestRulesFireExpected(t *testing.T) {
	e := mkEngine(t)
	cases := []struct {
		name string
		ev   correlate.Event
		want string // expected rule id, "" = none
	}{
		{"curl download", correlate.Event{ID: "1", Type: correlate.ProcessStart, ProcImage: "/usr/bin/curl", Cmdline: "/usr/bin/curl http://x/y -o /tmp/z"}, "lolbin_curl_download"},
		{"wget download", correlate.Event{ID: "2", Type: correlate.ProcessStart, ProcImage: "/usr/bin/wget", Cmdline: "/usr/bin/wget http://x/y"}, "lolbin_curl_download"},
		{"chmod +x", correlate.Event{ID: "3", Type: correlate.ProcessStart, ProcImage: "/usr/bin/chmod", Cmdline: "/usr/bin/chmod +x /tmp/z"}, "chmod_then_exec"},
		{"exec from tmp", correlate.Event{ID: "4", Type: correlate.ProcessStart, ProcImage: "/tmp/payload"}, "exec_from_tmp"},
		{"benign ls", correlate.Event{ID: "5", Type: correlate.ProcessStart, ProcImage: "/usr/bin/ls", Cmdline: "/usr/bin/ls -la"}, ""},
		{"curl but not exec event", correlate.Event{ID: "6", Type: correlate.NetConnect, ProcImage: "/usr/bin/curl"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := e.Eval(c.ev)
			if c.want == "" {
				if len(got) != 0 {
					t.Fatalf("expected no detection, got %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].RuleID != c.want {
				t.Fatalf("want rule %s, got %+v", c.want, got)
			}
			if len(got[0].Technique) == 0 || got[0].EventIDs[0] != c.ev.ID {
				t.Fatalf("detection missing technique/eventid: %+v", got[0])
			}
		})
	}
}

func TestDetectionIDsUnique(t *testing.T) {
	e := mkEngine(t)
	seen := map[int64]bool{}
	for i := 0; i < 5; i++ {
		for _, d := range e.Eval(correlate.Event{ID: "x", Type: correlate.ProcessStart, ProcImage: "/tmp/p", TS: time.Now()}) {
			if seen[d.ID] {
				t.Fatalf("duplicate detection id %d", d.ID)
			}
			seen[d.ID] = true
		}
	}
}

func TestTechniqueCoverage(t *testing.T) {
	e := mkEngine(t)
	techs := e.Techniques()
	if len(techs) < 4 {
		t.Fatalf("expected >=4 techniques covered, got %v", techs)
	}
}
