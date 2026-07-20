package collect

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"sentinelx/backend/normalize"
)

func TestReplayParsesArrayAndJSONL(t *testing.T) {
	arr := `[{"id":"1","kind":"exec","host_id":"h","pid":1,"exe":"/a"},{"id":"2","kind":"exit","host_id":"h","pid":1}]`
	c, err := NewReplayCollector(strings.NewReader(arr))
	if err != nil || len(c.Events()) != 2 {
		t.Fatalf("array parse failed: %v n=%d", err, len(c.Events()))
	}
	jsonl := `{"id":"1","kind":"exec","host_id":"h","pid":1,"exe":"/a"}
{"id":"2","kind":"exit","host_id":"h","pid":1}`
	c2, err := NewReplayCollector(strings.NewReader(jsonl))
	if err != nil || len(c2.Events()) != 2 {
		t.Fatalf("jsonl parse failed: %v n=%d", err, len(c2.Events()))
	}
}

type countSink struct {
	n       int
	tenants []string
}

func (s *countSink) Ingest(tenantID string, _ normalize.AgentEvent) ([]int64, error) {
	s.n++
	s.tenants = append(s.tenants, tenantID)
	return nil, nil
}

func TestReplayRunFeedsSink(t *testing.T) {
	c, _ := NewReplayCollector(strings.NewReader(`[{"id":"1","kind":"exec","host_id":"h","pid":1,"exe":"/a"}]`))
	s := &countSink{}
	if err := c.Run("acme", s); err != nil || s.n != 1 {
		t.Fatalf("run: err=%v n=%d", err, s.n)
	}
	if s.tenants[0] != "acme" {
		t.Fatalf("tenant not threaded through: got %q", s.tenants[0])
	}
}

// The /proc collector must observe this very test process on a real Linux host.
func TestProcCollectorSeesSelf(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc on this platform")
	}
	pc := NewProcCollector("test-host")
	snap, err := pc.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(snap) == 0 {
		t.Fatal("expected at least one process")
	}
	self := "proc-" + strconv.Itoa(os.Getpid())
	found := false
	for _, e := range snap {
		if e.ID == self {
			found = true
			if e.Kind != "exec" || e.PID != os.Getpid() {
				t.Fatalf("self event malformed: %+v", e)
			}
		}
	}
	if !found {
		t.Fatalf("current process %s not in snapshot", self)
	}
}
