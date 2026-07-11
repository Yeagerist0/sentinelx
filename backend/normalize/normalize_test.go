package normalize

import (
	"testing"

	"sentinelx/backend/correlate"
)

func TestProcGUIDStableAndDistinct(t *testing.T) {
	a := ProcGUID("boot", 100, 12345)
	b := ProcGUID("boot", 100, 12345)
	c := ProcGUID("boot", 100, 12346) // different start time = different process
	if a != b {
		t.Fatal("ProcGUID not stable for same inputs")
	}
	if a == c {
		t.Fatal("ProcGUID collided across different start times (pid reuse would merge)")
	}
}

func TestNormalizeMapsKindsAndObjects(t *testing.T) {
	cases := []struct {
		kind     string
		wantType correlate.EventType
	}{
		{"exec", correlate.ProcessStart},
		{"file.write", correlate.FileWrite},
		{"net.connect", correlate.NetConnect},
		{"dns", correlate.DNSQuery},
		{"module.load", correlate.ModuleLoad},
	}
	for _, c := range cases {
		ev, err := Normalize(AgentEvent{ID: "1", HostID: "h", BootID: "b", Kind: c.kind, PID: 1, Exe: "/x"})
		if err != nil {
			t.Fatalf("%s: %v", c.kind, err)
		}
		if ev.Type != c.wantType {
			t.Fatalf("%s -> %s, want %s", c.kind, ev.Type, c.wantType)
		}
	}
}

func TestNormalizeUnknownKind(t *testing.T) {
	if _, err := Normalize(AgentEvent{Kind: "bogus"}); err == nil {
		t.Fatal("expected error for unknown kind (schema-drift signal)")
	}
}

func TestNormalizeParentAndDerivedID(t *testing.T) {
	ev, err := Normalize(AgentEvent{HostID: "h", BootID: "b", Kind: "exec", PID: 5, StartTicks: 1, PPID: 2, ParentStartTicks: 3, Exe: "/bin/sh", Args: "-c id"})
	if err != nil {
		t.Fatal(err)
	}
	if ev.ID == "" {
		t.Fatal("expected derived event id when agent omits one")
	}
	if ev.ParentGUID == "" {
		t.Fatal("expected parent guid when ppid>0")
	}
	if ev.Cmdline != "/bin/sh -c id" {
		t.Fatalf("cmdline = %q", ev.Cmdline)
	}
}
