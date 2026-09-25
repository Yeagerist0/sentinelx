package correlate

import (
	"testing"
	"time"
)

// buildDropChain wires the canonical download → execute → beacon chain into a
// real graph (via AddEvent, not by hand) and returns it:
//
//	curl connects out, writes /tmp/payload; payload is executed and beacons.
func buildDropChain(t *testing.T) *Graph {
	t.Helper()
	g := NewGraph("web-01", NewBaseline(), DefaultParams().HubDegree)
	base := time.Unix(1700000000, 0)
	ev := func(i int, typ EventType, guid, parent, image, path, raddr string, rport int) Event {
		return Event{
			ID: string(rune('a' + i)), HostID: "web-01", TS: base.Add(time.Duration(i) * time.Second),
			Type: typ, ProcGUID: guid, ParentGUID: parent, ProcImage: image,
			FilePath: path, RemoteAddr: raddr, RemotePort: rport,
		}
	}
	g.AddEvent(ev(0, ProcessStart, "curl", "bash", "/usr/bin/curl", "", "", 0))
	g.AddEvent(ev(1, NetConnect, "curl", "", "/usr/bin/curl", "", "203.0.113.5", 80))
	g.AddEvent(ev(2, FileWrite, "curl", "", "/usr/bin/curl", "/tmp/payload", "", 0))
	g.AddEvent(ev(3, ProcessStart, "payload", "bash", "/tmp/payload", "", "", 0))
	g.AddEvent(ev(4, NetConnect, "payload", "", "/tmp/payload", "", "203.0.113.5", 4444))
	return g
}

func TestDownloadExecBeacon_FiresOnPayload(t *testing.T) {
	g := buildDropChain(t)

	hit, ok := DownloadExecBeacon(g.Node("payload"))
	if !ok {
		t.Fatal("expected download_exec_beacon to fire on the payload process")
	}
	if hit.RuleID != "download_exec_beacon" {
		t.Errorf("RuleID = %q", hit.RuleID)
	}
	if hit.ProcGUID != "payload" {
		t.Errorf("ProcGUID = %q, want payload", hit.ProcGUID)
	}
	// evidence must cite the write (event "c", i=2) and the beacon (event "e", i=4).
	if len(hit.EventIDs) != 2 || hit.EventIDs[0] != "c" || hit.EventIDs[1] != "e" {
		t.Errorf("EventIDs = %v, want [c e] (write, beacon)", hit.EventIDs)
	}
}

func TestDownloadExecBeacon_NotOnDownloader(t *testing.T) {
	g := buildDropChain(t)
	// curl connected and wrote a file, but nobody wrote curl's own image, so the
	// download→exec→beacon shape does not apply to it.
	if _, ok := DownloadExecBeacon(g.Node("curl")); ok {
		t.Error("download_exec_beacon must not fire on the downloader itself")
	}
}

func TestDownloadExecBeacon_NoBeaconNoHit(t *testing.T) {
	g := NewGraph("web-01", NewBaseline(), DefaultParams().HubDegree)
	base := time.Unix(1700000000, 0)
	// curl writes /tmp/payload, payload runs — but never connects out.
	g.AddEvent(Event{ID: "1", HostID: "web-01", TS: base, Type: FileWrite,
		ProcGUID: "curl", ProcImage: "/usr/bin/curl", FilePath: "/tmp/payload"})
	g.AddEvent(Event{ID: "2", HostID: "web-01", TS: base.Add(time.Second), Type: ProcessStart,
		ProcGUID: "payload", ProcImage: "/tmp/payload"})

	if _, ok := DownloadExecBeacon(g.Node("payload")); ok {
		t.Error("must not fire without an outbound connection")
	}
}

func TestDownloadExecBeacon_NoDropNoHit(t *testing.T) {
	g := NewGraph("web-01", NewBaseline(), DefaultParams().HubDegree)
	base := time.Unix(1700000000, 0)
	// a normal process runs its packaged binary and connects out — nobody wrote
	// its image, so this is not a dropped payload.
	g.AddEvent(Event{ID: "1", HostID: "web-01", TS: base, Type: ProcessStart,
		ProcGUID: "app", ProcImage: "/usr/bin/app"})
	g.AddEvent(Event{ID: "2", HostID: "web-01", TS: base.Add(time.Second), Type: NetConnect,
		ProcGUID: "app", ProcImage: "/usr/bin/app", RemoteAddr: "203.0.113.5", RemotePort: 443})

	if _, ok := DownloadExecBeacon(g.Node("app")); ok {
		t.Error("must not fire when the running image was not written by another process")
	}
}

// buildExfilChain wires a read-secret → connect-out chain into a real graph.
func buildExfilChain(t *testing.T, secretPath string) *Graph {
	t.Helper()
	g := NewGraph("web-01", NewBaseline(), DefaultParams().HubDegree)
	base := time.Unix(1700000000, 0)
	g.AddEvent(Event{ID: "1", HostID: "web-01", TS: base, Type: ProcessStart,
		ProcGUID: "curl", ProcImage: "/usr/bin/curl"})
	g.AddEvent(Event{ID: "2", HostID: "web-01", TS: base.Add(time.Second), Type: FileRead,
		ProcGUID: "curl", ProcImage: "/usr/bin/curl", FilePath: secretPath})
	g.AddEvent(Event{ID: "3", HostID: "web-01", TS: base.Add(2 * time.Second), Type: NetConnect,
		ProcGUID: "curl", ProcImage: "/usr/bin/curl", RemoteAddr: "203.0.113.9", RemotePort: 443})
	return g
}

func TestCredentialReadExfil_Fires(t *testing.T) {
	g := buildExfilChain(t, "/home/alice/.ssh/id_rsa")
	hit, ok := CredentialReadExfil(g.Node("curl"))
	if !ok {
		t.Fatal("expected credential_read_exfil to fire on read-secret → connect")
	}
	if hit.RuleID != "credential_read_exfil" {
		t.Errorf("RuleID = %q", hit.RuleID)
	}
	if len(hit.EventIDs) != 2 || hit.EventIDs[0] != "2" || hit.EventIDs[1] != "3" {
		t.Errorf("EventIDs = %v, want [2 3] (read, connect)", hit.EventIDs)
	}
}

func TestCredentialReadExfil_AwsAndKube(t *testing.T) {
	for _, p := range []string{"/root/.aws/credentials", "/home/bob/.kube/config", "/etc/shadow"} {
		if _, ok := CredentialReadExfil(buildExfilChain(t, p).Node("curl")); !ok {
			t.Errorf("expected fire for secret path %q", p)
		}
	}
}

func TestCredentialReadExfil_NonSecretNoHit(t *testing.T) {
	// reading an ordinary file then connecting out is not exfil.
	if _, ok := CredentialReadExfil(buildExfilChain(t, "/var/log/app.log").Node("curl")); ok {
		t.Error("must not fire on a non-secret file read")
	}
}

func TestCredentialReadExfil_ConnectBeforeReadNoHit(t *testing.T) {
	// a connection strictly before the secret read is not the read → send shape.
	g := NewGraph("web-01", NewBaseline(), DefaultParams().HubDegree)
	base := time.Unix(1700000000, 0)
	g.AddEvent(Event{ID: "1", HostID: "web-01", TS: base, Type: ProcessStart,
		ProcGUID: "p", ProcImage: "/usr/bin/app"})
	g.AddEvent(Event{ID: "2", HostID: "web-01", TS: base.Add(time.Second), Type: NetConnect,
		ProcGUID: "p", ProcImage: "/usr/bin/app", RemoteAddr: "203.0.113.9", RemotePort: 443})
	g.AddEvent(Event{ID: "3", HostID: "web-01", TS: base.Add(2 * time.Second), Type: FileRead,
		ProcGUID: "p", ProcImage: "/usr/bin/app", FilePath: "/home/alice/.ssh/id_rsa"})
	if _, ok := CredentialReadExfil(g.Node("p")); ok {
		t.Error("must not fire when the only connection preceded the secret read")
	}
}

func TestWriteThenSpawnExec_Fires(t *testing.T) {
	g := NewGraph("web-01", NewBaseline(), DefaultParams().HubDegree)
	base := time.Unix(1700000000, 0)
	// dropper writes /tmp/tool, then spawns a child that runs it.
	g.AddEvent(Event{ID: "1", HostID: "web-01", TS: base, Type: ProcessStart,
		ProcGUID: "dropper", ProcImage: "/usr/bin/dropper"})
	g.AddEvent(Event{ID: "2", HostID: "web-01", TS: base.Add(time.Second), Type: FileWrite,
		ProcGUID: "dropper", ProcImage: "/usr/bin/dropper", FilePath: "/tmp/tool"})
	g.AddEvent(Event{ID: "3", HostID: "web-01", TS: base.Add(2 * time.Second), Type: ProcessStart,
		ProcGUID: "child", ParentGUID: "dropper", ProcImage: "/tmp/tool"})

	hit, ok := WriteThenSpawnExec(g.Node("child"))
	if !ok {
		t.Fatal("expected drop_and_spawn to fire when the parent wrote the child's image")
	}
	if hit.RuleID != "drop_and_spawn" {
		t.Errorf("RuleID = %q", hit.RuleID)
	}
	if len(hit.EventIDs) != 2 || hit.EventIDs[0] != "2" || hit.EventIDs[1] != "3" {
		t.Errorf("EventIDs = %v, want [2 3] (write, spawn)", hit.EventIDs)
	}
}

func TestWriteThenSpawnExec_DifferentWriterNoHit(t *testing.T) {
	// the curl_lolbin shape: curl writes /tmp/payload, but bash (not curl) spawns
	// the payload — the writer is not the parent, so drop_and_spawn must not fire.
	g := NewGraph("web-01", NewBaseline(), DefaultParams().HubDegree)
	base := time.Unix(1700000000, 0)
	g.AddEvent(Event{ID: "1", HostID: "web-01", TS: base, Type: ProcessStart,
		ProcGUID: "curl", ParentGUID: "bash", ProcImage: "/usr/bin/curl"})
	g.AddEvent(Event{ID: "2", HostID: "web-01", TS: base.Add(time.Second), Type: FileWrite,
		ProcGUID: "curl", ProcImage: "/usr/bin/curl", FilePath: "/tmp/payload"})
	g.AddEvent(Event{ID: "3", HostID: "web-01", TS: base.Add(2 * time.Second), Type: ProcessStart,
		ProcGUID: "payload", ParentGUID: "bash", ProcImage: "/tmp/payload"})

	if _, ok := WriteThenSpawnExec(g.Node("payload")); ok {
		t.Error("must not fire when the writer is not the spawning parent")
	}
}

func TestWriteThenSpawnExec_NoWriteNoHit(t *testing.T) {
	// parent spawns a child running a packaged binary nobody wrote.
	g := NewGraph("web-01", NewBaseline(), DefaultParams().HubDegree)
	base := time.Unix(1700000000, 0)
	g.AddEvent(Event{ID: "1", HostID: "web-01", TS: base, Type: ProcessStart,
		ProcGUID: "sh", ProcImage: "/bin/sh"})
	g.AddEvent(Event{ID: "2", HostID: "web-01", TS: base.Add(time.Second), Type: ProcessStart,
		ProcGUID: "ls", ParentGUID: "sh", ProcImage: "/usr/bin/ls"})
	if _, ok := WriteThenSpawnExec(g.Node("ls")); ok {
		t.Error("must not fire without a parent-written image")
	}
}

func TestDroppedPersistence_Fires(t *testing.T) {
	g := NewGraph("web-01", NewBaseline(), DefaultParams().HubDegree)
	base := time.Unix(1700000000, 0)
	// writer drops /tmp/tool; tool runs and writes a cron entry.
	g.AddEvent(Event{ID: "1", HostID: "web-01", TS: base, Type: FileWrite,
		ProcGUID: "writer", ProcImage: "/usr/bin/writer", FilePath: "/tmp/tool"})
	g.AddEvent(Event{ID: "2", HostID: "web-01", TS: base.Add(time.Second), Type: ProcessStart,
		ProcGUID: "tool", ProcImage: "/tmp/tool"})
	g.AddEvent(Event{ID: "3", HostID: "web-01", TS: base.Add(2 * time.Second), Type: FileWrite,
		ProcGUID: "tool", ProcImage: "/tmp/tool", FilePath: "/etc/cron.d/evil"})

	hit, ok := DroppedPersistence(g.Node("tool"))
	if !ok {
		t.Fatal("expected dropped_persistence to fire on drop → persistence write")
	}
	if hit.RuleID != "dropped_persistence" {
		t.Errorf("RuleID = %q", hit.RuleID)
	}
	if len(hit.EventIDs) != 2 || hit.EventIDs[0] != "1" || hit.EventIDs[1] != "3" {
		t.Errorf("EventIDs = %v, want [1 3] (drop, persistence write)", hit.EventIDs)
	}
}

func TestDroppedPersistence_PersistencePaths(t *testing.T) {
	for _, p := range []string{
		"/etc/systemd/system/evil.service", "/home/bob/.bashrc",
		"/home/bob/.ssh/authorized_keys", "/etc/rc.local", "/etc/cron.daily/x",
	} {
		g := NewGraph("web-01", NewBaseline(), DefaultParams().HubDegree)
		base := time.Unix(1700000000, 0)
		g.AddEvent(Event{ID: "1", HostID: "web-01", TS: base, Type: FileWrite,
			ProcGUID: "w", ProcImage: "/usr/bin/w", FilePath: "/tmp/tool"})
		g.AddEvent(Event{ID: "2", HostID: "web-01", TS: base.Add(time.Second), Type: ProcessStart,
			ProcGUID: "tool", ProcImage: "/tmp/tool"})
		g.AddEvent(Event{ID: "3", HostID: "web-01", TS: base.Add(2 * time.Second), Type: FileWrite,
			ProcGUID: "tool", ProcImage: "/tmp/tool", FilePath: p})
		if _, ok := DroppedPersistence(g.Node("tool")); !ok {
			t.Errorf("expected fire for persistence path %q", p)
		}
	}
}

func TestDroppedPersistence_NotDroppedNoHit(t *testing.T) {
	// a packaged binary (nobody wrote its image) writes a systemd unit — normal
	// install activity, not a dropped foothold.
	g := NewGraph("web-01", NewBaseline(), DefaultParams().HubDegree)
	base := time.Unix(1700000000, 0)
	g.AddEvent(Event{ID: "1", HostID: "web-01", TS: base, Type: ProcessStart,
		ProcGUID: "apt", ProcImage: "/usr/bin/apt"})
	g.AddEvent(Event{ID: "2", HostID: "web-01", TS: base.Add(time.Second), Type: FileWrite,
		ProcGUID: "apt", ProcImage: "/usr/bin/apt", FilePath: "/etc/systemd/system/foo.service"})
	if _, ok := DroppedPersistence(g.Node("apt")); ok {
		t.Error("must not fire when the running image was not dropped")
	}
}

func TestConnectionFanout_Fires(t *testing.T) {
	g := NewGraph("web-01", NewBaseline(), DefaultParams().HubDegree)
	base := time.Unix(1700000000, 0)
	g.AddEvent(Event{ID: "p", HostID: "web-01", TS: base, Type: ProcessStart,
		ProcGUID: "scan", ProcImage: "/usr/bin/scan"})
	for i := 0; i < fanoutMinDistinct; i++ {
		g.AddEvent(Event{ID: "c" + string(rune('A'+i)), HostID: "web-01", TS: base.Add(time.Duration(i) * time.Millisecond),
			Type: NetConnect, ProcGUID: "scan", ProcImage: "/usr/bin/scan",
			RemoteAddr: "203.0.113." + itoa(i), RemotePort: 445})
	}
	hit, ok := ConnectionFanout(g.Node("scan"))
	if !ok {
		t.Fatalf("expected connection_fanout to fire on %d distinct hosts", fanoutMinDistinct)
	}
	if hit.RuleID != "connection_fanout" || len(hit.EventIDs) != 2 {
		t.Errorf("hit = %+v", hit)
	}
}

func TestConnectionFanout_BelowThresholdNoHit(t *testing.T) {
	g := NewGraph("web-01", NewBaseline(), DefaultParams().HubDegree)
	base := time.Unix(1700000000, 0)
	g.AddEvent(Event{ID: "p", HostID: "web-01", TS: base, Type: ProcessStart,
		ProcGUID: "app", ProcImage: "/usr/bin/app"})
	for i := 0; i < fanoutMinDistinct-1; i++ {
		g.AddEvent(Event{ID: "c" + itoa(i), HostID: "web-01", TS: base.Add(time.Duration(i) * time.Millisecond),
			Type: NetConnect, ProcGUID: "app", ProcImage: "/usr/bin/app",
			RemoteAddr: "203.0.113." + itoa(i), RemotePort: 443})
	}
	if _, ok := ConnectionFanout(g.Node("app")); ok {
		t.Errorf("must not fire below %d distinct hosts", fanoutMinDistinct)
	}
}

func TestConnectionFanout_SameHostManyPortsNoHit(t *testing.T) {
	// many connections to ONE host on different ports is not host fan-out.
	g := NewGraph("web-01", NewBaseline(), DefaultParams().HubDegree)
	base := time.Unix(1700000000, 0)
	g.AddEvent(Event{ID: "p", HostID: "web-01", TS: base, Type: ProcessStart,
		ProcGUID: "app", ProcImage: "/usr/bin/app"})
	for i := 0; i < fanoutMinDistinct+5; i++ {
		g.AddEvent(Event{ID: "c" + itoa(i), HostID: "web-01", TS: base.Add(time.Duration(i) * time.Millisecond),
			Type: NetConnect, ProcGUID: "app", ProcImage: "/usr/bin/app",
			RemoteAddr: "203.0.113.9", RemotePort: 1000 + i})
	}
	if _, ok := ConnectionFanout(g.Node("app")); ok {
		t.Error("must not fire for many ports on a single host (one distinct address)")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}
