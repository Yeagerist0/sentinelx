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
