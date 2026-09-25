package correlate

import "strings"

// Graph patterns are cross-event detections the single-event rule engine
// (backend/detect) cannot express: they match a *shape* in the provenance graph
// rather than fields on one event. They became possible once the agent emitted
// real file and network edges alongside process edges.

// Patterns is the set of graph-pattern detectors the pipeline evaluates on the
// process a new event just touched. Each fires at most once per process.
var Patterns = []func(*Node) (PatternHit, bool){
	DownloadExecBeacon,
	CredentialReadExfil,
	WriteThenSpawnExec,
	DroppedPersistence,
	ConnectionFanout,
}

// fanoutMinDistinct is how many distinct remote hosts one process must connect to
// before it looks like scanning/spraying rather than ordinary multi-host traffic.
// Deliberately conservative: browsers and package managers fan out too, so this
// is a broader, lower-severity signal than the chain patterns.
const fanoutMinDistinct = 20

// PatternHit is a graph-shape match. It carries the same fields the pipeline
// needs to synthesize a correlate.Detection, plus the concrete event ids that
// evidence the shape — so a pattern finding stays as auditable as a rule hit.
type PatternHit struct {
	RuleID      string
	Technique   []string // MITRE ATT&CK ids
	Severity    int      // 1..100
	ProcGUID    string   // the process the finding anchors on
	EventIDs    []string // the exact events that evidence the pattern
	Remediation string
}

// DownloadExecBeacon detects the download → execute → call-home chain centered on
// a process p that just acted: p runs an executable that some write produced, and
// p has made an outbound network connection. In a real drop the downloader
// (e.g. curl) connects and writes the payload first, then the payload is executed
// as a *separate* process and beacons out — so the signal lives on the payload
// process, bridged to the writer through the file node:
//
//	writer --wrote--> imageFile <--executed-- p --connected--> socket
//
// A normal program does not run from an image that another process just wrote,
// which is what keeps this specific and low-noise. Returns the write and connect
// event ids as evidence.
func DownloadExecBeacon(p *Node) (PatternHit, bool) {
	if p == nil || p.Kind != KindProcess {
		return PatternHit{}, false
	}

	// p must have beaconed out (earliest outbound connection).
	var conn *Edge
	for _, e := range p.Out {
		if e.Rel == RelConnected && e.Dst != nil && e.Dst.Kind == KindSocket {
			if conn == nil || e.TS.Before(conn.TS) {
				conn = e
			}
		}
	}
	if conn == nil {
		return PatternHit{}, false
	}

	// the image p is running.
	var image *Node
	for _, e := range p.Out {
		if e.Rel == RelExecuted && e.Dst != nil && e.Dst.Kind == KindFile {
			image = e.Dst
			break
		}
	}
	if image == nil {
		return PatternHit{}, false
	}

	// that image was written by some process (the drop) before it ran.
	var wrote *Edge
	for _, e := range image.In {
		if e.Rel == RelWrote {
			if wrote == nil || e.TS.Before(wrote.TS) {
				wrote = e
			}
		}
	}
	if wrote == nil {
		return PatternHit{}, false
	}

	return PatternHit{
		RuleID:    "download_exec_beacon",
		Technique: []string{"T1105", "T1071"},
		Severity:  85,
		ProcGUID:  p.ID,
		EventIDs:  []string{wrote.EventID, conn.EventID},
		Remediation: "A process is running an executable that another process wrote to disk, and it " +
			"has made an outbound connection — the download → execute → call-home shape of a dropped " +
			"payload. Identify the image path and the destination from the cited events, isolate the " +
			"host, capture the file for analysis before it is deleted, and trace the writer to find how " +
			"the payload arrived (download, extraction, lateral copy).",
	}, true
}

// secretSuffixes are credential/secret files whose read, paired with an outbound
// connection, is a staged-exfiltration signal. Kept aligned with the
// credential_file_read rule's set, plus a few common secret stores.
var secretSuffixes = []string{
	"/.ssh/id_rsa", "/.ssh/id_dsa", "/.ssh/id_ed25519",
	"/.aws/credentials", "/etc/shadow",
	"/.kube/config", "/.docker/config.json", "/.netrc",
}

func isSecretPath(path string) bool {
	for _, s := range secretSuffixes {
		if strings.HasSuffix(path, s) {
			return true
		}
	}
	return false
}

// CredentialReadExfil detects a process that read a credential/secret file and
// then made an outbound network connection — the staged-exfiltration shape:
//
//	p --read--> secretFile   and   p --connected--> socket   (connect at/after read)
//
// Reading a secret is expected for the right tool run by its owner; reading one
// and then talking to the network is the escalation the single-event
// credential_file_read rule cannot see on its own. Returns the read and connect
// event ids as evidence.
func CredentialReadExfil(p *Node) (PatternHit, bool) {
	if p == nil || p.Kind != KindProcess {
		return PatternHit{}, false
	}

	// earliest read of a secret file.
	var read *Edge
	for _, e := range p.Out {
		if e.Rel == RelRead && e.Dst != nil && e.Dst.Kind == KindFile && isSecretPath(e.Dst.Label) {
			if read == nil || e.TS.Before(read.TS) {
				read = e
			}
		}
	}
	if read == nil {
		return PatternHit{}, false
	}

	// earliest outbound connection at or after that read (send-after-read order).
	var conn *Edge
	for _, e := range p.Out {
		if e.Rel == RelConnected && e.Dst != nil && e.Dst.Kind == KindSocket && !e.TS.Before(read.TS) {
			if conn == nil || e.TS.Before(conn.TS) {
				conn = e
			}
		}
	}
	if conn == nil {
		return PatternHit{}, false
	}

	return PatternHit{
		RuleID:    "credential_read_exfil",
		Technique: []string{"T1552.001", "T1041"},
		Severity:  82,
		ProcGUID:  p.ID,
		EventIDs:  []string{read.EventID, conn.EventID},
		Remediation: "A process read a credential or secret file and then made an outbound connection — " +
			"the read → send shape of staged exfiltration. Confirm the reading process and the owner from " +
			"the cited events; if the pairing is unexpected, treat the secret as compromised and rotate it, " +
			"capture the destination for blocking, and review what else the process touched.",
	}, true
}

// WriteThenSpawnExec detects a process p whose executable was written by its own
// parent, which then spawned it — the drop-and-run shape where one process writes
// a tool to disk and directly executes it as a child:
//
//	parent --wrote--> imageFile <--executed-- p ,  parent --spawned--> p
//
// It needs only process, file-write and spawn edges (no network), so it catches a
// dropped tool the moment it runs, before any beacon. Tying the writer to the
// parent that launched it is what separates this from ordinary build-and-run:
// the same process wrote the binary and chose to execute it. Returns the write
// and spawn (exec) event ids as evidence.
func WriteThenSpawnExec(p *Node) (PatternHit, bool) {
	if p == nil || p.Kind != KindProcess {
		return PatternHit{}, false
	}

	// the image p runs.
	var image *Node
	for _, e := range p.Out {
		if e.Rel == RelExecuted && e.Dst != nil && e.Dst.Kind == KindFile {
			image = e.Dst
			break
		}
	}
	if image == nil {
		return PatternHit{}, false
	}

	// the parent that spawned p.
	var parent *Node
	var spawn *Edge
	for _, e := range p.In {
		if e.Rel == RelSpawned && e.Src != nil && e.Src.Kind == KindProcess {
			parent = e.Src
			spawn = e
			break
		}
	}
	if parent == nil {
		return PatternHit{}, false
	}

	// that same parent wrote p's image.
	var wrote *Edge
	for _, e := range image.In {
		if e.Rel == RelWrote && e.Src == parent {
			if wrote == nil || e.TS.Before(wrote.TS) {
				wrote = e
			}
		}
	}
	if wrote == nil {
		return PatternHit{}, false
	}

	return PatternHit{
		RuleID:    "drop_and_spawn",
		Technique: []string{"T1105", "T1059"},
		Severity:  78,
		ProcGUID:  p.ID,
		EventIDs:  []string{wrote.EventID, spawn.EventID},
		Remediation: "A process wrote an executable to disk and then spawned it directly — a tool " +
			"dropped and run in one step. Identify the image path and the parent from the cited events, " +
			"capture the file before it is removed, and treat the parent as the thing to investigate: " +
			"legitimate software rarely writes a binary and immediately executes its own drop.",
	}, true
}

// persistenceSubstrings / persistenceSuffixes are locations a foothold is
// installed for survival across reboots/logins: cron, systemd units, init and
// profile scripts, shell rc files, and authorized_keys.
var persistenceSubstrings = []string{
	"/etc/cron", "/var/spool/cron/", "/etc/systemd/system/", "/lib/systemd/system/",
	"/.config/systemd/user/", "/etc/init.d/", "/etc/profile.d/",
}
var persistenceSuffixes = []string{
	"/etc/rc.local", "/.bashrc", "/.bash_profile", "/.bash_login", "/.profile",
	"/.zshrc", "/.ssh/authorized_keys",
}

func isPersistencePath(path string) bool {
	for _, s := range persistenceSubstrings {
		if strings.Contains(path, s) {
			return true
		}
	}
	for _, s := range persistenceSuffixes {
		if strings.HasSuffix(path, s) {
			return true
		}
	}
	return false
}

// DroppedPersistence detects a dropped executable establishing persistence: a
// process p runs an image that another process wrote (the drop), and p itself
// writes to a known persistence location (cron, systemd unit, rc/profile script,
// authorized_keys):
//
//	writer --wrote--> image <--executed-- p --wrote--> persistenceFile
//
// The drop precondition is what keeps it specific — a package manager writing a
// systemd unit runs from its own packaged binary, not one another process just
// dropped. T1547 (boot/logon autostart) + T1053.003 (cron). Returns the drop and
// the persistence-write event ids as evidence.
func DroppedPersistence(p *Node) (PatternHit, bool) {
	if p == nil || p.Kind != KindProcess {
		return PatternHit{}, false
	}

	// p runs a dropped image.
	var image *Node
	for _, e := range p.Out {
		if e.Rel == RelExecuted && e.Dst != nil && e.Dst.Kind == KindFile {
			image = e.Dst
			break
		}
	}
	if image == nil {
		return PatternHit{}, false
	}
	var dropped *Edge
	for _, e := range image.In {
		if e.Rel == RelWrote {
			if dropped == nil || e.TS.Before(dropped.TS) {
				dropped = e
			}
		}
	}
	if dropped == nil {
		return PatternHit{}, false
	}

	// p writes to a persistence location.
	var persist *Edge
	for _, e := range p.Out {
		if e.Rel == RelWrote && e.Dst != nil && e.Dst.Kind == KindFile && isPersistencePath(e.Dst.Label) {
			if persist == nil || e.TS.Before(persist.TS) {
				persist = e
			}
		}
	}
	if persist == nil {
		return PatternHit{}, false
	}

	return PatternHit{
		RuleID:    "dropped_persistence",
		Technique: []string{"T1547", "T1053.003"},
		Severity:  84,
		ProcGUID:  p.ID,
		EventIDs:  []string{dropped.EventID, persist.EventID},
		Remediation: "A process running an image another process dropped wrote to a persistence " +
			"location (cron, systemd unit, rc/profile script, or authorized_keys). Read the persistence " +
			"file from the cited event and remove the unrecognized entry, capture the dropped image, and " +
			"trace the writer — a foothold that survives reboots is being installed.",
	}, true
}

// ConnectionFanout detects one process connecting out to many distinct remote
// hosts — the breadth signature of host discovery, port sweeping across a subnet,
// or credential/exploit spraying. Unlike the chain patterns this is structural: it
// counts the process's distinct outbound socket destinations (by address, so a
// sweep of one port across many hosts and many ports on shifting hosts both
// count). Cites the earliest and latest connect as evidence.
func ConnectionFanout(p *Node) (PatternHit, bool) {
	if p == nil || p.Kind != KindProcess {
		return PatternHit{}, false
	}
	addrs := map[string]bool{}
	var first, last *Edge
	for _, e := range p.Out {
		if e.Rel != RelConnected || e.Dst == nil || e.Dst.Kind != KindSocket {
			continue
		}
		addr := e.Dst.Label // "addr:port"; split on the LAST colon so IPv6 survives
		if i := strings.LastIndex(addr, ":"); i >= 0 {
			addr = addr[:i]
		}
		addrs[addr] = true
		if first == nil || e.TS.Before(first.TS) {
			first = e
		}
		if last == nil || e.TS.After(last.TS) {
			last = e
		}
	}
	if len(addrs) < fanoutMinDistinct {
		return PatternHit{}, false
	}
	evs := []string{first.EventID}
	if last.EventID != first.EventID {
		evs = append(evs, last.EventID)
	}
	return PatternHit{
		RuleID:    "connection_fanout",
		Technique: []string{"T1046"},
		Severity:  70,
		ProcGUID:  p.ID,
		EventIDs:  evs,
		Remediation: "One process connected to many distinct remote hosts in a short span — the " +
			"breadth of host discovery, subnet sweeping, or spraying. Confirm the process is an expected " +
			"scanner/updater run by the right user; if not, capture the destination list from its edges to " +
			"scope what it probed, and treat the host as potentially compromised or misused.",
	}, true
}
