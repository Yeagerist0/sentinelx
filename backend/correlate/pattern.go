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
}

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
