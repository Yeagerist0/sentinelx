// Package normalize converts OS-specific agent telemetry into the canonical
// correlate.Event. v1 targets a Linux eBPF agent; the Windows ETW/Sysmon agent
// produces the same AgentEvent shape, so only this package is OS-aware.
package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"sentinelx/backend/correlate"
)

// AgentEvent is the wire format the agent streams over mTLS. Fields are a
// superset; only those relevant to Kind are populated.
type AgentEvent struct {
	ID               string `json:"id"`     // agent-assigned, monotonic per host (also drives gap detection)
	Schema           string `json:"schema"` // e.g. "sentinelx.agent.v1"
	HostID           string `json:"host_id"`
	BootID           string `json:"boot_id"` // /proc/sys/kernel/random/boot_id  [VERIFY]
	TSUnixNs         int64  `json:"ts_unix_ns"`
	Kind             string `json:"kind"` // exec|exit|file.write|file.read|net.connect|dns|module.load
	PID              int    `json:"pid"`
	StartTicks       int64  `json:"start_ticks"` // task start time; part of the stable process key  [VERIFY field]
	PPID             int    `json:"ppid"`
	ParentStartTicks int64  `json:"parent_start_ticks"`
	Comm             string `json:"comm"`
	Exe              string `json:"exe"`
	Args             string `json:"args"`
	Path             string `json:"path"`
	RAddr            string `json:"raddr"`
	RPort            int    `json:"rport"`
	DNSName          string `json:"dns_name"`
}

var kindMap = map[string]correlate.EventType{
	"exec":        correlate.ProcessStart,
	"exit":        correlate.ProcessStop,
	"file.write":  correlate.FileWrite,
	"file.read":   correlate.FileRead,
	"net.connect": correlate.NetConnect,
	"dns":         correlate.DNSQuery,
	"module.load": correlate.ModuleLoad,
}

// ProcGUID synthesizes the stable process key Linux lacks natively:
// hash(boot_id, pid, start_time). Windows agents pass Sysmon ProcessGuid as the
// BootID+PID+StartTicks tuple degenerates to the same 16-hex-char key.
func ProcGUID(bootID string, pid int, startTicks int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", bootID, pid, startTicks)))
	return hex.EncodeToString(sum[:8])
}

// Normalize maps an AgentEvent to a canonical Event, returning an error for
// unknown kinds so the pipeline can count and alert on schema drift.
func Normalize(a AgentEvent) (correlate.Event, error) {
	t, ok := kindMap[a.Kind]
	if !ok {
		return correlate.Event{}, fmt.Errorf("normalize: unknown kind %q", a.Kind)
	}
	ev := correlate.Event{
		ID:        a.ID,
		HostID:    a.HostID,
		TS:        time.Unix(0, a.TSUnixNs).UTC(),
		Type:      t,
		ProcGUID:  ProcGUID(a.BootID, a.PID, a.StartTicks),
		ProcImage: a.Exe,
		Cmdline:   strings.TrimSpace(a.Exe + " " + a.Args),
	}
	if a.PPID > 0 {
		ev.ParentGUID = ProcGUID(a.BootID, a.PPID, a.ParentStartTicks)
	}
	switch t {
	case correlate.FileWrite, correlate.FileRead, correlate.ModuleLoad:
		ev.FilePath = a.Path
	case correlate.NetConnect:
		ev.RemoteAddr = a.RAddr
		ev.RemotePort = a.RPort
	case correlate.DNSQuery:
		ev.DNSName = a.DNSName
	}
	if ev.ID == "" {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s|%d", a.HostID, a.TSUnixNs, a.Kind, a.PID)))
		ev.ID = hex.EncodeToString(sum[:8])
	}
	return ev, nil
}
