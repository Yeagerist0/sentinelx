package collect

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sentinelx/backend/normalize"
)

// ProcCollector is a dependency-free Linux /proc poller (dev/fallback). It emits
// process_start events for processes it observes. Production uses eBPF; see
// ADR-0003. It cannot observe file/network/exec-args reliably without
// privileges and misses processes that live shorter than the poll interval.
type ProcCollector struct {
	HostID   string
	Interval time.Duration
	bootID   string
	seen     map[int]bool
}

// NewProcCollector reads the host boot_id and returns a collector.
func NewProcCollector(hostID string) *ProcCollector {
	boot := "unknown-boot"
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		boot = strings.TrimSpace(string(b))
	}
	if hostID == "" {
		hostID, _ = os.Hostname()
	}
	return &ProcCollector{HostID: hostID, Interval: time.Second, bootID: boot, seen: map[int]bool{}}
}

// Snapshot returns process_start events for every process currently in /proc.
func (c *ProcCollector) Snapshot() ([]normalize.AgentEvent, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []normalize.AgentEvent
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if ev, ok := c.readProcess(pid); ok {
			out = append(out, ev)
		}
	}
	return out, nil
}

// Run polls /proc and feeds newly-appeared processes to the sink until stop is
// closed.
func (c *ProcCollector) Run(tenantID string, s Sink) error { return c.RunUntil(tenantID, s, nil) }

// RunUntil polls until stop is closed (or forever if stop is nil).
func (c *ProcCollector) RunUntil(tenantID string, s Sink, stop <-chan struct{}) error {
	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		snap, err := c.Snapshot()
		if err != nil {
			return err
		}
		for _, ev := range snap {
			pid, _ := strconv.Atoi(strings.TrimPrefix(ev.ID, "proc-"))
			if c.seen[pid] {
				continue
			}
			c.seen[pid] = true
			_, _ = s.Ingest(tenantID, ev)
		}
		select {
		case <-stop:
			return nil
		case <-t.C:
		}
	}
}

func (c *ProcCollector) readProcess(pid int) (normalize.AgentEvent, bool) {
	statB, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return normalize.AgentEvent{}, false
	}
	stat := string(statB)
	// comm is parenthesized and may contain spaces/parens: fields after the last
	// ')' are state(3), ppid(4)... starttime(22). slice index = fieldNo-3.
	rp := strings.LastIndex(stat, ")")
	if rp < 0 || rp+2 > len(stat) {
		return normalize.AgentEvent{}, false
	}
	fields := strings.Fields(stat[rp+2:])
	if len(fields) < 20 {
		return normalize.AgentEvent{}, false
	}
	ppid, _ := strconv.Atoi(fields[1])               // field 4
	start, _ := strconv.ParseInt(fields[19], 10, 64) // field 22 (clock ticks since boot)

	exe := ""
	if link, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe")); err == nil {
		exe = link
	} else if commB, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm")); err == nil {
		exe = strings.TrimSpace(string(commB))
	}

	args := ""
	if cmdB, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline")); err == nil {
		parts := strings.Split(strings.TrimRight(string(cmdB), "\x00"), "\x00")
		if len(parts) > 1 {
			args = strings.Join(parts[1:], " ")
		}
	}

	return normalize.AgentEvent{
		ID:         "proc-" + strconv.Itoa(pid),
		Schema:     "sentinelx.agent.v1",
		HostID:     c.HostID,
		BootID:     c.bootID,
		TSUnixNs:   time.Now().UnixNano(),
		Kind:       "exec",
		PID:        pid,
		StartTicks: start,
		PPID:       ppid,
		Exe:        exe,
		Args:       args,
	}, true
}
