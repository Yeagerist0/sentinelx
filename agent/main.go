package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// agentEvent mirrors normalize.AgentEvent (the backend wire format). The agent is
// a separate module, so the shape is duplicated here rather than imported.
type agentEvent struct {
	ID         string `json:"id"`
	Schema     string `json:"schema"`
	HostID     string `json:"host_id"`
	BootID     string `json:"boot_id"`
	TSUnixNs   int64  `json:"ts_unix_ns"`
	Kind       string `json:"kind"`
	PID        int    `json:"pid"`
	StartTicks int64  `json:"start_ticks"`
	PPID       int    `json:"ppid"`
	Exe        string `json:"exe"`
	Args       string `json:"args"`
}

func main() {
	backend := flag.String("backend", "", "backend base URL (e.g. http://localhost:8080); empty = print JSONL to stdout")
	token := flag.String("token", os.Getenv("SENTINELX_TOKEN"), "ingest bearer token")
	host := flag.String("host", hostname(), "host id to report")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock (need CAP_SYS_RESOURCE/root): %v", err)
	}

	var objs execsnoopObjects
	if err := loadExecsnoopObjects(&objs, nil); err != nil {
		log.Fatalf("load BPF objects (need CAP_BPF/root): %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		log.Fatalf("attach tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ringbuf: %v", err)
	}
	defer rd.Close()

	boot := readTrim("/proc/sys/kernel/random/boot_id")
	log.Printf("sentinelx-agent: tracing execve on %s (boot %s)", *host, boot)

	// Close the reader on signal so rd.Read() unblocks and we exit cleanly.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; rd.Close() }()

	var seq int64
	for {
		rec, err := rd.Read()
		if err != nil {
			log.Printf("ringbuf closed: %v", err)
			return
		}
		var raw execsnoopExecEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}
		seq++
		ev := enrich(raw, *host, boot, seq)
		if *backend == "" {
			b, _ := json.Marshal(ev)
			fmt.Println(string(b))
			continue
		}
		if err := post(*backend, *token, ev); err != nil {
			log.Printf("forward: %v", err)
		}
	}
}

// enrich turns a BPF exec record into a canonical event, filling ppid and
// start_ticks from /proc (best-effort; short-lived processes may already be gone).
func enrich(raw execsnoopExecEvent, host, boot string, seq int64) agentEvent {
	pid := int(raw.Pid)
	exe := cstr(raw.Filename[:])
	if exe == "" {
		exe = cstr(raw.Comm[:])
	}
	ppid, start := procStat(pid)
	return agentEvent{
		ID:         fmt.Sprintf("%s-%d", boot, seq),
		Schema:     "sentinelx.agent.v1",
		HostID:     host,
		BootID:     boot,
		TSUnixNs:   time.Now().UnixNano(),
		Kind:       "exec",
		PID:        pid,
		StartTicks: start,
		PPID:       ppid,
		Exe:        exe,
		Args:       procArgs(pid),
	}
}

func procStat(pid int) (ppid int, start int64) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, 0
	}
	s := string(b)
	rp := strings.LastIndex(s, ")")
	if rp < 0 {
		return 0, 0
	}
	f := strings.Fields(s[rp+2:])
	if len(f) < 20 {
		return 0, 0
	}
	ppid, _ = strconv.Atoi(f[1])
	start, _ = strconv.ParseInt(f[19], 10, 64)
	return ppid, start
}

func procArgs(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	if len(parts) > 1 {
		return strings.Join(parts[1:], " ")
	}
	return ""
}

func post(base, token string, ev agentEvent) error {
	b, _ := json.Marshal(ev)
	req, err := http.NewRequest("POST", strings.TrimRight(base, "/")+"/v1/ingest", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown-host"
	}
	return h
}
