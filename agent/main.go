package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// agentEvent mirrors normalize.AgentEvent (the backend wire format). The agent is
// a separate module, so the shape is duplicated here rather than imported. Fields
// are a superset; only those relevant to Kind are populated.
type agentEvent struct {
	ID               string `json:"id"`
	Schema           string `json:"schema"`
	HostID           string `json:"host_id"`
	BootID           string `json:"boot_id"`
	TSUnixNs         int64  `json:"ts_unix_ns"`
	Kind             string `json:"kind"`
	PID              int    `json:"pid"`
	StartTicks       int64  `json:"start_ticks"`
	PPID             int    `json:"ppid,omitempty"`
	ParentStartTicks int64  `json:"parent_start_ticks,omitempty"`
	Comm             string `json:"comm,omitempty"`
	Exe              string `json:"exe,omitempty"`
	Args             string `json:"args,omitempty"`
	Path             string `json:"path,omitempty"`
	RAddr            string `json:"raddr,omitempty"`
	RPort            int    `json:"rport,omitempty"`
}

func main() {
	backend := flag.String("backend", "", "backend base URL (e.g. http://localhost:8080); empty = print JSONL to stdout")
	token := flag.String("token", os.Getenv("SENTINELX_TOKEN"), "ingest bearer token")
	host := flag.String("host", hostname(), "host id to report")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock (need CAP_SYS_RESOURCE/root): %v", err)
	}

	boot := readTrim("/proc/sys/kernel/random/boot_id")
	var seq int64
	forward := func(ev agentEvent) {
		if *backend == "" {
			b, _ := json.Marshal(ev)
			fmt.Println(string(b))
			return
		}
		if err := post(*backend, *token, ev); err != nil {
			log.Printf("forward: %v", err)
		}
	}

	// Each subsystem is an independent BPF object + tracepoint + ring buffer, read
	// by its own goroutine. A shared atomic sequence keeps event IDs unique and
	// monotonic across all three streams (the backend uses ID gaps for tamper/
	// drop detection, so the counter must be single-source).
	var (
		closers []func()
		readers []*ringbuf.Reader
		streams []func(*ringbuf.Reader)
	)

	// exec
	{
		var objs execsnoopObjects
		if err := loadExecsnoopObjects(&objs, nil); err != nil {
			log.Fatalf("load exec BPF (need CAP_BPF/root): %v", err)
		}
		closers = append(closers, func() { objs.Close() })
		tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
		if err != nil {
			log.Fatalf("attach execve: %v", err)
		}
		closers = append(closers, func() { tp.Close() })
		rd, err := ringbuf.NewReader(objs.Events)
		if err != nil {
			log.Fatalf("open exec ringbuf: %v", err)
		}
		readers = append(readers, rd)
		streams = append(streams, func(rd *ringbuf.Reader) {
			runStream(rd, "exec", &seq, forward, func(raw []byte, n int64) (agentEvent, bool) {
				var e execsnoopExecEvent
				if binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e) != nil {
					return agentEvent{}, false
				}
				return decodeExec(e, *host, boot, n), true
			})
		})
	}

	// net.connect
	{
		var objs connsnoopObjects
		if err := loadConnsnoopObjects(&objs, nil); err != nil {
			log.Fatalf("load conn BPF: %v", err)
		}
		closers = append(closers, func() { objs.Close() })
		tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.HandleConn, nil)
		if err != nil {
			log.Fatalf("attach inet_sock_set_state: %v", err)
		}
		closers = append(closers, func() { tp.Close() })
		rd, err := ringbuf.NewReader(objs.Events)
		if err != nil {
			log.Fatalf("open conn ringbuf: %v", err)
		}
		readers = append(readers, rd)
		streams = append(streams, func(rd *ringbuf.Reader) {
			runStream(rd, "net.connect", &seq, forward, func(raw []byte, n int64) (agentEvent, bool) {
				var e connsnoopConnEvent
				if binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e) != nil {
					return agentEvent{}, false
				}
				return decodeConn(e, *host, boot, n), true
			})
		})
	}

	// file.write
	{
		var objs filesnoopObjects
		if err := loadFilesnoopObjects(&objs, nil); err != nil {
			log.Fatalf("load file BPF: %v", err)
		}
		closers = append(closers, func() { objs.Close() })
		tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenat, nil)
		if err != nil {
			log.Fatalf("attach sys_enter_openat: %v", err)
		}
		closers = append(closers, func() { tp.Close() })
		rd, err := ringbuf.NewReader(objs.Events)
		if err != nil {
			log.Fatalf("open file ringbuf: %v", err)
		}
		readers = append(readers, rd)
		streams = append(streams, func(rd *ringbuf.Reader) {
			runStream(rd, "file", &seq, forward, func(raw []byte, n int64) (agentEvent, bool) {
				var e filesnoopFileEvent
				if binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e) != nil {
					return agentEvent{}, false
				}
				return decodeFile(e, *host, boot, n)
			})
		})
	}

	for _, c := range closers {
		defer c()
	}
	log.Printf("sentinelx-agent: tracing exec + net.connect + file.write on %s (boot %s)", *host, boot)

	// Close every reader on signal so the Read() calls unblock and goroutines exit.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		for _, rd := range readers {
			rd.Close()
		}
	}()

	var wg sync.WaitGroup
	for i := range streams {
		wg.Add(1)
		go func(fn func(*ringbuf.Reader), rd *ringbuf.Reader) {
			defer wg.Done()
			fn(rd)
		}(streams[i], readers[i])
	}
	wg.Wait()
}

// runStream reads a ring buffer to exhaustion, decoding each record with fn and
// forwarding the resulting event. fn returns false to drop a malformed record.
func runStream(rd *ringbuf.Reader, name string, seq *int64, forward func(agentEvent), fn func(raw []byte, n int64) (agentEvent, bool)) {
	for {
		rec, err := rd.Read()
		if err != nil {
			log.Printf("%s ringbuf closed: %v", name, err)
			return
		}
		n := atomic.AddInt64(seq, 1)
		ev, ok := fn(rec.RawSample, n)
		if !ok {
			continue
		}
		forward(ev)
	}
}

// decodeExec turns a BPF exec record into a canonical event. Identity (start) and
// lineage (ppid, parent start) are captured in-kernel via CO-RE at event time, so
// they are exact even for a process that exits microseconds later — no /proc race.
func decodeExec(raw execsnoopExecEvent, host, boot string, seq int64) agentEvent {
	exe := cstr(raw.Filename[:])
	if exe == "" {
		exe = cstr(raw.Comm[:])
	}
	pid := int(raw.Pid)
	return agentEvent{
		ID:               fmt.Sprintf("%s-%d", boot, seq),
		Schema:           "sentinelx.agent.v1",
		HostID:           host,
		BootID:           boot,
		TSUnixNs:         time.Now().UnixNano(),
		Kind:             "exec",
		PID:              pid,
		StartTicks:       int64(raw.Start),
		PPID:             int(raw.Ppid),
		ParentStartTicks: int64(raw.Pstart),
		Comm:             cstr(raw.Comm[:]),
		Exe:              exe,
		Args:             procArgs(pid),
	}
}

// decodeConn turns a BPF outbound-connect record into a net.connect event. The
// dest port is network byte order in the kernel; the address bytes are already
// the octets in order. start_boottime is captured in-kernel so the event keys to
// the same process node (ProcGUID) as that pid's exec.
func decodeConn(raw connsnoopConnEvent, host, boot string, seq int64) agentEvent {
	pid := int(raw.Pid)
	return agentEvent{
		ID:         fmt.Sprintf("%s-%d", boot, seq),
		Schema:     "sentinelx.agent.v1",
		HostID:     host,
		BootID:     boot,
		TSUnixNs:   time.Now().UnixNano(),
		Kind:       "net.connect",
		PID:        pid,
		StartTicks: int64(raw.Start),
		Comm:       cstr(raw.Comm[:]),
		Exe:        exeOf(pid),
		RAddr:      connIP(raw),
		// The inet_sock_set_state tracepoint already ntohs()'s the port, so the
		// field arrives in host byte order — no swap here.
		RPort: int(raw.Dport),
	}
}

// decodeFile turns a BPF open record into a file.write or file.read event. Write
// opens always forward; read opens are pre-filtered in-kernel to secret-likely
// paths and then held to the exact secret allowlist here — a non-secret read
// returns ok=false and is dropped, so the backend only sees credential reads.
func decodeFile(raw filesnoopFileEvent, host, boot string, seq int64) (agentEvent, bool) {
	path := cstr(raw.Filename[:])
	kind := "file.write"
	if raw.IsWrite == 0 {
		if !isSecretPath(path) {
			return agentEvent{}, false
		}
		kind = "file.read"
	}
	pid := int(raw.Pid)
	return agentEvent{
		ID:         fmt.Sprintf("%s-%d", boot, seq),
		Schema:     "sentinelx.agent.v1",
		HostID:     host,
		BootID:     boot,
		TSUnixNs:   time.Now().UnixNano(),
		Kind:       kind,
		PID:        pid,
		StartTicks: int64(raw.Start),
		Comm:       cstr(raw.Comm[:]),
		Exe:        exeOf(pid),
		Path:       path,
	}, true
}

// secretSuffixes are credential/secret files whose read is worth forwarding.
// Kept in sync with backend/correlate's isSecretPath and the credential_file_read
// rule; the in-kernel gate is a coarse prefilter, this is the exact allowlist.
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

// connIP formats the destination address for the event's address family
// (AF_INET=2, AF_INET6=10). The bytes are the address octets in network order.
func connIP(raw connsnoopConnEvent) string {
	if raw.Family == 10 {
		return net.IP(raw.Daddr6[:]).String()
	}
	return net.IP(raw.Daddr[:]).String()
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

// exeOf resolves a pid's executable path via /proc/<pid>/exe (best-effort).
func exeOf(pid int) string {
	p, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return ""
	}
	return p
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
