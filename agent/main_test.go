package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// nonexistent pid so procStat/exeOf enrichment returns zero values and the test
// asserts only the fields decoded straight from the BPF record.
const ghostPID = 2147480000

// TestDecodeConn_PortAndIPv4 drives a record laid out exactly as the kernel
// writes it — the inet_sock_set_state tracepoint already ntohs()'s the port, so
// dport is host byte order; the address is raw octets — through the same
// binary.Read the live agent uses, and checks the mapping. (A live run to 1.1.1.1
// on port 80 originally read back 20480 == 0x5000, catching a wrong byte swap.)
func TestDecodeConn_PortAndIPv4(t *testing.T) {
	buf := make([]byte, 56)
	binary.LittleEndian.PutUint32(buf[0:], ghostPID) // Pid
	binary.LittleEndian.PutUint64(buf[8:], 123)      // Ts
	binary.LittleEndian.PutUint16(buf[16:], 2)       // Family = AF_INET
	binary.LittleEndian.PutUint16(buf[18:], 4444)    // Dport, host order (tracepoint ntohs'd)
	copy(buf[20:24], []byte{203, 0, 113, 5})         // Daddr octets

	var e connsnoopConnEvent
	if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &e); err != nil {
		t.Fatalf("binary.Read: %v", err)
	}
	ev := decodeConn(e, "web-01", "b1", 7)

	if ev.Kind != "net.connect" {
		t.Errorf("Kind = %q, want net.connect", ev.Kind)
	}
	if ev.RAddr != "203.0.113.5" {
		t.Errorf("RAddr = %q, want 203.0.113.5", ev.RAddr)
	}
	if ev.RPort != 4444 {
		t.Errorf("RPort = %d, want 4444 (host-order port mishandled?)", ev.RPort)
	}
	if ev.PID != ghostPID {
		t.Errorf("PID = %d, want %d", ev.PID, ghostPID)
	}
	if ev.ID != "b1-7" {
		t.Errorf("ID = %q, want b1-7", ev.ID)
	}
}

// TestDecodeConn_IPv6 checks the AF_INET6 branch formats the v6 address.
func TestDecodeConn_IPv6(t *testing.T) {
	var e connsnoopConnEvent
	e.Pid = ghostPID
	e.Family = 10 // AF_INET6
	e.Daddr6 = [16]uint8{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	e.Dport = 443 // host order (tracepoint already ntohs'd)

	ev := decodeConn(e, "h", "b", 1)
	if ev.RAddr != "2001:db8::1" {
		t.Errorf("RAddr = %q, want 2001:db8::1", ev.RAddr)
	}
	if ev.RPort != 443 {
		t.Errorf("RPort = %d, want 443", ev.RPort)
	}
}

// TestDecodeFile_Write checks a write-intent open maps to a file.write event.
func TestDecodeFile_Write(t *testing.T) {
	var e filesnoopFileEvent
	e.Pid = ghostPID
	e.IsWrite = 1
	copy(e.Filename[:], "/tmp/payload\x00")
	copy(e.Comm[:], "curl\x00")

	ev, ok := decodeFile(e, "web-01", "b1", 3)
	if !ok {
		t.Fatal("write open should forward")
	}
	if ev.Kind != "file.write" {
		t.Errorf("Kind = %q, want file.write", ev.Kind)
	}
	if ev.Path != "/tmp/payload" {
		t.Errorf("Path = %q, want /tmp/payload", ev.Path)
	}
	if ev.Comm != "curl" {
		t.Errorf("Comm = %q, want curl", ev.Comm)
	}
}

// TestDecodeFile_SecretRead: a read of an allowlisted secret becomes file.read.
func TestDecodeFile_SecretRead(t *testing.T) {
	var e filesnoopFileEvent
	e.Pid = ghostPID
	e.IsWrite = 0
	copy(e.Filename[:], "/home/alice/.ssh/id_rsa\x00")

	ev, ok := decodeFile(e, "web-01", "b1", 4)
	if !ok {
		t.Fatal("secret read should forward")
	}
	if ev.Kind != "file.read" {
		t.Errorf("Kind = %q, want file.read", ev.Kind)
	}
	if ev.Path != "/home/alice/.ssh/id_rsa" {
		t.Errorf("Path = %q", ev.Path)
	}
}

// TestDecodeFile_NonSecretReadDropped: a read that passed the coarse kernel gate
// but is not on the exact allowlist (e.g. ~/.config/...) is dropped in userspace.
func TestDecodeFile_NonSecretReadDropped(t *testing.T) {
	var e filesnoopFileEvent
	e.Pid = ghostPID
	e.IsWrite = 0
	copy(e.Filename[:], "/home/alice/.config/app/settings.json\x00")

	if _, ok := decodeFile(e, "web-01", "b1", 5); ok {
		t.Error("non-allowlisted read must be dropped, not forwarded")
	}
}

// TestDecodeExec_Basic checks the exec record still maps as before.
func TestDecodeExec_Basic(t *testing.T) {
	var e execsnoopExecEvent
	e.Pid = ghostPID
	copy(e.Filename[:], "/usr/bin/curl\x00")
	copy(e.Comm[:], "curl\x00")

	ev := decodeExec(e, "web-01", "b1", 1)
	if ev.Kind != "exec" {
		t.Errorf("Kind = %q, want exec", ev.Kind)
	}
	if ev.Exe != "/usr/bin/curl" {
		t.Errorf("Exe = %q, want /usr/bin/curl", ev.Exe)
	}
}
