// Package main is the SentinelX Linux eBPF agent. It loads a real BPF program
// that traces execve via a tracepoint and a ring buffer (see execsnoop.bpf.c),
// enriches each exec from /proc, and forwards canonical AgentEvents to the
// backend. Loading requires CAP_BPF/CAP_SYS_ADMIN (root) and a kernel with BPF
// ring buffers (>= 5.8).
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -type exec_event execsnoop execsnoop.bpf.c
package main
