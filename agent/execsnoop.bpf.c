//go:build ignore

/* Real eBPF: attach to the sys_enter_execve tracepoint and stream every process
 * execution over a ring buffer. No CO-RE / vmlinux.h needed — the tracepoint
 * ABI below is stable, so this loads on any kernel with BPF ring buffers
 * (>= 5.8). Userspace enriches ppid/start_time from /proc (see main.go). */
#include "sxbpf.h"

#define TASK_COMM_LEN 16
#define FILENAME_LEN 256

struct exec_event {
	__u32 pid;
	__u64 ts;
	__u8 comm[TASK_COMM_LEN];
	__u8 filename[FILENAME_LEN];
};

/* force BTF emission of the event type for `bpf2go -type exec_event` */
struct exec_event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

/* stable layout of syscalls/sys_enter_execve (see the tracepoint format file) */
struct execve_ctx {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	__u32 __pad;
	const char *filename;
	const char *const *argv;
	const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct execve_ctx *ctx)
{
	struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__u64 id = bpf_get_current_pid_tgid();
	e->pid = (__u32)(id >> 32);
	e->ts = bpf_ktime_get_ns();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), ctx->filename);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
