//go:build ignore

/* Real eBPF: attach to the syscalls/sys_enter_openat tracepoint and stream every
 * open() made with write intent (O_WRONLY / O_RDWR / O_CREAT) over a ring buffer.
 * Read-only opens are dropped in-kernel to keep the volume sane. No CO-RE /
 * vmlinux.h needed — the tracepoint ABI below is stable. Userspace turns each
 * record into a file.write AgentEvent and enriches start_ticks/exe from /proc. */
#include "sxbpf.h"

#define TASK_COMM_LEN 16
#define FILENAME_LEN 256

/* fcntl.h access-mode + creation flags (Linux generic ABI) */
#define O_ACCMODE 00000003
#define O_WRONLY 00000001
#define O_RDWR 00000002
#define O_CREAT 00000100

struct file_event {
	__u32 pid;
	__u64 ts;
	__u32 flags;
	__u8 comm[TASK_COMM_LEN];
	__u8 filename[FILENAME_LEN];
};

/* force BTF emission of the event type for `bpf2go -type file_event` */
struct file_event *unused_file_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

/* stable layout of syscalls/sys_enter_openat: after the common header and the
 * syscall number, the syscall args are laid out as longs (dfd, filename, flags,
 * mode) 8-byte aligned. */
struct openat_ctx {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	__u32 __pad;
	long dfd;
	const char *filename;
	long flags;
	long mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct openat_ctx *ctx)
{
	long flags = ctx->flags;
	/* write intent only: O_WRONLY, O_RDWR, or a create */
	if ((flags & O_ACCMODE) == 0 && !(flags & O_CREAT))
		return 0;

	struct file_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__u64 id = bpf_get_current_pid_tgid();
	e->pid = (__u32)(id >> 32);
	e->ts = bpf_ktime_get_ns();
	e->flags = (__u32)flags;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), ctx->filename);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
