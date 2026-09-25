//go:build ignore

/* Real eBPF: attach to the syscalls/sys_enter_openat tracepoint and stream file
 * opens. Two cases are emitted, everything else is dropped in-kernel:
 *   - write intent (O_WRONLY / O_RDWR / O_CREAT)  -> is_write = 1  (file.write)
 *   - read of a likely-secret path                 -> is_write = 0  (file.read)
 * Tracing every read open would flood, so reads are gated in-kernel to paths
 * under /etc/ or containing a dot-directory (where .ssh/.aws/.kube/.docker/.netrc
 * live); userspace then applies the exact secret allowlist before forwarding.
 * No CO-RE / vmlinux.h needed — the tracepoint ABI below is stable. */
#include "sxbpf.h"

#define TASK_COMM_LEN 16
#define FILENAME_LEN 256

/* fcntl.h access-mode + creation flags (Linux generic ABI) */
#define O_ACCMODE 00000003
#define O_CREAT 00000100

struct file_event {
	__u32 pid;
	__u64 ts;
	__u32 flags;
	__u8 is_write; /* 1 = write-intent open, 0 = read of a candidate secret */
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
 * syscall number, the args are laid out as longs (dfd, filename, flags, mode). */
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

/* coarse in-kernel gate for read opens: under /etc/, or containing "/." (a
 * dot-directory such as .ssh/.aws/.kube/.docker or a .netrc file). Bounded scan
 * keeps the verifier happy; userspace refines to the exact allowlist. */
static int read_candidate(__u8 *f)
{
	if (f[0] == '/' && f[1] == 'e' && f[2] == 't' && f[3] == 'c' && f[4] == '/')
		return 1;
	for (int i = 0; i < 96; i++) {
		if (f[i] == 0)
			break;
		if (f[i] == '/' && f[i + 1] == '.')
			return 1;
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct openat_ctx *ctx)
{
	long flags = ctx->flags;
	int is_write = (flags & O_ACCMODE) != 0 || (flags & O_CREAT) != 0;

	struct file_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__u64 id = bpf_get_current_pid_tgid();
	e->pid = (__u32)(id >> 32);
	e->ts = bpf_ktime_get_ns();
	e->flags = (__u32)flags;
	e->is_write = is_write ? 1 : 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), ctx->filename);

	if (!is_write && !read_candidate(e->filename)) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
