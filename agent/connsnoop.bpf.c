//go:build ignore

/* Real eBPF: attach to the sock/inet_sock_set_state tracepoint and stream every
 * outbound TCP connection attempt (newstate == TCP_SYN_SENT) over a ring buffer.
 * No CO-RE / vmlinux.h needed — the tracepoint ABI below is stable, so this loads
 * on any kernel with BPF ring buffers (>= 5.8). Userspace turns each record into
 * a net.connect AgentEvent and enriches start_ticks/exe from /proc (see main.go). */
#include "sxbpf.h"

#define TASK_COMM_LEN 16

#define TCP_SYN_SENT 2
#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6

struct conn_event {
	__u32 pid;
	__u64 ts;
	__u64 start; /* process start_boottime (stable identity key) */
	__u16 family;
	__u16 dport; /* network byte order */
	__u8 daddr[4];
	__u8 daddr6[16];
	__u8 comm[TASK_COMM_LEN];
};

/* force BTF emission of the event type for `bpf2go -type conn_event` */
struct conn_event *unused_conn_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

/* stable layout of sock/inet_sock_set_state (see the tracepoint format file) */
struct set_state_ctx {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

SEC("tracepoint/sock/inet_sock_set_state")
int handle_conn(struct set_state_ctx *ctx)
{
	/* only the client-side transition into a connection attempt */
	if (ctx->newstate != TCP_SYN_SENT || ctx->protocol != IPPROTO_TCP)
		return 0;
	if (ctx->family != AF_INET && ctx->family != AF_INET6)
		return 0;

	struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__u64 id = bpf_get_current_pid_tgid();
	e->pid = (__u32)(id >> 32);
	e->ts = bpf_ktime_get_ns();
	e->start = task_start((struct task_struct *)bpf_get_current_task());
	e->family = ctx->family;
	e->dport = ctx->dport;
	__builtin_memcpy(e->daddr, ctx->daddr, sizeof(e->daddr));
	__builtin_memcpy(e->daddr6, ctx->daddr_v6, sizeof(e->daddr6));
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
