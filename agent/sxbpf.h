/* Self-contained BPF helper/macro definitions so the program builds without
 * libbpf-dev or bpftool. Only what execsnoop needs. */
#ifndef SXBPF_H
#define SXBPF_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))

/* libbpf-style BTF map definition macros */
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name

/* map type constant (enum bpf_map_type in uapi/linux/bpf.h) */
#define BPF_MAP_TYPE_RINGBUF 27

/* BPF helper ids (enum bpf_func_id in uapi/linux/bpf.h) */
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_get_current_comm)(void *buf, __u32 size_in_bytes) = (void *)16;
static __u64 (*bpf_get_current_task)(void) = (void *)35;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)113;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)114;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)133;

/* Minimal CO-RE view of task_struct: only the fields we read. The real layout
 * comes from the running kernel's BTF — preserve_access_index makes clang emit
 * CO-RE relocations so each field's offset is fixed up at load time by field
 * NAME, not by this (deliberately partial, order-irrelevant) declaration. This
 * is the one place the agent uses CO-RE; everything else stays vmlinux-free. */
struct task_struct {
	__u64 start_boottime; /* process start, boottime clock (ns), set at fork */
	int tgid;
	struct task_struct *real_parent;
} __attribute__((preserve_access_index));

/* proc_ident reads a process's stable identity in-kernel: its start_boottime and
 * (for the current task) its real parent's pid + start. Reading start_boottime
 * here, at event time, avoids the userspace /proc race where a short-lived
 * process is gone before enrichment and gets start=0. */
static __always_inline __u64 task_start(struct task_struct *t)
{
	__u64 s = 0;
	bpf_probe_read_kernel(&s, sizeof(s), &t->start_boottime);
	return s;
}

#endif
