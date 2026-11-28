// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Tracing-only programs: tracepoints that observe and report. No signals, return-value
// overrides or LSM hooks are used (Requirements 15.3, 15.9).
//
// Build (needs clang, libbpf headers and a bpftool-generated vmlinux.h): see ../generate.go.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "sensor.h"

#define AF_INET 2
#define O_WRONLY 01
#define O_RDWR 02
#define CLONE_NEWNS 0x00020000
#define CLONE_NEWPID 0x20000000

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

// When cgroup_filter_enabled[0] is non-zero only cgroups present in cgroup_filter are reported.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} cgroup_filter_enabled SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u8);
} cgroup_filter SEC(".maps");

static const char sensitive_prefixes[][16] = {
	"/etc/", "/root/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
	"/var/spool/cron", "/proc/", "/sys/", "/boot/", "/lib/", "/usr/lib/",
};

static __always_inline int cgroup_allowed(__u64 id)
{
	__u32 zero = 0;
	__u32 *on = bpf_map_lookup_elem(&cgroup_filter_enabled, &zero);
	if (!on || !*on)
		return 1;
	return bpf_map_lookup_elem(&cgroup_filter, &id) != NULL;
}

static __always_inline int in_container(void)
{
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	return BPF_CORE_READ(t, thread_pid, level) > 0;
}

static __always_inline struct bellu_event *reserve(__u32 kind)
{
	__u64 cg = bpf_get_current_cgroup_id();
	if (!cgroup_allowed(cg))
		return NULL;
	struct bellu_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return NULL;
	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns = bpf_ktime_get_ns();
	e->cgroup_id = cg;
	e->kind = kind;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->in_container = in_container();
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return e;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int bellu_exec(struct trace_event_raw_sys_enter *ctx)
{
	const char *filename = (const char *)ctx->args[0];
	const char *const *argv = (const char *const *)ctx->args[1];
	struct bellu_event *e = reserve(BELLU_EXEC);
	if (!e)
		return 0;
	bpf_probe_read_user_str(e->path, sizeof(e->path), filename);
	const char *a1 = NULL;
	if (argv && bpf_probe_read_user(&a1, sizeof(a1), &argv[1]) == 0 && a1)
		bpf_probe_read_user_str(e->args, sizeof(e->args), a1);
	int shell = 0;
	char tail[8] = {};
	int len = 0;
#pragma unroll
	for (int i = 0; i < BELLU_PATH_LEN; i++) {
		if (e->path[i] == 0)
			break;
		len = i + 1;
	}
	if (len >= 3 && len < BELLU_PATH_LEN) {
		__builtin_memcpy(tail, &e->path[(len - 3) & (BELLU_PATH_LEN - 1)], 3);
		shell = tail[0] == '/' && tail[1] == 's' && tail[2] == 'h';
		if (!shell && len >= 5) {
			char t5[5];
			__builtin_memcpy(t5, &e->path[(len - 5) & (BELLU_PATH_LEN - 1)], 5);
			shell = t5[0] == '/' && t5[1] == 'b' && t5[2] == 'a' && t5[3] == 's' && t5[4] == 'h';
		}
	}
	bool container_shell = shell && e->in_container;
	bpf_ringbuf_submit(e, 0);
	if (container_shell) {
		struct bellu_event *s = reserve(BELLU_SHELL_IN_CONTAINER);
		if (!s)
			return 0;
		bpf_probe_read_user_str(s->path, sizeof(s->path), filename);
		bpf_ringbuf_submit(s, 0);
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int bellu_openat(struct trace_event_raw_sys_enter *ctx)
{
	long flags = ctx->args[2];
	if (!(flags & (O_WRONLY | O_RDWR)))
		return 0;
	char p[BELLU_PATH_LEN] = {};
	bpf_probe_read_user_str(p, sizeof(p), (const char *)ctx->args[1]);
	int match = 0;
#pragma unroll
	for (int i = 0; i < sizeof(sensitive_prefixes) / sizeof(sensitive_prefixes[0]); i++) {
		int j = 0;
#pragma unroll
		for (; j < 16; j++) {
			char c = sensitive_prefixes[i][j];
			if (c == 0) {
				match = 1;
				break;
			}
			if (p[j] != c)
				break;
		}
		if (match)
			break;
	}
	if (!match)
		return 0;
	struct bellu_event *e = reserve(BELLU_FILE_WRITE);
	if (!e)
		return 0;
	__builtin_memcpy(e->path, p, sizeof(e->path));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int bellu_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct sockaddr_in sa = {};
	if (bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]) != 0)
		return 0;
	if (sa.sin_family != AF_INET)
		return 0;
	struct bellu_event *e = reserve(BELLU_CONNECT);
	if (!e)
		return 0;
	e->family = sa.sin_family;
	e->addr4 = sa.sin_addr.s_addr;
	e->port = __builtin_bswap16(sa.sin_port);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int priv_change(__u32 target)
{
	if (target != 0)
		return 0;
	if ((__u32)bpf_get_current_uid_gid() == 0)
		return 0;
	struct bellu_event *e = reserve(BELLU_PRIV_CHANGE);
	if (!e)
		return 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int bellu_setuid(struct trace_event_raw_sys_enter *ctx)
{
	return priv_change((__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int bellu_setresuid(struct trace_event_raw_sys_enter *ctx)
{
	return priv_change((__u32)ctx->args[1]);
}

static __always_inline int escape(void)
{
	if (!in_container())
		return 0;
	struct bellu_event *e = reserve(BELLU_CONTAINER_ESCAPE);
	if (!e)
		return 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// setns from inside a container and mount/unshare of namespaces are escape indicators.
SEC("tracepoint/syscalls/sys_enter_setns")
int bellu_setns(struct trace_event_raw_sys_enter *ctx)
{
	return escape();
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int bellu_unshare(struct trace_event_raw_sys_enter *ctx)
{
	if (!(ctx->args[0] & (CLONE_NEWNS | CLONE_NEWPID)))
		return 0;
	return escape();
}
