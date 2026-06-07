// SPDX-License-Identifier: GPL-2.0
//
// syscalls.bpf.c — counts syscalls and measures latency per (enter, exit)
// raw_syscalls of the target PID.
//
// Maps:
//   target_pid     ARRAY[1]  struct target_filter (written by the Go loader)
//   syscall_count  HASH      syscall_id → {count, total_lat_ns}
//   enter_ts       HASH      tgid_pid → {ts_ns, syscall_id}
//                            correlates enter→exit to compute latency
//
// Compilation (run by `make gen` on Linux):
//   clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
//     -I/usr/include/bpf \
//     -c programs/syscalls.bpf.c -o programs/syscalls.bpf.o
//
// The Go loader (internal/bpf/syscalls.go) embeds the .o via go:embed and
// uses cilium/ebpf to load it, attach the tracepoints and read the
// syscall_count map.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";

// raw_syscalls tracepoint structures — stable in the kernel since ~2010.
// Defining them inline avoids a dependency on vmlinux.h, which is large
// and arch-specific. The first u64 is padding for the tracepoint header
// (common_type/flag/preempt/pid).
struct sys_enter_args {
    unsigned long long _pad;
    long id;
    unsigned long args[6];
};

struct sys_exit_args {
    unsigned long long _pad;
    long id;
    long ret;
};

struct syscall_stat {
    __u64 count;
    __u64 total_lat_ns;
};

struct enter_data {
    __u64 ts_ns;
    __u32 syscall_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct syscall_stat);
    __uint(max_entries, 512);
} syscall_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct enter_data);
    __uint(max_entries, 10240);
} enter_ts SEC(".maps");

// is_target returns 1 if the current task belongs to the target process,
// resolving pids inside the target's PID namespace (see target.bpf.h).
static __always_inline int is_target(void)
{
    return pid_is_target(&target_pid);
}

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct sys_enter_args *ctx)
{
    if (!is_target())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct enter_data data = {
        .ts_ns      = bpf_ktime_get_ns(),
        .syscall_id = (__u32)ctx->id,
    };
    bpf_map_update_elem(&enter_ts, &pid_tgid, &data, BPF_ANY);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int handle_sys_exit(struct sys_exit_args *ctx)
{
    if (!is_target())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct enter_data *enter = bpf_map_lookup_elem(&enter_ts, &pid_tgid);
    if (!enter)
        return 0;

    __u64 lat_ns = bpf_ktime_get_ns() - enter->ts_ns;
    __u32 sc_id = enter->syscall_id;
    bpf_map_delete_elem(&enter_ts, &pid_tgid);

    struct syscall_stat *stat = bpf_map_lookup_elem(&syscall_count, &sc_id);
    if (stat) {
        __sync_fetch_and_add(&stat->count, 1);
        __sync_fetch_and_add(&stat->total_lat_ns, lat_ns);
    } else {
        struct syscall_stat new_stat = {.count = 1, .total_lat_ns = lat_ns};
        bpf_map_update_elem(&syscall_count, &sc_id, &new_stat, BPF_ANY);
    }
    return 0;
}
