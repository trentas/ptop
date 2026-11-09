// SPDX-License-Identifier: GPL-2.0
//
// syscalls.bpf.c — counts syscalls and measures latency per (enter, exit)
// raw_syscalls of the target PID.
//
// Maps:
//   target_pid     ARRAY[1]  struct target_filter (written by the Go loader)
//   syscall_count  HASH      syscall_id → {count, total_lat_ns}
//   enter_ts       HASH      tgid_pid → {ts_ns, arg0, syscall_id}
//                            correlates enter→exit to compute latency
//   restarting     LRU_HASH  tgid_pid → a call stopped by a signal that the
//                            kernel may re-run (restart.bpf.h, #160)
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
#include <asm/unistd.h>
#include "target.bpf.h"
#include "restart.bpf.h"

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
    __u64 arg0;       // a re-run enters with the same arguments
    __u32 syscall_id;
    __u32 _pad;
};

// A call stopped by a restart code, waiting to learn whether it is re-run.
struct restart_data {
    __u64 ts_ns;      // when it first entered
    __u64 end_ns;     // when it stopped: its end, if it returned EINTR
    __u64 arg0;
    __u32 syscall_id;
    __u32 _pad;
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

// LRU: a thread killed inside the call never settles it.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, struct restart_data);
    __uint(max_entries, 10240);
} restarting SEC(".maps");

// is_target returns 1 if the current task belongs to the target process,
// resolving pids inside the target's PID namespace (see target.bpf.h).
static __always_inline int is_target(void)
{
    return pid_is_target(&target_pid);
}

static __always_inline void account(__u32 sc_id, __u64 lat_ns)
{
    struct syscall_stat *stat = bpf_map_lookup_elem(&syscall_count, &sc_id);
    if (stat) {
        __sync_fetch_and_add(&stat->count, 1);
        __sync_fetch_and_add(&stat->total_lat_ns, lat_ns);
    } else {
        struct syscall_stat new_stat = {.count = 1, .total_lat_ns = lat_ns};
        bpf_map_update_elem(&syscall_count, &sc_id, &new_stat, BPF_ANY);
    }
}

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct sys_enter_args *ctx)
{
    if (!is_target())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct enter_data data = {
        .ts_ns      = bpf_ktime_get_ns(),
        .arg0       = ctx->args[0],
        .syscall_id = (__u32)ctx->id,
    };
    // The kernel re-running a call a signal stopped: one call, timed from
    // its first entry (#160).
    struct restart_data *r = bpf_map_lookup_elem(&restarting, &pid_tgid);
    if (r && r->syscall_id == data.syscall_id && r->arg0 == data.arg0) {
        data.ts_ns = r->ts_ns;
        bpf_map_delete_elem(&restarting, &pid_tgid);
    }
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

    __u64 now = bpf_ktime_get_ns();
    __u32 sc_id = enter->syscall_id;
    __u64 start = enter->ts_ns;
    if (ret_restarts(ctx->ret)) {
        // Not over yet, or over with EINTR: restart.bpf.h.
        struct restart_data r = {
            .ts_ns      = start,
            .end_ns     = now,
            .arg0       = enter->arg0,
            .syscall_id = sc_id,
        };
        bpf_map_update_elem(&restarting, &pid_tgid, &r, BPF_ANY);
        bpf_map_delete_elem(&enter_ts, &pid_tgid);
        return 0;
    }
    bpf_map_delete_elem(&enter_ts, &pid_tgid);

    // The id comes from the entry: rt_sigreturn exits with the id the frame
    // restored, -1 on x86 and arm64.
    if (sc_id == __NR_rt_sigreturn && ctx->ret == -PTOP_EINTR) {
        struct restart_data *r = bpf_map_lookup_elem(&restarting, &pid_tgid);
        if (r) {
            account(r->syscall_id, r->end_ns - r->ts_ns);
            bpf_map_delete_elem(&restarting, &pid_tgid);
        }
    }
    account(sc_id, now - start);
    return 0;
}
