// SPDX-License-Identifier: GPL-2.0
//
// futex.bpf.c — traces target PID's futex operations via the
// syscalls:sys_enter_futex / sys_exit_futex tracepoints.
//
// Purpose:
//   Every userspace synchronization primitive on Linux (pthread_mutex,
//   sem_t, std::mutex, Go's sync.Mutex, …) falls into futex(2) under
//   contention. Counting WAITs per uaddr reveals where the program is
//   serializing.
//
// Maps:
//   futex_target_pid    ARRAY[1]  struct target_filter (written by the Go loader)
//   futex_inflight      HASH      tgid_pid → {uaddr, op, ts_ns}
//                                 correlates enter→exit to compute
//                                 per-call latency
//   futex_stats         HASH      uaddr → {wait_count, wake_count,
//                                 lat_sum_ns, lat_count, last_wait_tid,
//                                 last_wake_tid}
//
// Op filtering:
//   FUTEX_CMD_MASK = 0x7F strips FUTEX_PRIVATE_FLAG (0x80) and
//   FUTEX_CLOCK_REALTIME (0x100). We classify each base op as
//   "wait" (thread sleeps) or "wake" (wakes others).

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define FUTEX_CMD_MASK 0x7F

// Wait-class ops (thread sleeps on the uaddr)
#define FUTEX_WAIT             0
#define FUTEX_LOCK_PI          6
#define FUTEX_WAIT_BITSET      9
#define FUTEX_WAIT_REQUEUE_PI 11

// Wake-class ops (thread wakes others)
#define FUTEX_WAKE         1
#define FUTEX_REQUEUE      3
#define FUTEX_CMP_REQUEUE  4
#define FUTEX_WAKE_OP      5
#define FUTEX_UNLOCK_PI    7
#define FUTEX_WAKE_BITSET 10

// Layout of the syscalls:sys_enter_futex tracepoint.
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_futex/format
struct sys_enter_futex_args {
    unsigned long long _pad;
    long id;
    unsigned long uaddr;
    unsigned long op;
    unsigned long val;
    unsigned long utime;
    unsigned long uaddr2;
    unsigned long val3;
};

struct sys_exit_args {
    unsigned long long _pad;
    long id;
    long ret;
};

struct futex_inflight {
    __u64 uaddr;
    __u64 ts_ns;
    __u32 op;
    __u32 _pad;
};

struct futex_stat {
    __u64 wait_count;
    __u64 wake_count;
    __u64 lat_sum_ns;
    __u64 lat_count;
    __u32 last_wait_tid;
    __u32 last_wake_tid;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} futex_target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct futex_inflight);
    __uint(max_entries, 8192);
} futex_inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct futex_stat);
    __uint(max_entries, 4096);
} futex_stats SEC(".maps");

static __always_inline int is_futex_target(void)
{
    return pid_is_target(&futex_target_pid);
}

static __always_inline int is_wait_op(__u32 op)
{
    return op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET ||
           op == FUTEX_LOCK_PI || op == FUTEX_WAIT_REQUEUE_PI;
}

static __always_inline int is_wake_op(__u32 op)
{
    return op == FUTEX_WAKE || op == FUTEX_WAKE_BITSET ||
           op == FUTEX_REQUEUE || op == FUTEX_CMP_REQUEUE ||
           op == FUTEX_WAKE_OP || op == FUTEX_UNLOCK_PI;
}

SEC("tracepoint/syscalls/sys_enter_futex")
int handle_enter_futex(struct sys_enter_futex_args *ctx)
{
    if (!is_futex_target())
        return 0;

    __u32 base_op = (__u32)(ctx->op & FUTEX_CMD_MASK);
    if (!is_wait_op(base_op) && !is_wake_op(base_op))
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct futex_inflight inf = {
        .uaddr = ctx->uaddr,
        .ts_ns = bpf_ktime_get_ns(),
        .op    = base_op,
    };
    bpf_map_update_elem(&futex_inflight, &pid_tgid, &inf, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_futex")
int handle_exit_futex(struct sys_exit_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct futex_inflight *inf = bpf_map_lookup_elem(&futex_inflight, &pid_tgid);
    if (!inf)
        return 0;

    __u64 lat_ns = bpf_ktime_get_ns() - inf->ts_ns;
    __u64 uaddr = inf->uaddr;
    __u32 op = inf->op;
    __u32 tid = (__u32)pid_tgid;
    bpf_map_delete_elem(&futex_inflight, &pid_tgid);

    struct futex_stat *s = bpf_map_lookup_elem(&futex_stats, &uaddr);
    if (!s) {
        struct futex_stat ns = {};
        if (is_wait_op(op)) {
            ns.wait_count = 1;
            ns.last_wait_tid = tid;
        } else {
            ns.wake_count = 1;
            ns.last_wake_tid = tid;
        }
        ns.lat_sum_ns = lat_ns;
        ns.lat_count = 1;
        bpf_map_update_elem(&futex_stats, &uaddr, &ns, BPF_ANY);
        return 0;
    }
    if (is_wait_op(op)) {
        __sync_fetch_and_add(&s->wait_count, 1);
        s->last_wait_tid = tid;
    } else {
        __sync_fetch_and_add(&s->wake_count, 1);
        s->last_wake_tid = tid;
    }
    __sync_fetch_and_add(&s->lat_sum_ns, lat_ns);
    __sync_fetch_and_add(&s->lat_count, 1);
    return 0;
}
