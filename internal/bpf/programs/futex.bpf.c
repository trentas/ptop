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
//   futex_inflight      HASH      tgid_pid → {uaddr, op, ts_ns, stack_id}
//                                 correlates enter→exit to compute
//                                 per-call latency, and carries the stack
//                                 captured at enter to the exit that accounts it
//   futex_stats         HASH      {uaddr, stack_id} → {wait_count, wake_count,
//                                 lat_sum_ns, lat_count, last_wait_tid,
//                                 last_wake_tid}
//   futex_stacks        STACK_TRACE  user stacks captured at the WAIT call site
//
// Why the key carries a stack id (#89):
//   uaddr alone identifies a lock only inside the live process — ASLR and
//   arena reuse give the same logical lock a different address on the next
//   run. The stack captured where a thread blocks is the address-independent
//   identity (module+offset survives ASLR), so waits are counted per
//   (uaddr, contention site) and userspace picks the dominant site as the
//   lock's name. Wake-class calls get stack_id = -1: they never name a lock,
//   and skipping the walk keeps the cheap path cheap.
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

// User-stack depth captured per contention site — enough to step over libc's
// pthread/futex wrappers and reach the application caller. Mirrors
// heap.bpf.c's HEAP_STACK_DEPTH; futexStackDepth in internal/bpf/futex.go.
#define FUTEX_STACK_DEPTH 32

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
    __s32 stack_id; // wait-site user stack (<0 → unknown, or a wake op)
};

// futex_stats key. A hash key is compared byte-wise, so _pad must be zeroed on
// every lookup/update — always build it as `struct futex_key k = {};`.
// Mirrored by FutexKey in internal/bpf/futex.go.
struct futex_key {
    __u64 uaddr;
    __s32 stack_id;
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
    __type(key, struct futex_key);
    __type(value, struct futex_stat);
    __uint(max_entries, 8192); // (lock × contention site) pairs, not locks
} futex_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, FUTEX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 4096);
} futex_stacks SEC(".maps");

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
        .uaddr    = ctx->uaddr,
        .ts_ns    = bpf_ktime_get_ns(),
        .op       = base_op,
        // Only a WAIT names a lock (the caller is blocking ON it); a WAKE is
        // the release path and would only add noise plus a stack walk.
        .stack_id = is_wait_op(base_op)
                        ? (__s32)bpf_get_stackid(ctx, &futex_stacks, BPF_F_USER_STACK)
                        : -1,
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
    __u32 op = inf->op;
    __u32 tid = (__u32)pid_tgid;
    struct futex_key key = {}; // zero-init: the padding is part of the hash key
    key.uaddr = inf->uaddr;
    key.stack_id = inf->stack_id;
    bpf_map_delete_elem(&futex_inflight, &pid_tgid);

    struct futex_stat *s = bpf_map_lookup_elem(&futex_stats, &key);
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
        bpf_map_update_elem(&futex_stats, &key, &ns, BPF_ANY);
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
