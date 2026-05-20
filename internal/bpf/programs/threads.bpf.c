// SPDX-License-Identifier: GPL-2.0
//
// threads.bpf.c — tracks scheduler transitions (on-CPU ↔ off-CPU) of the
// target PID's threads via the sched:sched_switch tracepoint.
//
// Why sched_switch and not /proc/<pid>/task/<tid>/stat?
//   /proc gives cumulative utime+stime sampled at 1Hz — bad granularity
//   for threads that oscillate quickly between running/blocked. The
//   tracepoint fires on EVERY context switch, so on_cpu_ns reflects
//   exactly what the kernel measured, in real time.
//
// Maps:
//   threads_target_pid  ARRAY[1]   struct target_filter (written by Go)
//   root2ns             LRU_HASH   root-ns tid → namespace-local tid
//   tid_state           HASH       ns-local tid → struct thread_state
//
// PID-namespace handling:
//   sched_switch delivers prev_pid/next_pid as ROOT-namespace TIDs, but the
//   Go side and tid_state work in the target's namespace-local TIDs. At the
//   tracepoint `current` == prev, so pid_target_ns() resolves prev's
//   namespace-local tid; that {root_tid → ns_tid} pair is cached in root2ns.
//   The `next` side then recovers the ns-local tid by looking up next_pid in
//   root2ns (learned the previous time that thread was scheduled out). A
//   brand-new thread is learned the first time it is `prev` — one context
//   switch of warm-up, which the UI tolerates.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";

// Stable layout of the sched:sched_switch tracepoint.
// /sys/kernel/debug/tracing/events/sched/sched_switch/format
struct sched_switch_args {
    unsigned long long _pad;     // common_type/flags/preempt_count/pid (8B)
    char prev_comm[16];          // offset 8
    int prev_pid;                // offset 24
    int prev_prio;               // offset 28
    long prev_state;             // offset 32
    char next_comm[16];          // offset 40
    int next_pid;                // offset 56
    int next_prio;               // offset 60
};

struct thread_state {
    __u64 last_on_cpu_ns;
    __u64 last_off_cpu_ns;
    __u64 on_cpu_ns_total;
    __u64 off_cpu_ns_total;
    __u64 ctx_switches;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} threads_target_pid SEC(".maps");

// root2ns maps a root-namespace TID to the target's namespace-local TID.
// Self-populated from the `prev` side of sched_switch; LRU evicts dead TIDs.
// Only target-process threads are ever inserted, so 8192 entries comfortably
// covers any realistic thread count.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 8192);
} root2ns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct thread_state);
    __uint(max_entries, 8192);
} tid_state SEC(".maps");

// Get-or-create entry in tid_state. Returns ptr (always non-null on success).
// On update failure (pathological case), returns NULL.
static __always_inline struct thread_state *get_or_create_state(__u32 tid)
{
    struct thread_state *s = bpf_map_lookup_elem(&tid_state, &tid);
    if (s)
        return s;
    struct thread_state zero = {};
    bpf_map_update_elem(&tid_state, &tid, &zero, BPF_ANY);
    return bpf_map_lookup_elem(&tid_state, &tid);
}

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct sched_switch_args *ctx)
{
    __u64 now = bpf_ktime_get_ns();

    // prev == current at sched_switch. If it belongs to the target process,
    // cache its root→ns TID mapping and do off-CPU accounting.
    struct bpf_pidns_info ns = {};
    if (pid_target_ns(&threads_target_pid, &ns)) {
        __u32 root_tid = (__u32)ctx->prev_pid;
        __u32 ns_tid = ns.pid;
        bpf_map_update_elem(&root2ns, &root_tid, &ns_tid, BPF_ANY);

        struct thread_state *s = get_or_create_state(ns_tid);
        if (s) {
            if (s->last_on_cpu_ns != 0) {
                __u64 delta = now - s->last_on_cpu_ns;
                __sync_fetch_and_add(&s->on_cpu_ns_total, delta);
            }
            s->last_off_cpu_ns = now;
            __sync_fetch_and_add(&s->ctx_switches, 1);
        }
    }

    // next entering CPU: recover its ns-local TID from root2ns (learned the
    // last time it was scheduled out).
    __u32 next_root = (__u32)ctx->next_pid;
    __u32 *next_ns = bpf_map_lookup_elem(&root2ns, &next_root);
    if (next_ns) {
        struct thread_state *s = get_or_create_state(*next_ns);
        if (s) {
            if (s->last_off_cpu_ns != 0) {
                __u64 delta = now - s->last_off_cpu_ns;
                __sync_fetch_and_add(&s->off_cpu_ns_total, delta);
            }
            s->last_on_cpu_ns = now;
        }
    }
    return 0;
}
