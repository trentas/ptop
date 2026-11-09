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
//
// Three kinds of time, and the interval still open (#150):
//   A thread is on a CPU, switched out asleep, or switched out still runnable.
//   Each switch closes the interval it ends into one of three totals: on-CPU,
//   off-CPU (asleep: S, D, T...) and run-queue (runnable, waiting for a CPU).
//   Which off it is comes from prev_state at the switch-out. It used to be one
//   off total, so a preempted thread's wait for a CPU read as blocked: the two
//   point at opposite fixes (more CPU or fewer threads, against the code or
//   the dependency it waits on).
//
//   The totals only grow when an interval ENDS, so a thread asleep for the
//   whole window had nothing to add in it and read 0% off-CPU, then the whole
//   sleep landed in the window it woke in. The stamps below say which interval
//   is open and since when, and the Go side adds the open part at read time
//   (ThreadsTracer.Totals), the way cpu_on_since does for the CPU axis.
//
//   The wait between a wakeup and the switch-in that follows is still off-CPU
//   here: telling it apart needs sched_wakeup, which is #151.

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

// prev_state as sched_switch reports it (the event's print fmt in
// /sys/kernel/tracing/events/sched/sched_switch/format): the task state bits
// in the low byte, 0 for runnable, and 0x100 on its own when the switch was a
// preemption ("R+"). Runnable at the switch-out is the low byte at 0, which
// covers a preemption and a yield alike.
#define PREV_STATE_MASK   0xff
// X (EXIT_DEAD) and Z (EXIT_ZOMBIE): the switch-out is the thread's last. It is
// not asleep, and an interval left open would grow for as long as /proc keeps
// the zombie listed.
#define PREV_STATE_EXITED 0x30

#define OFF_ASLEEP   0
#define OFF_RUNNABLE 1
#define OFF_EXITED   2

// Field order matters, and it is the CPU tracer's rule (#108): the totals come
// first and the program writes a stamp BEFORE the total it closes into. A map
// lookup that copies in address order then reads a total before the stamps, so
// it cannot see an interval in a total and still open on its stamp — that read
// would count it twice. Nothing guarantees the copy order, or the store order
// on arm64, so the collector also keeps a per-thread high-water mark: a torn
// read moves a slice into the next window, it never counts it twice in sum.
struct thread_state {
    __u64 on_cpu_ns_total;
    __u64 off_cpu_ns_total;    // asleep (S, D, T...)
    __u64 runq_ns_total;       // runnable, waiting for a CPU after a preemption
    __u64 ctx_switches;
    __u64 last_on_cpu_ns;      // the later of the two stamps is the open interval
    __u64 last_off_cpu_ns;
    __u64 off_kind;            // OFF_* for the interval that began at last_off_cpu_ns
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

// charge_off closes an off interval into the total its kind belongs to.
static __always_inline void charge_off(struct thread_state *s, __u64 kind, __u64 ns)
{
    if (kind == OFF_RUNNABLE)
        __sync_fetch_and_add(&s->runq_ns_total, ns);
    else if (kind == OFF_ASLEEP)
        __sync_fetch_and_add(&s->off_cpu_ns_total, ns);
}

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct sched_switch_args *ctx)
{
    __u64 now = bpf_ktime_get_ns();

    // prev == current at sched_switch. If it belongs to the target process,
    // cache its root→ns TID mapping and close the slice it just ended.
    struct bpf_pidns_info ns = {};
    if (pid_target_ns(&threads_target_pid, &ns)) {
        __u32 root_tid = (__u32)ctx->prev_pid;
        __u32 ns_tid = ns.pid;
        bpf_map_update_elem(&root2ns, &root_tid, &ns_tid, BPF_ANY);

        struct thread_state *s = get_or_create_state(ns_tid);
        if (s) {
            __u64 on = s->last_on_cpu_ns, off = s->last_off_cpu_ns;
            __u64 was = s->off_kind;
            __u64 state = (__u64)ctx->prev_state;
            __u64 kind = OFF_RUNNABLE;
            if (state & PREV_STATE_EXITED)
                kind = OFF_EXITED;
            else if (state & PREV_STATE_MASK)
                kind = OFF_ASLEEP;

            s->off_kind = kind;
            s->last_off_cpu_ns = now;
            if (on > off) {
                // The slice we saw begin. on == 0 is a thread first seen
                // here: its slice began before we knew it (the warm-up).
                __sync_fetch_and_add(&s->on_cpu_ns_total, now - on);
            } else if (off != 0) {
                // We never saw it switch back in (root2ns lost it). The reader
                // has been counting the open off interval; keep it there
                // rather than take back what was already reported.
                charge_off(s, was, now - off);
            }
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
            __u64 on = s->last_on_cpu_ns, off = s->last_off_cpu_ns;
            __u64 was = s->off_kind;
            s->last_on_cpu_ns = now;
            if (off > on)
                charge_off(s, was, now - off);
        }
    }
    return 0;
}
