// SPDX-License-Identifier: GPL-2.0
//
// cpu.bpf.c — the target's on-CPU time, taken from the scheduler.
//
// Maps:
//   cpu_target_pid    ARRAY[1]        struct target_filter (written by Go)
//   cpu_oncpu_ns      PERCPU_ARRAY[1] nanoseconds the target has been on this
//                                     CPU, summed over slices that have ended
//   cpu_on_since      PERCPU_ARRAY[1] when the slice running right now began,
//                                     0 when this CPU is not running the target
//   cpu_target_tids   LRU_HASH        root-ns TIDs known to belong to the target
//
// Why time and not samples (#108).
//   This used to be a perf_event at 100Hz per CPU that incremented a counter
//   whenever the target happened to be on-CPU, and the collector turned that
//   count into a percentage by dividing by the nominal rate. Two things were
//   wrong with that, and both surfaced as a CPU axis contradicting /proc:
//
//   - A process using 2.5% of a core produces 2.5 samples a second. The whole
//     signal was a handful of Bernoulli trials per bucket, so a one-second
//     bucket was mostly shot noise — three runs of one binary measured 0, 1
//     and 19 percent — and a busy second could legitimately come out ZERO.
//   - The nominal 100Hz is not the achieved rate. In freq mode the kernel
//     re-derives the sampling period from the count it observes at scheduler
//     ticks, which do not run on an idle CPU; after an idle stretch the period
//     inflates and the event fires well below 100Hz while the collector keeps
//     dividing by 100. Measured on a lightly loaded 10-CPU host: 80-90Hz per
//     CPU, drifting from one window to the next.
//
//   The scheduler already knows the answer exactly. sched_switch brackets
//   every slice the target gets, so summing (switch_out - switch_in) is the
//   quantity /proc reports as utime+stime, at nanosecond resolution instead
//   of 10ms ticks, and with no sampling rate to assume.
//
// PID-namespace handling, and why `next` needs a map.
//   At sched_switch `current` is `prev`, so pid_is_target() answers directly
//   for the outgoing task — that is the only side where the target can be
//   identified, in either PID or CGROUP mode. The incoming task arrives as a
//   bare root-namespace TID in next_pid, which no helper can resolve for a
//   task that is not current, so target TIDs are learned from the `prev` side
//   and remembered in cpu_target_tids. A thread's very first slice is
//   therefore missed, once, until it has been switched out at least once.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";

// Stable layout of the sched:sched_switch tracepoint — the same one
// threads.bpf.c reads. See
// /sys/kernel/tracing/events/sched/sched_switch/format.
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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} cpu_target_pid SEC(".maps");

// Per-CPU, so the hot path is a plain add rather than an atomic on one
// cacheline shared by every CPU in the machine. The Go side sums them.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} cpu_oncpu_ns SEC(".maps");

// The slice in flight. Only one task runs on a CPU at a time, so one
// timestamp per CPU is enough, and a switch-in is always followed by a
// switch-out on the same CPU (a task cannot migrate while running).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} cpu_on_since SEC(".maps");

// Only the target's threads are ever inserted; LRU evicts the dead ones. A
// cgroup subtree can hold many more threads than one process, hence the
// headroom over threads.bpf.c's 8192.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 16384);
} cpu_target_tids SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct sched_switch_args *ctx)
{
    __u32 key = 0;
    __u64 *since = bpf_map_lookup_elem(&cpu_on_since, &key);
    if (!since)
        return 0;

    __u64 now = bpf_ktime_get_ns();

    // Outgoing task. `current` is still prev here, so the target filter
    // applies to it directly.
    if (pid_is_target(&cpu_target_pid)) {
        // Learn this thread for the `next` side. Lookup first: after the
        // first switch-out this is the target's own hot path, and a lookup
        // takes no bucket lock where an update does. It also refreshes the
        // LRU entry, which is what keeps a busy thread from being evicted.
        __u32 tid = (__u32)ctx->prev_pid;
        if (!bpf_map_lookup_elem(&cpu_target_tids, &tid)) {
            __u8 one = 1;
            bpf_map_update_elem(&cpu_target_tids, &tid, &one, BPF_ANY);
        }

        // *since == 0 means this slice began before the thread was known —
        // the one-slice warm-up. Charging it would mean charging from zero.
        if (*since) {
            __u64 *acc = bpf_map_lookup_elem(&cpu_oncpu_ns, &key);
            if (acc)
                *acc += now - *since;
        }
    }

    // Incoming task. Clear first: whoever ran before is accounted for by now,
    // and most switches hand the CPU to someone who is not the target.
    *since = 0;
    __u32 next = (__u32)ctx->next_pid;
    if (bpf_map_lookup_elem(&cpu_target_tids, &next))
        *since = now;

    return 0;
}
