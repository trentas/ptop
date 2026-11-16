// SPDX-License-Identifier: GPL-2.0
//
// jvmpause.bpf.c — how long a HotSpot JVM stops the world, pause by pause
// (#189). The twin of gopause.bpf.c (#175), with two lanes:
//
//   safepoints  ENTRY uprobes on SafepointSynchronize::begin() and ::end() in
//               libjvm.so. A safepoint is the JVM's stop-the-world, GC or not:
//               every VM operation that needs the Java threads stopped (a
//               collection's pause, a deoptimization, a thread dump, class
//               redefinition) runs between the two, on the VM thread. begin()
//               includes reaching the safepoint (time-to-safepoint), so the
//               pause is timed from the moment the VM starts stopping the
//               threads to the moment it starts releasing them, as gopause
//               times Go's.
//
//   gc          USDT hotspot:gc__begin and hotspot:gc__end, HotSpot's own
//               boundaries of a collection (SvcGCMarker, which every collector
//               puts inside its stop-the-world pauses). Each probe has several
//               sites in libjvm.so and the loader attaches every one. The pause
//               of a collection always lies inside a safepoint, so this lane
//               says which of the safepoints were collections.
//
// Both lanes are keyed by thread: begin and end run on the same one (the VM
// thread for a safepoint; a scoped SvcGCMarker for a collection). A begin that
// finds one already open is a nested marker and only deepens it: the outermost
// pair is the pause, counted once.
//
// Maps:
//   jvmpause_target_pid  ARRAY[1]   struct target_filter (the loader writes it)
//   jvmpause_start       HASH       {thread, lane} → open pause (start, depth)
//   jvmpause_totals      ARRAY[2]   per lane: cumulative count, sum and a
//                                   log2(µs) histogram; the loader reads it
//                                   every window and the consumer takes the
//                                   difference

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define JVMPAUSE_BUCKETS 32

#define LANE_SAFEPOINT 0
#define LANE_GC 1
#define LANES 2

struct jvmpause_totals {
    __u64 count;
    __u64 sum_ns;
    __u64 buckets[JVMPAUSE_BUCKETS]; // [2^i, 2^(i+1)) µs; 0 also < 1 µs; the last everything longer
};

struct jvmpause_key {
    __u64 pid_tgid;
    __u32 lane;
    __u32 _pad;
};

struct jvmpause_open {
    __u64 start_ns;
    __u32 depth;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} jvmpause_target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct jvmpause_key);
    __type(value, struct jvmpause_open);
    __uint(max_entries, 1024);
} jvmpause_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct jvmpause_totals);
    __uint(max_entries, LANES);
} jvmpause_totals SEC(".maps");

static __always_inline __u32 log2_us(__u64 ns)
{
    __u64 us = ns / 1000;
    __u32 b = 0;
#pragma unroll
    for (int i = 0; i < JVMPAUSE_BUCKETS - 1; i++) {
        if (us >= 2) {
            us >>= 1;
            b++;
        }
    }
    return b;
}

static __always_inline int pause_begin(__u32 lane)
{
    if (!pid_is_target(&jvmpause_target_pid))
        return 0;
    struct jvmpause_key k = {.pid_tgid = bpf_get_current_pid_tgid(), .lane = lane};
    struct jvmpause_open *o = bpf_map_lookup_elem(&jvmpause_start, &k);
    if (o) {
        // A marker inside one already open: the outer pair times the pause.
        // The entry is this thread's alone, so a plain write is enough.
        o->depth += 1;
        return 0;
    }
    struct jvmpause_open n = {.start_ns = bpf_ktime_get_ns(), .depth = 1};
    bpf_map_update_elem(&jvmpause_start, &k, &n, BPF_NOEXIST);
    return 0;
}

static __always_inline int pause_end(__u32 lane)
{
    if (!pid_is_target(&jvmpause_target_pid))
        return 0;
    struct jvmpause_key k = {.pid_tgid = bpf_get_current_pid_tgid(), .lane = lane};
    struct jvmpause_open *o = bpf_map_lookup_elem(&jvmpause_start, &k);
    if (!o)
        return 0; // the begin predates the attach: a partial pause is not one
    if (o->depth > 1) {
        o->depth -= 1;
        return 0;
    }
    __u64 d = bpf_ktime_get_ns() - o->start_ns;
    bpf_map_delete_elem(&jvmpause_start, &k);

    struct jvmpause_totals *t = bpf_map_lookup_elem(&jvmpause_totals, &lane);
    if (!t)
        return 0;
    __sync_fetch_and_add(&t->count, 1);
    __sync_fetch_and_add(&t->sum_ns, d);
    __u32 b = log2_us(d);
    if (b < JVMPAUSE_BUCKETS)
        __sync_fetch_and_add(&t->buckets[b], 1);
    return 0;
}

SEC("uprobe/jvm_safepoint_begin")
int uprobe_jvm_safepoint_begin(void *ctx)
{
    return pause_begin(LANE_SAFEPOINT);
}

SEC("uprobe/jvm_safepoint_end")
int uprobe_jvm_safepoint_end(void *ctx)
{
    return pause_end(LANE_SAFEPOINT);
}

SEC("uprobe/jvm_gc_begin")
int uprobe_jvm_gc_begin(void *ctx)
{
    return pause_begin(LANE_GC);
}

SEC("uprobe/jvm_gc_end")
int uprobe_jvm_gc_end(void *ctx)
{
    return pause_end(LANE_GC);
}
