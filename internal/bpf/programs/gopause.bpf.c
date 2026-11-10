// SPDX-License-Identifier: GPL-2.0
//
// gopause.bpf.c — how long a Go target stops the world, pause by pause (#175).
//
// Every stop-the-world in the Go runtime goes through
// runtime.stopTheWorldWithSema and ends in runtime.startTheWorldWithSema: the
// GC's sweep and mark termination, ReadMemStats, GOMAXPROCS, a goroutine
// profile. Two ENTRY uprobes, one on each, time a pause from the moment the
// runtime starts stopping the world to the moment it starts restarting it.
// That is exact, where the runtime-agnostic alternative (every thread of the
// process deschedules together) is a heuristic with no ground truth, reads an
// idle process the same way, and in Go misses the one thread that keeps
// running through the pause: the one that stopped the world.
//
// No uretprobe, on purpose: a uretprobe on Go code rewrites a return address
// the GC's stack scan then cannot unwind (#154, calib.bpf.c). Two entries need
// none.
//
// The start is keyed by tgid, not by thread: a process stops the world once at
// a time (worldsema), and the restart can run on another thread than the stop.
//
// Maps:
//   gopause_target_pid  ARRAY[1]   struct target_filter (the loader writes it)
//   gopause_start       HASH       tgid → the stop's start time
//   gopause_totals      ARRAY[1]   cumulative count, sum and a log2(µs)
//                                  histogram; the loader reads it every window
//                                  and the consumer takes the difference

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define GOPAUSE_BUCKETS 32

struct gopause_totals {
    __u64 count;
    __u64 sum_ns;
    __u64 buckets[GOPAUSE_BUCKETS]; // [2^i, 2^(i+1)) µs; 0 also < 1 µs; the last everything longer
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} gopause_target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} gopause_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct gopause_totals);
    __uint(max_entries, 1);
} gopause_totals SEC(".maps");

static __always_inline __u32 log2_us(__u64 ns)
{
    __u64 us = ns / 1000;
    __u32 b = 0;
#pragma unroll
    for (int i = 0; i < GOPAUSE_BUCKETS - 1; i++) {
        if (us >= 2) {
            us >>= 1;
            b++;
        }
    }
    return b;
}

SEC("uprobe/go_stop_the_world")
int uprobe_go_stop_the_world(void *ctx)
{
    if (!pid_is_target(&gopause_target_pid))
        return 0;
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&gopause_start, &tgid, &now, BPF_ANY);
    return 0;
}

SEC("uprobe/go_start_the_world")
int uprobe_go_start_the_world(void *ctx)
{
    if (!pid_is_target(&gopause_target_pid))
        return 0;
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 *start = bpf_map_lookup_elem(&gopause_start, &tgid);
    if (!start)
        return 0; // the stop predates the attach: a partial pause is not one
    __u64 d = bpf_ktime_get_ns() - *start;
    bpf_map_delete_elem(&gopause_start, &tgid);

    __u32 zero = 0;
    struct gopause_totals *t = bpf_map_lookup_elem(&gopause_totals, &zero);
    if (!t)
        return 0;
    __sync_fetch_and_add(&t->count, 1);
    __sync_fetch_and_add(&t->sum_ns, d);
    __u32 b = log2_us(d);
    if (b < GOPAUSE_BUCKETS)
        __sync_fetch_and_add(&t->buckets[b], 1);
    return 0;
}
