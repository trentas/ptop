/* SPDX-License-Identifier: GPL-2.0 */
/*
 * probecost.bpf.h — what the heap probes cost the target, counted where it is
 * spent (#154).
 *
 * A uprobe runs on the thread that tripped it, so its whole cost lands on the
 * target: the trap into the kernel and back, and the program. The trap is
 * calibrated on the host at startup (calib.bpf.c); the program is timed here,
 * on one hit in COST_TIME_EVERY so that timing every hit does not become a cost
 * of its own. Every hit is counted. The Go side multiplies the two.
 *
 * The map is per program object: each .bpf.c that includes this gets its own.
 */
#ifndef PTOP_PROBECOST_BPF_H
#define PTOP_PROBECOST_BPF_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define COST_TIME_EVERY 64 /* a power of two */

#define COST_ENTRY  0
#define COST_RETURN 1

/* Per CPU, summed by the Go side. Mirrored by ProbeCostCounters in
 * internal/bpf/probecost.go. */
struct probe_cost {
    __u64 entries;  /* uprobe hits */
    __u64 returns;  /* uretprobe hits */
    __u64 timed;    /* hits whose program time was measured */
    __u64 timed_ns; /* their program time */
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct probe_cost);
    __uint(max_entries, 1);
} probe_cost SEC(".maps");

/* cost_begin counts a hit and, on one in COST_TIME_EVERY, returns the clock to
 * time the program from; 0 otherwise. */
static __always_inline __u64 cost_begin(int kind)
{
    __u32 key = 0;
    struct probe_cost *c = bpf_map_lookup_elem(&probe_cost, &key);
    if (!c)
        return 0;
    __u64 n = kind == COST_RETURN ? ++c->returns : ++c->entries;
    if (n & (COST_TIME_EVERY - 1))
        return 0;
    return bpf_ktime_get_ns();
}

static __always_inline void cost_end(__u64 t0)
{
    if (!t0)
        return;
    __u32 key = 0;
    struct probe_cost *c = bpf_map_lookup_elem(&probe_cost, &key);
    if (!c)
        return;
    c->timed++;
    c->timed_ns += bpf_ktime_get_ns() - t0;
}

#endif /* PTOP_PROBECOST_BPF_H */
