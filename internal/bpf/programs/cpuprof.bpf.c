// SPDX-License-Identifier: GPL-2.0
//
// cpuprof.bpf.c — WHERE the target's CPU time goes, sampled.
//
// Maps:
//   cpuprof_target_pid  ARRAY[1]      struct target_filter (written by Go)
//   cpuprof_counts      HASH          stack_id → samples taken at that stack
//   cpuprof_stacks      STACK_TRACE   user stacks captured at sample time
//   cpuprof_rate        PERCPU_ARRAY  {fired, hit} — the ACHIEVED sampling rate
//
// ─── Why this exists next to cpu.bpf.c, and not instead of it (#125) ────────
//
// cpu.bpf.c answers HOW MUCH: it brackets the target's slices at sched_switch
// and sums nanoseconds, which is the quantity /proc reports as utime+stime.
// That axis is a magnitude and it has no address — a hot loop shows up as "p99
// CPU rose" and never names the function. Every other axis in the stream
// carries one: heap has a call site with func/file:line, locks have a
// symbolized acquire site, syscalls have a name.
//
// This program answers WHERE, and it answers it by sampling, because sampling
// is the right instrument for that question and the wrong one for the other.
// Read the header of cpu.bpf.c for the long version; the short version is that
// a count of samples is not a measurement of time (a process at 2.5% of a core
// draws 2.5 Bernoulli trials a second, and three runs of one binary measured
// 0, 1 and 19 percent), while the scheduler already knows the exact answer. So
// the nanoseconds stay there and the addresses come from here, and the two
// NEVER meet in one field — that conflation is precisely what #108 undid.
//
// What a consumer multiplies is its own business: share × on-CPU nanoseconds
// gives time-in-function, and it inherits this program's sampling uncertainty
// when it does. Userspace publishes the sample COUNT beside every share so
// that inference can be refused when the counts are too thin to carry it.
//
// ─── The rate is asked for, and then it is measured ─────────────────────────
//
// `fired` counts every sample the PMU delivers on this CPU, target or not;
// `hit` counts the ones where the target was the task running. Two adds on a
// per-CPU cache line, and they buy the one thing #108 proved cannot be
// assumed: in freq mode the kernel re-derives the sampling period from what it
// observes at scheduler ticks, and ticks do not run on an idle CPU, so the
// event fires well below the requested rate — measured at 80-90Hz per CPU
// where 100 was asked, drifting window to window. The old sampler divided by
// the number it had asked for. This one reports fired/(ncpu·Δt) as the rate it
// actually got, beside the rate it wanted, and lets the reader see the gap.
//
// The requested rate defaults to 99Hz rather than 100, as insurance against the
// shape of problem goalloc.bpf.c draws its threshold at random to avoid: a
// sampler whose period divides a periodic workload's would land at the same
// point of every cycle, and one function would take every sample.
//
// Insurance, not a repair: the attempt to reproduce it failed. An 8ms/2ms duty
// cycle sampled at exactly 100Hz measured 80/77/79/85 against a true 80. Freq
// mode re-derives the period from the observed rate — the same behaviour #108
// found underdelivering — so the phase dithers rather than locking, and a real
// workload's own jitter does likewise. A FIXED-period sampler would have no
// such dithering, which is why the choice stays.
//
// ─── Scope ──────────────────────────────────────────────────────────────────
//
// USER stacks only (BPF_F_USER_STACK). Time spent inside a syscall is
// attributed to the userspace frame that made the call, which is true and
// cross-references the syscall axis; naming the kernel function would need
// /proc/kallsyms and a kptr_restrict conversation, and is a declared absence
// rather than a silent one.
//
// A failed stack walk returns a negative id, which keys its own bucket here and
// is published by userspace as an unresolved-sample COUNT rather than as a list
// entry — so a capture this program cannot see into says so, instead of quietly
// ranking the few stacks that did resolve.
//
// Worth being precise about what that does and does not cover, because the
// obvious guess is wrong. Missing frame pointers do NOT land here: the leaf
// comes from the interrupted register state, not from unwinding, so it resolves
// either way. Measured on a C target built both ways, the only difference was
// the DEPTH of the stack above the leaf (4 frames against 3) — the attribution
// was identical, and unresolved was zero in both. Since this axis attributes by
// the leaf, it is largely immune to a target without frame pointers; what
// suffers is ResolveStack's answer, not the ranking.
//
// Userspace reads cpuprof_counts with a read-and-DELETE, so each publish
// covers exactly one window and stack ids that stopped being sampled evaporate
// on their own. That works here and not for heap because this is a pure
// counter, where heap tracks a live set it has to keep.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";

// User-stack depth captured per sample. Matches HEAP_STACK_DEPTH /
// GOALLOC_STACK_DEPTH: deep enough to carry a stack worth resolving through
// EventStreamService.ResolveStack, while the leaf — the function actually
// executing — is what this axis ranks by.
#define CPUPROF_STACK_DEPTH 32

// Per-CPU sampling bookkeeping. Per-CPU because a BPF program runs with
// preemption disabled, so the adds are contention-free; a global counter here
// would put an atomic on the machine's hottest shared line at 99Hz × ncpu.
struct cpuprof_rate_stat {
    __u64 fired; // every sample delivered on this CPU, whoever was running
    __u64 hit;   // those where the running task belonged to the target
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} cpuprof_target_pid SEC(".maps");

// Keyed by stack id, like every other aggregate here: one entry per distinct
// stack, folded into one entry per FUNCTION by userspace. Negative ids (the
// walk failed) key their own entry and become the unresolved count.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __s32);
    __type(value, __u64);
    __uint(max_entries, 8192);
} cpuprof_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, CPUPROF_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 16384);
} cpuprof_stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct cpuprof_rate_stat);
    __uint(max_entries, 1);
} cpuprof_rate SEC(".maps");

// cpuprof_slot returns this stack's counter, creating it at zero on first
// sight. BPF_NOEXIST + re-lookup rather than a blind update, so two CPUs
// sampling the same stack in the same instant cannot lose each other's count.
static __always_inline __u64 *cpuprof_slot(__s32 sid)
{
    __u64 *n = bpf_map_lookup_elem(&cpuprof_counts, &sid);
    if (n)
        return n;
    __u64 zero = 0;
    bpf_map_update_elem(&cpuprof_counts, &sid, &zero, BPF_NOEXIST);
    return bpf_map_lookup_elem(&cpuprof_counts, &sid);
}

// handle_cpu_sample fires on the perf_event the Go loader opens per online CPU
// (PERF_TYPE_SOFTWARE / PERF_COUNT_SW_CPU_CLOCK, freq mode). `current` is the
// task the sample interrupted, so pid_is_target() answers for it directly — in
// PID mode through the target's pid namespace, in CGROUP mode through the
// ancestor cgroup id. Software clock rather than hardware cycles so it works
// in a VM or a container with no PMU exposed.
//
// ctx is typed void* deliberately: bpf_get_stackid takes it as void*, and this
// keeps the include surface to what target.bpf.h already pulls in.
SEC("perf_event")
int handle_cpu_sample(void *ctx)
{
    __u32 key = 0;
    struct cpuprof_rate_stat *r = bpf_map_lookup_elem(&cpuprof_rate, &key);
    if (!r)
        return 0;
    r->fired += 1;

    if (!pid_is_target(&cpuprof_target_pid))
        return 0;
    r->hit += 1;

    __s32 sid = (__s32)bpf_get_stackid(ctx, &cpuprof_stacks, BPF_F_USER_STACK);

    __u64 *n = cpuprof_slot(sid);
    if (n)
        __sync_fetch_and_add(n, 1);
    return 0;
}
