// SPDX-License-Identifier: GPL-2.0
//
// heap.bpf.c — libc heap allocation tracking for the target PID (#53).
//
// Attaches uprobes/uretprobes to the libc allocator entry points and pairs
// each allocation with its free by the returned pointer, deriving:
//   - per-call-site live bytes / alloc count / average lifetime
//   - allocation lifetime (free.ts − alloc.ts), emitted per event
//   - a "large allocation" tag for sizes ≥ 128KB (glibc's M_MMAP_THRESHOLD —
//     the allocations glibc services with a direct mmap rather than the heap)
//
// Probes (attached by the Go loader against the target's mapped libc — see
// internal/bpf/heap.go):
//   uprobe/uretprobe malloc(size)
//   uprobe/uretprobe calloc(nmemb, size)
//   uprobe/uretprobe realloc(ptr, size)   → free(old) + alloc(new)
//   uprobe           free(ptr)
//
// Maps:
//   heap_target_pid     ARRAY[1]     struct target_filter (Go loader writes it)
//   heap_inflight       HASH         pid_tgid → in-flight alloc request; carries
//                                    size+stack from the uprobe entry to the
//                                    uretprobe exit (the public allocator
//                                    symbols never recurse on one thread, so a
//                                    single slot per thread is enough — same
//                                    trick as io.bpf.c).
//   heap_allocs         LRU_HASH     ptr → {size, ts_ns, stack_id}; the live set
//                                    and the pairing/lifetime source. LRU-bounded
//                                    so a long-lived target can't grow it without
//                                    limit — eviction silently drops the oldest
//                                    live allocation, so live-heap UNDERCOUNTS on
//                                    alloc-heavy targets (a documented fidelity
//                                    limit, never claimed exact).
//   heap_callsite_live  HASH         stack_id → aggregate (live bytes/count,
//                                    alloc count, lifetime sum, large count),
//                                    updated in the kernel so userspace iterates
//                                    only this small map (one entry per distinct
//                                    call site) rather than the per-pointer map.
//   heap_stacks         STACK_TRACE  user stacks captured at alloc time; the Go
//                                    side resolves a stack_id to its application
//                                    call-site address (shown in hex until #54
//                                    symbolizes it).
//   heap_events         RINGBUF      per-event stream to userspace (struct
//                                    heap_event, fixed layout, LittleEndian).
//
// Why kernel-side call-site aggregation? Summing live bytes by walking the
// per-pointer map from userspace every tick would cost O(live allocations)
// syscalls. Instead each alloc/free updates heap_callsite_live in place, and a
// free attributes its bytes to the ALLOC site (the stack_id stored in
// heap_allocs[ptr]), not the free site, so per-site live_bytes stays consistent
// regardless of where free() is called from.

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";

// Op codes — shared with the Go side (collector/heap_ebpf.go). For the inflight
// record they identify which allocator is in flight; on the ring-buffer event
// they identify the operation.
#define OP_MALLOC  0
#define OP_CALLOC  1
#define OP_REALLOC 2
#define OP_FREE    3

// glibc's default M_MMAP_THRESHOLD: requests at/above this are serviced with a
// direct mmap. We tag them from the request size alone — no extra probe.
#define HEAP_LARGE_THRESHOLD (128 * 1024)
#define HEAP_FLAG_LARGE 1

// User-stack depth captured per call site. 32 frames is plenty to step over the
// libc allocator internals and reach the application caller.
#define HEAP_STACK_DEPTH 32

// In-flight allocation request, keyed by pid_tgid between entry and exit.
struct inflight {
    __u64 size;     // requested bytes (calloc: nmemb*size)
    __u64 old_ptr;  // realloc's first arg; 0 otherwise
    __s32 stack_id; // bpf_get_stackid result (<0 → unknown)
    __u32 op;
};

// Per-pointer live allocation record. 24 bytes — mirrored by allocInfo in
// internal/bpf/heap.go for the leak scan.
struct alloc_info {
    __u64 size;
    __u64 ts_ns;
    __s32 stack_id;
    __u32 _pad;
};

// Per-call-site running aggregate. Mirrored by HeapCallSiteRaw in heap.go.
// live_bytes/live_count are signed: a free only decrements when its alloc was
// tracked, so they stay ≥ 0 in practice, but signed keeps atomic subtraction
// well-defined and lets the Go side clamp defensively.
struct callsite_stat {
    __s64 live_bytes;
    __s64 live_count;
    __u64 alloc_count;
    __u64 lifetime_sum_ns;
    __u64 lifetime_count;
    __u64 large_count;
};

// Event published to userspace via ring buffer. Fixed 48-byte layout, read with
// binary.LittleEndian on the Go side — keep in sync with HeapEvent in heap.go.
struct heap_event {
    __u64 ts_ns;
    __u64 size;
    __u64 addr;
    __u64 lifetime_ns; // free.ts − alloc.ts; 0 for alloc events
    __s32 stack_id;    // alloc-site stack (<0 → unknown)
    __u32 op;
    __u32 flags;       // bit0 = large (size ≥ HEAP_LARGE_THRESHOLD)
    __u32 tgid;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} heap_target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct inflight);
    __uint(max_entries, 10240);
} heap_inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, struct alloc_info);
    __uint(max_entries, 1 << 17); // 131072 live allocations before eviction
} heap_allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __s32);
    __type(value, struct callsite_stat);
    __uint(max_entries, 8192);
} heap_callsite_live SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, HEAP_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 16384);
} heap_stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB
} heap_events SEC(".maps");

static __always_inline int is_heap_target(void)
{
    return pid_is_target(&heap_target_pid);
}

static __always_inline struct callsite_stat *get_or_init_callsite(__s32 sid)
{
    struct callsite_stat *cs = bpf_map_lookup_elem(&heap_callsite_live, &sid);
    if (cs)
        return cs;
    struct callsite_stat zero = {};
    bpf_map_update_elem(&heap_callsite_live, &sid, &zero, BPF_NOEXIST);
    return bpf_map_lookup_elem(&heap_callsite_live, &sid);
}

static __always_inline void emit(__u64 ts, __u64 size, __u64 addr,
                                 __u64 lifetime, __s32 sid, __u32 op,
                                 __u32 flags, __u32 tgid)
{
    struct heap_event *e = bpf_ringbuf_reserve(&heap_events, sizeof(*e), 0);
    if (!e)
        return;
    e->ts_ns       = ts;
    e->size        = size;
    e->addr        = addr;
    e->lifetime_ns = lifetime;
    e->stack_id    = sid;
    e->op          = op;
    e->flags       = flags;
    e->tgid        = tgid;
    bpf_ringbuf_submit(e, 0);
}

static __always_inline void do_alloc(__u64 ptr, __u64 size, __s32 sid,
                                     __u32 op, __u32 tgid)
{
    __u64 now = bpf_ktime_get_ns();
    struct alloc_info ai = {
        .size     = size,
        .ts_ns    = now,
        .stack_id = sid,
    };
    bpf_map_update_elem(&heap_allocs, &ptr, &ai, BPF_ANY);

    struct callsite_stat *cs = get_or_init_callsite(sid);
    if (cs) {
        __sync_fetch_and_add(&cs->live_bytes, (__s64)size);
        __sync_fetch_and_add(&cs->live_count, 1);
        __sync_fetch_and_add(&cs->alloc_count, 1);
        if (size >= HEAP_LARGE_THRESHOLD)
            __sync_fetch_and_add(&cs->large_count, 1);
    }

    __u32 flags = (size >= HEAP_LARGE_THRESHOLD) ? HEAP_FLAG_LARGE : 0;
    emit(now, size, ptr, 0, sid, op, flags, tgid);
}

static __always_inline void do_free(__u64 ptr, __u32 tgid)
{
    if (ptr == 0)
        return; // free(NULL) is a no-op
    struct alloc_info *ai = bpf_map_lookup_elem(&heap_allocs, &ptr);
    if (!ai)
        return; // untracked: pre-existing block or LRU-evicted — skip

    __u64 now      = bpf_ktime_get_ns();
    __u64 size     = ai->size;
    __s32 sid      = ai->stack_id;
    __u64 lifetime = now - ai->ts_ns;

    // Attribute the freed bytes back to the ALLOC site, not the free site.
    struct callsite_stat *cs = bpf_map_lookup_elem(&heap_callsite_live, &sid);
    if (cs) {
        __sync_fetch_and_add(&cs->live_bytes, -(__s64)size);
        __sync_fetch_and_add(&cs->live_count, -1);
        __sync_fetch_and_add(&cs->lifetime_sum_ns, lifetime);
        __sync_fetch_and_add(&cs->lifetime_count, 1);
    }

    __u32 flags = (size >= HEAP_LARGE_THRESHOLD) ? HEAP_FLAG_LARGE : 0;
    emit(now, size, ptr, lifetime, sid, OP_FREE, flags, tgid);

    bpf_map_delete_elem(&heap_allocs, &ptr);
}

static __always_inline void enter_alloc(void *ctx, __u64 size, __u64 old_ptr,
                                        __u32 op)
{
    if (!is_heap_target())
        return;
    __u64 pt = bpf_get_current_pid_tgid();
    struct inflight inf = {
        .size     = size,
        .old_ptr  = old_ptr,
        .stack_id = (__s32)bpf_get_stackid(ctx, &heap_stacks, BPF_F_USER_STACK),
        .op       = op,
    };
    bpf_map_update_elem(&heap_inflight, &pt, &inf, BPF_ANY);
}

static __always_inline void exit_alloc(__u64 ret)
{
    __u64 pt = bpf_get_current_pid_tgid();
    struct inflight *inf = bpf_map_lookup_elem(&heap_inflight, &pt);
    if (!inf)
        return;
    __u32 op      = inf->op;
    __u64 size    = inf->size;
    __u64 old_ptr = inf->old_ptr;
    __s32 sid     = inf->stack_id;
    __u32 tgid    = (__u32)(pt >> 32);
    bpf_map_delete_elem(&heap_inflight, &pt);

    if (op == OP_REALLOC) {
        // realloc(p, n): the old block is released iff realloc returned a
        // (possibly new) pointer, or n==0 (shrink-to-free). On OOM
        // (ret==0 && n>0) the old block stays live — release nothing.
        if (old_ptr != 0 && (ret != 0 || size == 0))
            do_free(old_ptr, tgid);
        if (ret != 0)
            do_alloc(ret, size, sid, OP_REALLOC, tgid);
        return;
    }

    // malloc / calloc — ret==0 is OOM, emit nothing.
    if (ret != 0)
        do_alloc(ret, size, sid, op, tgid);
}

SEC("uprobe/malloc")
int BPF_KPROBE(uprobe_malloc, __u64 size)
{
    enter_alloc(ctx, size, 0, OP_MALLOC);
    return 0;
}

SEC("uretprobe/malloc")
int BPF_KRETPROBE(uretprobe_malloc, void *ret)
{
    exit_alloc((__u64)ret);
    return 0;
}

SEC("uprobe/calloc")
int BPF_KPROBE(uprobe_calloc, __u64 nmemb, __u64 size)
{
    // A truncating 64-bit product is fine: a real overflow makes calloc return
    // NULL, so the uretprobe sees ret==0 and records nothing — the bogus total
    // is never used. (A manual overflow check via the division idiom makes
    // clang emit a 128-bit __multi3, which the BPF target rejects.)
    enter_alloc(ctx, nmemb * size, 0, OP_CALLOC);
    return 0;
}

SEC("uretprobe/calloc")
int BPF_KRETPROBE(uretprobe_calloc, void *ret)
{
    exit_alloc((__u64)ret);
    return 0;
}

SEC("uprobe/realloc")
int BPF_KPROBE(uprobe_realloc, void *ptr, __u64 size)
{
    enter_alloc(ctx, size, (__u64)ptr, OP_REALLOC);
    return 0;
}

SEC("uretprobe/realloc")
int BPF_KRETPROBE(uretprobe_realloc, void *ret)
{
    exit_alloc((__u64)ret);
    return 0;
}

SEC("uprobe/free")
int BPF_KPROBE(uprobe_free, void *ptr)
{
    if (!is_heap_target())
        return 0;
    do_free((__u64)ptr, (__u32)(bpf_get_current_pid_tgid() >> 32));
    return 0;
}
