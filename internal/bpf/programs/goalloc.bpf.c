// SPDX-License-Identifier: GPL-2.0
//
// goalloc.bpf.c — Go heap allocation tracking for the target PID.
//
// Why this exists at all: heap.bpf.c hangs its uprobes on the libc allocator,
// and the Go runtime does not route through it. `runtime.mallocgc` carves out
// of per-P caches backed by mmap'd spans, so a Go target produces an entirely
// EMPTY heap call-site axis under heap.bpf.c — not a sparse one, an empty one.
// The axis is the only thing in the signature that carries func/file/line, so
// for a Go fleet the whole behaviour → code link is missing.
//
// Probe: one uprobe on `runtime.mallocgc`, the single funnel every Go heap
// allocation passes through. `newobject`, `makeslice`, `growslice` and
// `reflect.unsafe_New` all call it, and the size-specialised fast paths
// (mallocgcTiny / mallocgcSmallNoscan / mallocgcSmallScanHeader /
// mallocgcLarge, plus the generated SC1..N variants) are dispatched from
// INSIDE its body — so probing the entry catches all of them exactly once.
//
// ─── Entry only, and why that is a design choice, not a shortcut ────────────
//
// There is no uretprobe here and no free pairing, so this program reports
// allocation RATE and VOLUME per call site, never live bytes or lifetime.
// Two independent reasons, either one sufficient:
//
//  1. A uretprobe on a Go function is unsafe. The kernel implements it by
//     patching the return address on the stack; the Go runtime copies and
//     moves goroutine stacks when they grow, and walks them during GC and
//     traceback. The patched address is not one it can relocate or recognise.
//     Production Go tracers avoid uretprobes on runtime functions for exactly
//     this reason.
//  2. Nothing frees a Go allocation at a point a probe could observe. The GC
//     sweeper reclaims spans in bulk, asynchronously, with no per-object call
//     naming the object. Pairing alloc→free the way heap.bpf.c does has no
//     counterpart to attach to.
//
// So the honest surface is alloc_count / alloc_bytes per site. The userspace
// side marks live/lifetime UNMEASURED rather than publishing a zero, because a
// zero would read as "nothing is live", which is false, and would diff against
// a libc-lane baseline as a collapse to zero.
//
// ─── Sampling, and why the probe cannot afford to run in full ────────────────
//
// The expensive part of this probe is not the counting, it is bpf_get_stackid:
// a user stack walk, up to GOALLOC_STACK_DEPTH frames, on every allocation. It
// runs on the thread that allocated, so its cost lands in the TARGET's own CPU
// accounting — measured at +110% of the target's CPU time at 114k
// allocations/s and +404% at 1.2M/s (bench/results/). Two things follow.
//
// The obvious one: ptop was multiplying the cost of the program it was
// watching. The subtle one, and the reason this is not merely a tax: ptop's own
// CPU axis samples the target on-CPU, so it reported that inflated figure AS
// THE TARGET'S CPU — a Go service came out at ten times what /proc said, and
// the alloc-heavy arm of an A/B pair came out hotter than the compute-heavy
// one, inverting the very comparison the axis exists for (#108).
//
// So the stack walk is sampled, by BYTES ALLOCATED, the way Go's own heap
// profiler samples (runtime.MemProfileRate, 512KB). A per-CPU accumulator adds
// up size and count; only when it crosses a RANDOM threshold averaging the
// configured rate does an allocation take a stack, and it is then credited with
// everything accumulated since the last one. The threshold is random for the
// reason Go's is — see goalloc_next_threshold. Consequences worth being precise about:
//
//   - TOTALS STAY EXACT. Every byte and every allocation is attributed to some
//     site; none is discarded. alloc_bytes and alloc_count summed over all
//     sites equal what the target really did.
//   - PER-SITE ATTRIBUTION BECOMES AN ESTIMATE, proportional to bytes. A site
//     allocating a large share of the bytes is sampled proportionally often; a
//     site that allocates rarely may be missed in a short window.
//   - LARGE ALLOCATIONS ARE NEVER SAMPLED AWAY. An allocation at or above the
//     large threshold always takes the sample point, so large_count stays exact
//     and the object that actually moved the heap is always attributed.
//
// A rate of 0 skips the sampler entirely and a rate of 1 byte passes every
// allocation through it: both record everything, which is the only way to get
// exact per-site numbers and what the overhead benchmark measures against. It
// is not a reasonable default on an allocation-heavy target. Userspace asks for
// it with 1 rather than 0, so that an unset field means the safe default rather
// than the exhaustive one; 0 remains the map's pre-write value and behaves the
// same way.
//
// Register ABI: Go uses ABIInternal (register-based) since Go 1.17, NOT the
// SysV C ABI that BPF_KPROBE/PT_REGS_PARM1 assume. mallocgc's first argument
// (size uintptr) arrives in RAX on x86-64 and in X0 on arm64. libbpf's
// PT_REGS_RC macro names precisely those two registers (__PT_RC_REG is `rax`
// / `regs[0]`), so it — not PT_REGS_PARM1 — is the portable way to read Go's
// first argument. See GO_ARG0 below.
//
// Maps:
//   goalloc_target_pid  ARRAY[1]     struct target_filter (Go loader writes it)
//   goalloc_callsite    HASH         stack_id → aggregate (alloc count/bytes,
//                                    large count), summed in the kernel so
//                                    userspace iterates one entry per distinct
//                                    call site instead of per event.
//   goalloc_stacks      STACK_TRACE  user stacks captured at alloc time; the Go
//                                    side resolves a stack_id to the
//                                    application frame and symbolizes it
//                                    through .gopclntab (func + file:line).
//   goalloc_events      RINGBUF      sampled allocation stream to userspace
//                                    (struct go_alloc_event, fixed layout,
//                                    LittleEndian).
//   goalloc_config      ARRAY[1]     sample_bytes: bytes of allocation between
//                                    recorded samples (0 = record every one).
//   goalloc_accum       PERCPU_ARRAY per-CPU counters: bytes/count since this
//                                    CPU's last recorded sample and the random
//                                    threshold for the next one, plus running
//                                    totals over EVERY allocation (the rate).

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";

// GO_ARG0 reads the Go ABIInternal first argument register.
//
// PT_REGS_RC expands to the ABI's return register — `rax` on x86-64,
// `regs[0]` on arm64 (see __PT_RC_REG in bpf_tracing.h). Those are the same
// two registers Go's register ABI uses for the first integer argument, which
// is why this aliases the return macro instead of PT_REGS_PARM1: PT_REGS_PARM1
// would read `rdi` on x86-64, a register mallocgc does not use.
#define GO_ARG0(ctx) PT_REGS_RC(ctx)

// Go's large-object boundary: allocations above maxSmallSize (32KB) skip the
// per-P cache and are served straight from the heap by mallocgcLarge. That is
// the size boundary that means something in a Go process — deliberately NOT
// glibc's 128KB M_MMAP_THRESHOLD, which describes a different allocator.
#define GOALLOC_LARGE_THRESHOLD (32 * 1024)
#define GOALLOC_FLAG_LARGE 1

// User-stack depth captured per call site. Matches HEAP_STACK_DEPTH: enough to
// step over the runtime's allocation frames and reach application code.
#define GOALLOC_STACK_DEPTH 32

// Per-call-site running aggregate. Mirrored by GoAllocCallSiteRaw in
// internal/bpf/goalloc.go. All unsigned and monotonic — nothing decrements
// these, because nothing observes a free.
struct go_callsite_stat {
    __u64 alloc_count;
    __u64 alloc_bytes;
    __u64 large_count;
};

// Event published to userspace via ring buffer. Fixed 48-byte layout, read
// with binary.LittleEndian on the Go side — keep in sync with GoAllocEvent in
// internal/bpf/goalloc.go.
//
// size is the sampled allocation's own size; weight_bytes/weight_count are what
// it stands for — everything accumulated since the previous sample on this CPU,
// itself included. With sampling off they are size and 1.
struct go_alloc_event {
    __u64 ts_ns;
    __u64 size;
    __u64 weight_bytes;
    __u64 weight_count;
    __s32 stack_id; // alloc-site stack (<0 → unknown)
    __u32 flags;    // bit0 = large (size ≥ GOALLOC_LARGE_THRESHOLD)
    __u32 tgid;
    __u32 _pad;
};

// Per-CPU counters. Per-CPU rather than global because a BPF program runs with
// preemption disabled, which makes the update contention-free and lock-free — a
// global counter here would put an atomic on the hottest path in the program.
//
// bytes/count reset at every recorded sample; next is the threshold bytes has
// to reach for the next one. total_bytes/total_count never reset and count
// EVERY allocation, sampled or not: they are what the allocation RATE is
// computed from. Deriving the rate from the sampled events instead would make
// it lumpy — a target allocating less than one sample's worth per publish
// interval would report zero, then a spike — and would also lose whatever the
// ring buffer dropped. Two adds on a cache line the program has already touched
// is the whole cost of avoiding that.
struct goalloc_accum {
    __u64 bytes;
    __u64 count;
    __u64 next;
    __u64 total_bytes;
    __u64 total_count;
};

// goalloc_next_threshold draws the next sampling threshold: uniform over
// [1, 2*rate], so the mean stays at rate.
//
// RANDOM, not fixed, and this is the load-bearing part. Allocation patterns are
// periodic — a request handler allocates the same objects in the same order
// every time round — and a FIXED threshold crossed by a periodic byte stream
// always crosses at the same phase of the cycle, so the same call site takes
// every sample and the others take none. Measured on a workload alternating a
// 152-byte allocation with a 1048-byte one, a fixed threshold attributed the
// bytes 1.1:1 where the truth is 6.9:1. With a random threshold the crossing
// lands at a uniformly distributed byte offset, which is what makes a site's
// share of the samples equal its share of the bytes.
//
// bpf_get_prandom_u32 caps the span at 2^32, so a rate above 2GB samples more
// often than asked rather than not at all. Nobody is setting that, but silently
// sampling nothing would be the worse failure.
static __always_inline __u64 goalloc_next_threshold(__u64 rate)
{
    __u64 span = rate << 1;
    if (span < rate || span > 0xffffffffULL) // overflow, or past prandom's range
        span = 0xffffffffULL;
    return 1 + (__u64)bpf_get_prandom_u32() % span;
}

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} goalloc_target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __s32);
    __type(value, struct go_callsite_stat);
    __uint(max_entries, 8192);
} goalloc_callsite SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, GOALLOC_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 16384);
} goalloc_stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB
} goalloc_events SEC(".maps");

// sample_bytes, written by the Go loader. 0 records every allocation.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} goalloc_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct goalloc_accum);
    __uint(max_entries, 1);
} goalloc_accum SEC(".maps");

static __always_inline int is_goalloc_target(void)
{
    return pid_is_target(&goalloc_target_pid);
}

static __always_inline struct go_callsite_stat *get_or_init_site(__s32 sid)
{
    struct go_callsite_stat *cs = bpf_map_lookup_elem(&goalloc_callsite, &sid);
    if (cs)
        return cs;
    struct go_callsite_stat zero = {};
    bpf_map_update_elem(&goalloc_callsite, &sid, &zero, BPF_NOEXIST);
    return bpf_map_lookup_elem(&goalloc_callsite, &sid);
}

// uprobe_go_mallocgc fires on entry to runtime.mallocgc.
//
// mallocgc(size uintptr, typ *_type, needzero bool) unsafe.Pointer
//          ^^^^ GO_ARG0
//
// A size of 0 is a real call (Go short-circuits it to &zerobase) but allocates
// nothing, so it is dropped rather than inflating the site's alloc_count with
// allocations that never happened.
SEC("uprobe/runtime.mallocgc")
int uprobe_go_mallocgc(struct pt_regs *ctx)
{
    if (!is_goalloc_target())
        return 0;

    __u64 size = (__u64)GO_ARG0(ctx);
    if (size == 0)
        return 0;

    __u32 key = 0;
    __u32 flags = (size >= GOALLOC_LARGE_THRESHOLD) ? GOALLOC_FLAG_LARGE : 0;
    __u64 weight_bytes = size, weight_count = 1;

    struct goalloc_accum *acc = bpf_map_lookup_elem(&goalloc_accum, &key);
    if (!acc)
        return 0;
    acc->total_bytes += size;
    acc->total_count += 1;

    // Everything above the stack walk is cheap; everything below it is not.
    // The accumulate-and-return path is the one nearly every allocation takes.
    //
    // A rate of 0 or 1 means record everything, and skips the sampler outright
    // rather than running it with a threshold every allocation crosses.
    __u64 *rate = bpf_map_lookup_elem(&goalloc_config, &key);
    if (rate && *rate > 1) {
        acc->bytes += size;
        acc->count += 1;
        if (acc->next == 0)
            acc->next = goalloc_next_threshold(*rate);
        // A large allocation always takes the sample point, so large_count and
        // the attribution of the objects that actually move the heap stay
        // exact however coarse the rate is.
        if (!(flags & GOALLOC_FLAG_LARGE) && acc->bytes < acc->next)
            return 0;
        weight_bytes = acc->bytes;
        weight_count = acc->count;
        acc->bytes = 0;
        acc->count = 0;
        acc->next = goalloc_next_threshold(*rate);
    }

    __s32 sid = (__s32)bpf_get_stackid(ctx, &goalloc_stacks, BPF_F_USER_STACK);

    struct go_callsite_stat *cs = get_or_init_site(sid);
    if (cs) {
        __sync_fetch_and_add(&cs->alloc_count, weight_count);
        __sync_fetch_and_add(&cs->alloc_bytes, weight_bytes);
        if (flags & GOALLOC_FLAG_LARGE)
            __sync_fetch_and_add(&cs->large_count, 1);
    }

    struct go_alloc_event *e =
        bpf_ringbuf_reserve(&goalloc_events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->ts_ns        = bpf_ktime_get_ns();
    e->size         = size;
    e->weight_bytes = weight_bytes;
    e->weight_count = weight_count;
    e->stack_id     = sid;
    e->flags        = flags;
    e->tgid         = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e->_pad         = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
