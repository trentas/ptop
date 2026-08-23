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
//   goalloc_events      RINGBUF      per-allocation stream to userspace
//                                    (struct go_alloc_event, fixed layout,
//                                    LittleEndian).

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

// Event published to userspace via ring buffer. Fixed 32-byte layout, read
// with binary.LittleEndian on the Go side — keep in sync with GoAllocEvent in
// internal/bpf/goalloc.go.
struct go_alloc_event {
    __u64 ts_ns;
    __u64 size;
    __s32 stack_id; // alloc-site stack (<0 → unknown)
    __u32 flags;    // bit0 = large (size ≥ GOALLOC_LARGE_THRESHOLD)
    __u32 tgid;
    __u32 _pad;
};

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

    __s32 sid = (__s32)bpf_get_stackid(ctx, &goalloc_stacks, BPF_F_USER_STACK);
    __u32 flags = (size >= GOALLOC_LARGE_THRESHOLD) ? GOALLOC_FLAG_LARGE : 0;

    struct go_callsite_stat *cs = get_or_init_site(sid);
    if (cs) {
        __sync_fetch_and_add(&cs->alloc_count, 1);
        __sync_fetch_and_add(&cs->alloc_bytes, size);
        if (flags & GOALLOC_FLAG_LARGE)
            __sync_fetch_and_add(&cs->large_count, 1);
    }

    struct go_alloc_event *e =
        bpf_ringbuf_reserve(&goalloc_events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->ts_ns    = bpf_ktime_get_ns();
    e->size     = size;
    e->stack_id = sid;
    e->flags    = flags;
    e->tgid     = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e->_pad     = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
