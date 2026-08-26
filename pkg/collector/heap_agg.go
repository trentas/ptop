package collector

import (
	"fmt"
	"sort"
	"strings"

	"github.com/trentas/ptop/internal/bpf"
)

// Pure aggregation/formatting helpers for the heap collector (#53), kept free
// of any kernel/eBPF dependency so they unit-test on every platform. The real
// collector (heap_ebpf.go) feeds these from the BPF maps.

// isSuspectedLeak reports whether an allocation of the given age has outlived
// the leak threshold. It is a stateless property of the current live set — a
// suspicion, not a proof (a long-lived cache looks identical to a leak).
func isSuspectedLeak(ageNs, thresholdNs uint64) bool {
	return ageNs > thresholdNs
}

// rawCallSite is ONE STACK's aggregate, before stacks that reach the same
// application call site are folded into one entry. The kernel keys its heap
// aggregates by stack id, and one call site is reached through as many stacks
// as there are paths into the allocator beneath it — a map that grows produces
// a fresh one per growth path. LifetimeSumNs/LifetimeCount are carried
// alongside because a mean cannot be merged, only recomputed from its parts.
type rawCallSite struct {
	HeapCallSite
	LifetimeSumNs uint64
	LifetimeCount uint64
}

// foldCallSites merges per-stack aggregates into per-call-site ones, summing
// the measurements and recomputing the lifetime mean from the pooled sum.
//
// Without this the top-N cut is counted in stacks, which is not the unit anyone
// reading the list thinks in. A function reached through six stacks holds six of
// the eight slots, so a busy site that reaches the allocator one way is pushed
// out by a quieter one that reaches it many ways — and a consumer counting the
// FUNCTIONS it received sees a short list and concludes nothing was dropped
// (#109). Folding first makes the cap mean what it reads as.
//
// Sites whose stack walk failed (CallSite 0, "unknown") fold together too: they
// are one bucket of unattributed allocation, not N distinct sites, and leaving
// them apart lets them crowd out sites that DID resolve.
//
// The identity fields belong to the address, so the first resolution of a site
// wins. StackID cannot be summed and is not dropped either — it keeps the
// heaviest contributing stack, so resolving it still yields a stack that
// genuinely reached this site. It is representative, not exhaustive.
func foldCallSites(raw []rawCallSite) []HeapCallSite {
	type acc struct {
		site      HeapCallSite
		dominant  HeapCallSite
		lifeSumNs uint64
		lifeCount uint64
	}
	order := make([]uint64, 0, len(raw))
	by := make(map[uint64]*acc, len(raw))
	for _, r := range raw {
		a := by[r.CallSite]
		if a == nil {
			by[r.CallSite] = &acc{
				site: r.HeapCallSite, dominant: r.HeapCallSite,
				lifeSumNs: r.LifetimeSumNs, lifeCount: r.LifetimeCount,
			}
			order = append(order, r.CallSite)
			continue
		}
		a.site.LiveBytes += r.LiveBytes
		a.site.AllocBytes += r.AllocBytes
		a.site.AllocCount += r.AllocCount
		a.site.Suspected = a.site.Suspected || r.Suspected
		a.lifeSumNs += r.LifetimeSumNs
		a.lifeCount += r.LifetimeCount
		if outranks(r.HeapCallSite, a.dominant) {
			a.dominant = r.HeapCallSite
		}
	}
	out := make([]HeapCallSite, 0, len(order))
	for _, addr := range order {
		a := by[addr]
		a.site.StackID = a.dominant.StackID
		a.site.AvgLifetimeMs = 0
		if a.lifeCount > 0 {
			a.site.AvgLifetimeMs = float64(a.lifeSumNs) / float64(a.lifeCount) / 1e6
		}
		out = append(out, a.site)
	}
	return out
}

// heapOmitted is what the top-N cut left outside a snapshot: the sites that did
// not fit and the volume they carried.
//
// It exists so absence can be read. A consumer holding a truncated list cannot
// tell a site that stopped allocating from one that stopped being reported, and
// the two call for opposite responses (sunnysystems/witness#69). Sites == 0
// says the list is a census and absence means zero; otherwise these totals
// bound what any single missing site can account for.
type heapOmitted struct {
	Sites      int
	AllocCount uint64
	AllocBytes uint64
	LiveBytes  uint64
}

// outranks reports whether a is more significant than b.
//
// Live bytes rank first, then bytes ever allocated, then allocation count, then
// address and stack for a deterministic tie-break. The AllocBytes tier is what
// makes this work unchanged on the Go lane: there LiveBytes is 0 for every site
// (nothing observes a free), so the comparison falls straight through to
// allocation volume — the ranking that means something there — instead of
// collapsing into an address sort.
func outranks(a, b HeapCallSite) bool {
	switch {
	case a.LiveBytes != b.LiveBytes:
		return a.LiveBytes > b.LiveBytes
	case a.AllocBytes != b.AllocBytes:
		return a.AllocBytes > b.AllocBytes
	case a.AllocCount != b.AllocCount:
		return a.AllocCount > b.AllocCount
	case a.CallSite != b.CallSite:
		return a.CallSite < b.CallSite
	default:
		return a.StackID < b.StackID
	}
}

// topCallSites returns the n most significant call sites, descending, together
// with an account of what it dropped. n < 0 keeps all.
func topCallSites(sites []HeapCallSite, n int) ([]HeapCallSite, heapOmitted) {
	out := make([]HeapCallSite, len(sites))
	copy(out, sites)
	sort.Slice(out, func(i, j int) bool { return outranks(out[i], out[j]) })
	if n < 0 || len(out) <= n {
		return out, heapOmitted{}
	}
	var om heapOmitted
	for _, s := range out[n:] {
		om.Sites++
		om.AllocCount += s.AllocCount
		om.AllocBytes += s.AllocBytes
		om.LiveBytes += s.LiveBytes
	}
	return out[:n], om
}

// chooseTopCallSites is topCallSites for callers that do not report what was
// dropped.
func chooseTopCallSites(sites []HeapCallSite, n int) []HeapCallSite {
	top, _ := topCallSites(sites, n)
	return top
}

// pickAppFrame returns the first stack frame outside the libc address range —
// the application site that called the allocator. Frames are leaf-first (libc
// internals first). Falls back to the leaf frame when every frame is inside
// libc, and to 0 when there are no frames.
func pickAppFrame(frames []uint64, libcLo, libcHi uint64) uint64 {
	for _, f := range frames {
		if f == 0 {
			continue
		}
		if libcHi > libcLo && f >= libcLo && f < libcHi {
			continue // inside libc — keep walking toward the caller
		}
		return f
	}
	if len(frames) > 0 {
		return frames[0]
	}
	return 0
}

// pickGoAppFrame returns the first stack frame outside the Go runtime — the
// application site that allocated. Frames are leaf-first (runtime.mallocgc and
// its callers first); nameAt resolves a frame address to a function name, or
// "" when it cannot.
//
// The libc lane can filter by address range because libc is a separate mapped
// module. On the Go lane the runtime and the application are the SAME module,
// linked into one binary, so there is no range to exclude — the only thing
// separating them is the package a function belongs to. Hence a name filter.
//
// An unresolvable frame ("") is treated as application code rather than
// skipped: on a stripped module every name is empty, and skipping them all
// would walk the whole stack and return the leaf — reporting runtime.mallocgc
// itself as the call site, which is the one answer that is never useful.
//
// Falls back to the leaf frame when every frame is runtime code, and to 0 when
// there are no frames.
func pickGoAppFrame(frames []uint64, nameAt func(uint64) string) uint64 {
	for _, f := range frames {
		if f == 0 {
			continue
		}
		if isGoRuntimeFunc(nameAt(f)) {
			continue // still inside the allocator — keep walking toward the caller
		}
		return f
	}
	if len(frames) > 0 {
		return frames[0]
	}
	return 0
}

// isGoRuntimeFunc reports whether a symbolized function name belongs to the Go
// runtime rather than to code someone wrote.
//
// "internal/runtime/" covers the packages the runtime was split into (maps,
// atomic, sys, math), which allocate on the runtime's behalf and would
// otherwise be reported as the application call site for every map growth.
func isGoRuntimeFunc(name string) bool {
	return strings.HasPrefix(name, "runtime.") ||
		strings.HasPrefix(name, "internal/runtime/")
}

// sampledRate is the Go lane's sampling rate as the wire reports it: 0 when
// nothing was estimated.
//
// A rate of ONE BYTE records every allocation — any allocation crosses it
// immediately — so it is exact, and publishing it as a sampling rate would be
// wrong in the one direction that matters: sample_bytes > 0 is precisely what a
// consumer branches on to know the per-site split is an estimate rather than a
// census. Userspace spells "every allocation" as 1 rather than 0 so that the
// zero value of SetConfig can mean the safe default instead (#108).
func sampledRate(rate uint64) uint64 {
	if rate <= 1 {
		return 0
	}
	return rate
}

// heapAddrHex formats a call-site address for display; 0 means the stack walk
// failed (no frame pointers) and renders as "unknown".
func heapAddrHex(addr uint64) string {
	if addr == 0 {
		return "unknown"
	}
	return fmt.Sprintf("0x%x", addr)
}

// heapOpName maps a kernel op code to its event-stream string.
func heapOpName(op uint32) string {
	switch op {
	case bpf.HeapOpMalloc:
		return "malloc"
	case bpf.HeapOpCalloc:
		return "calloc"
	case bpf.HeapOpRealloc:
		return "realloc"
	case bpf.HeapOpFree:
		return "free"
	default:
		return "?"
	}
}
