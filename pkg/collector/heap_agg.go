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

// chooseTopCallSites returns the n most significant call sites, descending.
// n < 0 keeps all.
//
// Live bytes rank first, then bytes ever allocated, then allocation count,
// then the address for a deterministic tie-break. The AllocBytes tier is what
// makes this work unchanged on the Go lane: there LiveBytes is 0 for every
// site (nothing observes a free), so the comparison falls straight through to
// allocation volume — the ranking that means something there — instead of
// collapsing into an address sort.
func chooseTopCallSites(sites []HeapCallSite, n int) []HeapCallSite {
	out := make([]HeapCallSite, len(sites))
	copy(out, sites)
	sort.Slice(out, func(i, j int) bool {
		if out[i].LiveBytes != out[j].LiveBytes {
			return out[i].LiveBytes > out[j].LiveBytes
		}
		if out[i].AllocBytes != out[j].AllocBytes {
			return out[i].AllocBytes > out[j].AllocBytes
		}
		if out[i].AllocCount != out[j].AllocCount {
			return out[i].AllocCount > out[j].AllocCount
		}
		return out[i].CallSite < out[j].CallSite
	})
	if n >= 0 && len(out) > n {
		out = out[:n]
	}
	return out
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
