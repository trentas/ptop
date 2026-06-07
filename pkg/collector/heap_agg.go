package collector

import (
	"fmt"
	"sort"

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

// chooseTopCallSites returns the n call sites with the most live bytes,
// descending. Ties break by AllocCount then CallSite for a deterministic order.
// n < 0 keeps all.
func chooseTopCallSites(sites []HeapCallSite, n int) []HeapCallSite {
	out := make([]HeapCallSite, len(sites))
	copy(out, sites)
	sort.Slice(out, func(i, j int) bool {
		if out[i].LiveBytes != out[j].LiveBytes {
			return out[i].LiveBytes > out[j].LiveBytes
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
