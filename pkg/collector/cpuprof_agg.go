package collector

import (
	"fmt"
	"sort"

	"github.com/trentas/ptop/pkg/symbol"
)

// Pure aggregation helpers for the CPU attribution collector (#125), kept free
// of any kernel/eBPF dependency so they unit-test on every platform. The real
// collector (cpuprof_ebpf.go) feeds these from the BPF maps.

// rawCPUSite is ONE STACK's sample count, before stacks landing in the same
// function are folded together. Frame is the symbolization of the stack's LEAF
// — the function that was executing — and Addr its raw instruction pointer, 0
// when the walk failed.
type rawCPUSite struct {
	Addr    uint64
	Frame   symbol.Frame
	StackID int32
	Samples uint64
}

// cpuFoldKey is the identity two samples have to share to be the same site.
//
// This is where the heap axis's foldCallSites (#109) does NOT transfer, and
// getting it wrong is not a rounding error. An allocation call site is one
// specific call instruction, so folding heap aggregates by address is right. A
// CPU sample lands wherever the program counter happened to be inside a
// function body, so folding by address shatters one hot function into as many
// entries as it has sampled instructions — each holding one or two samples,
// none of them ranking, and a top-N that is pure noise.
//
// So: by function when there is one. By MODULE when the address resolved to a
// mapped image but no symbol — "the time is in libfoo.so, function unknown" is
// true, useful and keeps the list rankable, where folding a stripped binary by
// instruction offset would fragment it exactly the way folding by address does.
// By address only when even the module is unknown, which means /proc/<pid>/maps
// did not cover it and there is no coarser identity available to honestly use.
func cpuFoldKey(r rawCPUSite) string { return cpuSiteOf(r).Key() }

// Key is the identity two samples must share to be the same site — see
// cpuFoldKey for why it is a function and not an address.
//
// Exported because the fold happens twice: once in the collector, over one
// window's stacks, and again in any consumer merging several windows (the TUI
// aggregates ~30s of them, since one second of a lightly loaded target is too
// few samples to rank). Two copies of this rule would drift, and the drift
// would be silent — a consumer folding differently from the collector produces
// a plausible list that disagrees with the one on the wire.
//
// It is an identity within one process, not across processes: Module+Func is
// stable across runs and ASLR, but an unsymbolized site keys on its module and
// a wholly unresolved one on its raw address, which is not.
func (s CPUSite) Key() string {
	switch {
	case s.Func != "":
		return "f\x00" + s.Module + "\x00" + s.Func
	case s.Module != "":
		return "m\x00" + s.Module
	default:
		return fmt.Sprintf("a\x00%x", s.Addr)
	}
}

// foldCPUSites merges per-stack sample counts into per-function ones and
// returns them with the samples that could not be attributed at all.
//
// A stack with no usable leaf (Addr 0) is NOT given a bucket: it goes to the
// unresolved count. Letting it fold into a site would put "unknown" into the
// ranking, where on a capture the sampler cannot see into it would win every
// time and push out the handful of functions that did resolve — reporting a
// nearly blind axis as a confident one-item profile.
//
// Within a bucket the DOMINANT sample (the most-sampled leaf address) supplies
// the identity fields, which is what makes Line the hottest line inside the
// function rather than an arbitrary one: each distinct leaf address is its own
// stack id, so the dominant raw is by construction the busiest instruction.
func foldCPUSites(raw []rawCPUSite) (sites []CPUSite, unresolved uint64) {
	type acc struct {
		site     CPUSite
		dominant uint64 // samples held by the raw that donated the identity
	}
	order := make([]string, 0, len(raw))
	by := make(map[string]*acc, len(raw))
	for _, r := range raw {
		if r.Addr == 0 {
			unresolved += r.Samples
			continue
		}
		key := cpuFoldKey(r)
		a := by[key]
		if a == nil {
			by[key] = &acc{site: cpuSiteOf(r), dominant: r.Samples}
			order = append(order, key)
			continue
		}
		a.site.Samples += r.Samples
		if r.Samples > a.dominant {
			// A new dominant sample re-donates every identity field, so Addr,
			// Line, Offset and StackID stay one coherent observation rather
			// than a mix of two.
			samples := a.site.Samples
			a.site = cpuSiteOf(r)
			a.site.Samples = samples
			a.dominant = r.Samples
		}
	}
	sites = make([]CPUSite, 0, len(order))
	for _, key := range order {
		sites = append(sites, by[key].site)
	}
	return sites, unresolved
}

// cpuSiteOf projects one raw stack onto the published shape.
func cpuSiteOf(r rawCPUSite) CPUSite {
	return CPUSite{
		Addr:    r.Addr,
		AddrHex: cpuAddrHex(r.Addr),
		Func:    r.Frame.Func,
		File:    r.Frame.File,
		Line:    r.Frame.Line,
		Module:  r.Frame.Module,
		Offset:  r.Frame.Offset,
		StackID: r.StackID,
		Samples: r.Samples,
	}
}

// cpuOmitted is what the top-N cut left outside a profile: how many functions
// did not fit and how many samples they held.
//
// Same contract as heapOmitted, for the same reason: with a truncated list a
// consumer cannot tell a function that stopped running from one that stopped
// being reported, and the two call for opposite responses. Sites == 0 says the
// list is a census; otherwise Samples bounds what any single missing function
// can account for.
type cpuOmitted struct {
	Sites   int
	Samples uint64
}

// outranksCPUSite reports whether a is more significant than b: samples first,
// then a deterministic tie-break so a profile does not reshuffle between
// windows for no reason.
func outranksCPUSite(a, b CPUSite) bool {
	switch {
	case a.Samples != b.Samples:
		return a.Samples > b.Samples
	case a.Func != b.Func:
		return a.Func < b.Func
	case a.Module != b.Module:
		return a.Module < b.Module
	default:
		return a.Addr < b.Addr
	}
}

// topCPUSites returns the n most-sampled functions, descending, with an account
// of what it dropped. n < 0 keeps all.
func topCPUSites(sites []CPUSite, n int) ([]CPUSite, cpuOmitted) {
	out := make([]CPUSite, len(sites))
	copy(out, sites)
	sort.Slice(out, func(i, j int) bool { return outranksCPUSite(out[i], out[j]) })
	if n < 0 || len(out) <= n {
		return out, cpuOmitted{}
	}
	var om cpuOmitted
	for _, s := range out[n:] {
		om.Sites++
		om.Samples += s.Samples
	}
	return out[:n], om
}

// withCPUShares fills SharePct against total, which INCLUDES the unresolved
// samples. The shares therefore sum to less than 100 exactly when the axis
// could not see part of what the target was doing, and that shortfall is the
// honest reading of it — normalising over the resolved samples alone would
// present a 6%-visible profile as if it were the whole picture.
func withCPUShares(sites []CPUSite, total uint64) []CPUSite {
	if total == 0 {
		return sites
	}
	for i := range sites {
		sites[i].SharePct = float64(sites[i].Samples) / float64(total) * 100
	}
	return sites
}

// cpuAddrHex formats a sample address for display; 0 means the stack walk
// failed, which foldCPUSites keeps out of the list entirely.
func cpuAddrHex(addr uint64) string {
	if addr == 0 {
		return "unknown"
	}
	return fmt.Sprintf("0x%x", addr)
}

// achievedHz turns the sampler's own delivery count into the per-CPU frequency
// it actually ran at over a window. Zero when there is nothing to divide by,
// never a fallback to the requested rate: publishing the requested rate as
// though it had been measured is the specific mistake #108 was about.
func achievedHz(firedDelta uint64, windowSeconds float64, ncpu int) float64 {
	if windowSeconds <= 0 || ncpu <= 0 {
		return 0
	}
	return float64(firedDelta) / windowSeconds / float64(ncpu)
}
