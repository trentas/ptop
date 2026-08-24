package collector

import (
	"fmt"
	"sort"
	"strings"

	"github.com/trentas/ptop/pkg/symbol"
)

// Pure aggregation helpers for the futex collector (#89), kept free of any
// kernel/eBPF dependency so they unit-test on every platform. The real
// collector (futex_ebpf.go) feeds these from the BPF maps and symbolizes the
// call site each lock ends up named by.

// lockSite is the resolved contention site for a stack_id: the raw frame
// address plus its symbolization. An empty frame means no application code was
// found on the stack — see pickLockSite.
type lockSite struct {
	addr  uint64
	frame symbol.Frame
}

// pickLockSite chooses the frame that names a lock, walking the leaf-first
// contention stack past the machinery every lock goes through and stopping at
// the first frame belonging to code someone wrote. resolve symbolizes a frame
// address; nil means no symbolizer (cgroup mode), where only the leaf address
// is available.
//
// Walking past the machinery is the whole point (#107). The leaf of a futex
// wait is the primitive's syscall wrapper — libc's `__lll_lock_wait`, or in a
// Go binary `runtime.futex` at one fixed line of sys_linux_$GOARCH.s. EVERY
// lock in the process passes through it, so naming a lock by that frame gives
// every lock in the process the same name and collapses them into one entry.
// That is strictly worse than the bare futex word it replaced: the address at
// least told two locks apart.
//
// When nothing but machinery is on the stack — contention genuinely internal to
// the runtime, which is where a Go program's futex traffic actually lives,
// since sync.Mutex parks a goroutine and only the scheduler reaches a futex —
// the site is reported as the ADDRESS ALONE, with no symbol. A caller that
// keys on the symbolized site then finds none and falls back to the futex word,
// which distinguishes locks again. Reporting the wrapper's name here would be
// reporting a name that means "some lock".
func pickLockSite(frames []uint64, resolve func(uint64) symbol.Frame) lockSite {
	leaf := uint64(0)
	for _, f := range frames {
		if f == 0 {
			continue
		}
		if leaf == 0 {
			leaf = f
		}
		if resolve == nil {
			break
		}
		fr := resolve(f)
		// isLoaderModule covers the libc lane, where the pthread/futex
		// wrappers sit in their own module; isLockInfraFunc covers the Go lane,
		// where they do not.
		if isLoaderModule(fr.Module) || isLockInfraFunc(fr.Func) {
			continue // still inside the locking machinery — keep walking
		}
		return lockSite{addr: f, frame: fr}
	}
	return lockSite{addr: leaf}
}

// isLockInfraFunc reports whether a symbolized function is part of the locking
// machinery rather than the code that took the lock.
//
// The Go runtime and the application are ONE module, so unlike the libc lane
// there is no address range to exclude — only the package a function belongs
// to (the same reason heap_agg.go filters Go allocation frames by name). sync
// and internal/sync are in here beside the runtime because they are the
// primitive, not its caller: a lock named sync.(*Mutex).Lock says no more than
// runtime.futex does.
func isLockInfraFunc(name string) bool {
	if name == "" {
		return false // unresolved: treat as application code, not as machinery
	}
	return isGoRuntimeFunc(name) ||
		strings.HasPrefix(name, "sync.") ||
		strings.HasPrefix(name, "internal/sync.")
}

// lockSample is one row of the kernel's futex_stats map: everything a single
// (futex word, contention site) pair accumulated since the tracer started.
// StackID < 0 means no site was captured — every wake-class call lands there,
// and so does a wait whose stack walk failed (no frame pointers).
type lockSample struct {
	UAddr       uint64
	StackID     int32
	WaitCount   uint64
	WakeCount   uint64
	LatSumNs    uint64
	LatCount    uint64
	LastWaitTID int
	LastWakeTID int
}

// lockAcc accumulates one lock's rows while aggregateLocks folds them.
type lockAcc struct {
	entry     LockEntry
	latSum    uint64
	latCount  uint64
	bestWaits uint64 // waits of the dominant (named) site so far
	maxWaits  uint64 // waits of the row LastWaitTID came from
	maxWakes  uint64 // wakes of the row LastWakeTID came from
}

// aggregateLocks folds the per-(lock, site) rows into one entry per lock and
// names each lock by its DOMINANT contention site — the one accounting for most
// of its waits. A lock taken from several places therefore reports the site
// that is actually serializing it, and reports it stably: the same site wins
// again next window unless the contention itself moves.
//
// WaitDelta is measured against prevWaits (per-lock cumulative wait totals from
// the previous window); the returned map replaces it. A lock whose total went
// backwards (its rows fell out of the map) reports a delta of 0 rather than
// wrapping around.
//
// Call sites come out as StackID only — symbolizing one needs the tracer, so
// that belongs to the collector.
func aggregateLocks(samples []lockSample, prevWaits map[uint64]uint64) ([]LockEntry, map[uint64]uint64) {
	// Fold in a fixed order so a tie between two equally-hot sites always
	// resolves the same way (map iteration in the caller does not).
	rows := make([]lockSample, len(samples))
	copy(rows, samples)
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].UAddr != rows[j].UAddr {
			return rows[i].UAddr < rows[j].UAddr
		}
		return rows[i].StackID < rows[j].StackID
	})

	accs := make(map[uint64]*lockAcc, len(rows))
	order := make([]uint64, 0, len(rows))
	for _, r := range rows {
		a := accs[r.UAddr]
		if a == nil {
			a = &lockAcc{entry: LockEntry{UAddr: r.UAddr, StackID: -1}}
			accs[r.UAddr] = a
			order = append(order, r.UAddr)
		}
		a.entry.Waiters += r.WaitCount
		a.entry.Wakers += r.WakeCount
		a.latSum += r.LatSumNs
		a.latCount += r.LatCount

		// The dominant site names the lock. Only a real captured stack can:
		// the StackID < 0 row is the wake path and the failed walks.
		if r.StackID >= 0 && r.WaitCount > a.bestWaits {
			a.bestWaits = r.WaitCount
			a.entry.StackID = r.StackID
		}
		// Last waiter/waker: keep the one from the busiest row, so a single
		// stray call can't overwrite the tid of the site doing the blocking.
		if r.LastWaitTID != 0 && r.WaitCount >= a.maxWaits {
			a.maxWaits = r.WaitCount
			a.entry.LastWaitTID = r.LastWaitTID
		}
		if r.LastWakeTID != 0 && r.WakeCount >= a.maxWakes {
			a.maxWakes = r.WakeCount
			a.entry.LastWakeTID = r.LastWakeTID
		}
	}

	out := make([]LockEntry, 0, len(order))
	curWaits := make(map[uint64]uint64, len(order))
	for _, uaddr := range order {
		a := accs[uaddr]
		e := a.entry
		if a.latCount > 0 {
			e.LatencyMs = float64(a.latSum) / float64(a.latCount) / 1e6
		}
		if prev := prevWaits[uaddr]; e.Waiters > prev {
			e.WaitDelta = e.Waiters - prev
		}
		curWaits[uaddr] = e.Waiters
		out = append(out, e)
	}
	return out, curWaits
}

// rankLocks orders locks by contention in the current window (WaitDelta),
// falling back to the cumulative total and then the address so the order is
// deterministic. n < 0 keeps all.
func rankLocks(entries []LockEntry, n int) []LockEntry {
	out := make([]LockEntry, len(entries))
	copy(out, entries)
	sort.Slice(out, func(i, j int) bool {
		if out[i].WaitDelta != out[j].WaitDelta {
			return out[i].WaitDelta > out[j].WaitDelta
		}
		if out[i].Waiters != out[j].Waiters {
			return out[i].Waiters > out[j].Waiters
		}
		return out[i].UAddr < out[j].UAddr
	})
	if n >= 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// countHot returns how many of the ranked locks passed the contention
// threshold for this window. rankLocks sorts by WaitDelta first, so those are
// exactly the first countHot entries.
func countHot(ranked []LockEntry, threshold uint64) int {
	for i, e := range ranked {
		if e.WaitDelta < threshold {
			return i
		}
	}
	return len(ranked)
}

// lockName is the shortest honest name for a lock in a one-line message: its
// contention site when symbolized, the module it sits in when only that
// resolved, else the futex word in hex (all we had before #89).
func lockName(e LockEntry) string {
	switch {
	case e.Func != "":
		return e.Func
	case e.Module != "":
		return fmt.Sprintf("%s+0x%x", e.Module, e.Offset)
	default:
		return fmt.Sprintf("futex@0x%x", e.UAddr)
	}
}
