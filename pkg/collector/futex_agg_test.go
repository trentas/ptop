package collector

import (
	"testing"

	"github.com/trentas/ptop/pkg/symbol"
)

// A lock taken from several places is named by the site doing most of the
// blocking, and its totals still cover every site — including the wake rows,
// which carry no stack at all.
func TestAggregateLocksNamesDominantSite(t *testing.T) {
	samples := []lockSample{
		{UAddr: 0x1000, StackID: 9, WaitCount: 10, LatSumNs: 10_000_000, LatCount: 10, LastWaitTID: 22},
		{UAddr: 0x1000, StackID: 7, WaitCount: 100, LatSumNs: 200_000_000, LatCount: 100, LastWaitTID: 33},
		{UAddr: 0x1000, StackID: -1, WakeCount: 50, LatSumNs: 5_000_000, LatCount: 50, LastWakeTID: 44},
	}

	got, cur := aggregateLocks(samples, map[uint64]uint64{0x1000: 60})
	if len(got) != 1 {
		t.Fatalf("len(entries) = %d, want 1 (rows fold per lock)", len(got))
	}
	e := got[0]
	if e.StackID != 7 {
		t.Errorf("StackID = %d, want 7 (the site with most waits)", e.StackID)
	}
	if e.Waiters != 110 || e.Wakers != 50 {
		t.Errorf("Waiters/Wakers = %d/%d, want 110/50", e.Waiters, e.Wakers)
	}
	if e.WaitDelta != 50 {
		t.Errorf("WaitDelta = %d, want 50 (110 − 60)", e.WaitDelta)
	}
	// (10 + 200 + 5)ms over 160 calls.
	if want := 215.0 / 160.0; e.LatencyMs < want-0.001 || e.LatencyMs > want+0.001 {
		t.Errorf("LatencyMs = %v, want ~%v", e.LatencyMs, want)
	}
	if e.LastWaitTID != 33 || e.LastWakeTID != 44 {
		t.Errorf("last tids = %d/%d, want 33/44 (from the busiest rows)", e.LastWaitTID, e.LastWakeTID)
	}
	if cur[0x1000] != 110 {
		t.Errorf("carried total = %d, want 110", cur[0x1000])
	}
}

// The dominant site must not depend on the order rows come out of the kernel
// map (Go randomizes map iteration), and a tie resolves the same way every time.
func TestAggregateLocksDeterministicOnTies(t *testing.T) {
	forward := []lockSample{
		{UAddr: 0x2000, StackID: 4, WaitCount: 7},
		{UAddr: 0x2000, StackID: 2, WaitCount: 7},
	}
	reversed := []lockSample{forward[1], forward[0]}

	a, _ := aggregateLocks(forward, nil)
	b, _ := aggregateLocks(reversed, nil)
	if a[0].StackID != b[0].StackID {
		t.Fatalf("tie broke differently by input order: %d vs %d", a[0].StackID, b[0].StackID)
	}
	if a[0].StackID != 2 {
		t.Errorf("StackID = %d, want 2 (lowest id wins a tie)", a[0].StackID)
	}
}

// A wait whose stack walk failed still counts — it just leaves the lock unnamed
// rather than borrowing the wake path's sentinel as a site.
func TestAggregateLocksUnwalkedStaysUnnamed(t *testing.T) {
	got, _ := aggregateLocks([]lockSample{
		{UAddr: 0x3000, StackID: -1, WaitCount: 5, LastWaitTID: 12},
	}, nil)
	if len(got) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(got))
	}
	if got[0].StackID != -1 {
		t.Errorf("StackID = %d, want -1 (no site captured)", got[0].StackID)
	}
	if got[0].Waiters != 5 || got[0].LastWaitTID != 12 {
		t.Errorf("waits/tid = %d/%d, want 5/12", got[0].Waiters, got[0].LastWaitTID)
	}
}

// Totals only ever grow; if the kernel map lost the rows, report no contention
// for the window instead of an unsigned wrap-around.
func TestAggregateLocksNoUnderflow(t *testing.T) {
	got, _ := aggregateLocks([]lockSample{
		{UAddr: 0x4000, StackID: 1, WaitCount: 3},
	}, map[uint64]uint64{0x4000: 900})
	if got[0].WaitDelta != 0 {
		t.Errorf("WaitDelta = %d, want 0", got[0].WaitDelta)
	}
}

func TestRankLocks(t *testing.T) {
	in := []LockEntry{
		{UAddr: 0x30, WaitDelta: 5, Waiters: 100},
		{UAddr: 0x10, WaitDelta: 5, Waiters: 900},
		{UAddr: 0x20, WaitDelta: 40, Waiters: 40},
		{UAddr: 0x05, WaitDelta: 5, Waiters: 100},
	}
	got := rankLocks(in, -1)
	want := []uint64{0x20, 0x10, 0x05, 0x30} // delta desc, then waiters desc, then addr
	for i, w := range want {
		if got[i].UAddr != w {
			t.Fatalf("rank[%d] = 0x%x, want 0x%x (order: %v)", i, got[i].UAddr, w, addrsOf(got))
		}
	}
	if n := len(rankLocks(in, 2)); n != 2 {
		t.Errorf("len(rankLocks(.., 2)) = %d, want 2", n)
	}
	if in[0].UAddr != 0x30 {
		t.Error("rankLocks mutated its input")
	}
}

func TestCountHot(t *testing.T) {
	ranked := []LockEntry{{WaitDelta: 90}, {WaitDelta: 20}, {WaitDelta: 19}, {WaitDelta: 0}}
	if got := countHot(ranked, 20); got != 2 {
		t.Errorf("countHot = %d, want 2", got)
	}
	if got := countHot(ranked, 0); got != len(ranked) {
		t.Errorf("countHot(threshold 0) = %d, want %d", got, len(ranked))
	}
	if got := countHot(nil, 20); got != 0 {
		t.Errorf("countHot(nil) = %d, want 0", got)
	}
}

func TestLockName(t *testing.T) {
	cases := []struct {
		name string
		in   LockEntry
		want string
	}{
		{"symbolized", LockEntry{UAddr: 0xabc, Func: "pool.acquire", Module: "app"}, "pool.acquire"},
		{"module only", LockEntry{UAddr: 0xabc, Module: "libfoo.so", Offset: 0x1f}, "libfoo.so+0x1f"},
		{"unresolved", LockEntry{UAddr: 0xabc}, "futex@0xabc"},
	}
	for _, tc := range cases {
		if got := lockName(tc.in); got != tc.want {
			t.Errorf("%s: lockName = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func addrsOf(entries []LockEntry) []uint64 {
	out := make([]uint64, len(entries))
	for i, e := range entries {
		out[i] = e.UAddr
	}
	return out
}

// ─── contention site selection (#107) ────────────────────────────────────────

// symbolTable turns a fixture map into the resolver pickLockSite takes.
func symbolTable(frames map[uint64]symbol.Frame) func(uint64) symbol.Frame {
	return func(a uint64) symbol.Frame { return frames[a] }
}

// The Go lane: the runtime and the application are one module, so the walk has
// to step over frames by NAME. Everything above the syscall wrapper here is
// runtime scheduler code, which is where a Go program's futex traffic really
// lives — sync.Mutex parks a goroutine, and only the scheduler ever blocks on a
// futex. Naming the lock after any of those frames names every lock in the
// process the same thing.
func TestPickLockSiteGoRuntimeOnlyReportsAddress(t *testing.T) {
	frames := map[uint64]symbol.Frame{
		0x1000: {Func: "runtime.futex", File: "runtime/sys_linux_arm64.s", Line: 666, Module: "ordersvc"},
		0x1100: {Func: "runtime.futexsleep", File: "runtime/os_linux.go", Line: 69, Module: "ordersvc"},
		0x1200: {Func: "runtime.notesleep", File: "runtime/lock_futex.go", Line: 159, Module: "ordersvc"},
		0x1300: {Func: "runtime.stopm", File: "runtime/proc.go", Line: 2800, Module: "ordersvc"},
	}
	site := pickLockSite([]uint64{0x1000, 0x1100, 0x1200, 0x1300}, symbolTable(frames))
	if site.addr != 0x1000 {
		t.Errorf("addr = %#x, want the leaf %#x", site.addr, 0x1000)
	}
	if site.frame != (symbol.Frame{}) {
		t.Errorf("frame = %+v, want unresolved: naming the runtime's futex wrapper collapses every lock into one", site.frame)
	}
}

// The case #107 is really about: two mutexes contended from two different
// functions must come out as two different sites, not one.
func TestPickLockSiteDistinguishesTwoGoCallers(t *testing.T) {
	base := map[uint64]symbol.Frame{
		0x1000: {Func: "runtime.futex", File: "runtime/sys_linux_arm64.s", Line: 666, Module: "ordersvc"},
		0x1100: {Func: "runtime.semasleep", File: "runtime/os_linux.go", Line: 100, Module: "ordersvc"},
		0x1200: {Func: "sync.(*Mutex).lockSlow", File: "sync/mutex.go", Line: 138, Module: "ordersvc"},
		0x2000: {Func: "github.com/o/svc/pool.(*Pool).acquire", File: "github.com/o/svc/pool/pool.go", Line: 42, Module: "ordersvc"},
		0x2100: {Func: "github.com/o/svc/ledger.(*Book).post", File: "github.com/o/svc/ledger/book.go", Line: 17, Module: "ordersvc"},
	}
	resolve := symbolTable(base)
	a := pickLockSite([]uint64{0x1000, 0x1100, 0x1200, 0x2000}, resolve)
	b := pickLockSite([]uint64{0x1000, 0x1100, 0x1200, 0x2100}, resolve)

	if a.frame.Func != "github.com/o/svc/pool.(*Pool).acquire" {
		t.Errorf("first site = %q, want the application caller", a.frame.Func)
	}
	if b.frame.Func != "github.com/o/svc/ledger.(*Book).post" {
		t.Errorf("second site = %q, want the application caller", b.frame.Func)
	}
	if a.frame.Func == b.frame.Func {
		t.Fatal("two locks taken from different functions collapsed into one site")
	}
}

// The libc lane keeps working the way it did: the pthread wrappers live in
// their own module, so the module check is what steps over them.
func TestPickLockSiteSkipsLibcFrames(t *testing.T) {
	frames := map[uint64]symbol.Frame{
		0x7f00: {Func: "__lll_lock_wait", Module: "libc.so.6", Offset: 0x9a1c0},
		0x7f10: {Func: "pthread_mutex_lock", Module: "libpthread.so.0", Offset: 0x8e00},
		0x4000: {Func: "worker_run", File: "worker.c", Line: 88, Module: "app"},
	}
	site := pickLockSite([]uint64{0x7f00, 0x7f10, 0x4000}, symbolTable(frames))
	if site.addr != 0x4000 || site.frame.Func != "worker_run" {
		t.Errorf("site = %#x %+v, want the application frame", site.addr, site.frame)
	}
}

func TestPickLockSiteEdgeCases(t *testing.T) {
	resolve := symbolTable(map[uint64]symbol.Frame{
		0x7f00: {Func: "__lll_lock_wait", Module: "libc.so.6"},
	})

	if got := pickLockSite(nil, resolve); got != (lockSite{}) {
		t.Errorf("no frames: %+v, want zero site", got)
	}
	// A libc-only stack has no application frame either — address, not a name
	// every lock in the process shares.
	if got := pickLockSite([]uint64{0x7f00}, resolve); got.addr != 0x7f00 || got.frame != (symbol.Frame{}) {
		t.Errorf("libc-only stack: %+v, want address only", got)
	}
	// Leading zeros are stack-map padding, not frames.
	if got := pickLockSite([]uint64{0, 0, 0x7f00}, resolve); got.addr != 0x7f00 {
		t.Errorf("padded stack: addr = %#x, want %#x", got.addr, 0x7f00)
	}
	// No symbolizer (cgroup mode): the leaf address, as before #89.
	if got := pickLockSite([]uint64{0x7f00, 0x4000}, nil); got.addr != 0x7f00 || got.frame != (symbol.Frame{}) {
		t.Errorf("no symbolizer: %+v, want the leaf address only", got)
	}
	// An unresolved frame is application code, not machinery: on a stripped
	// module every name is empty, and skipping them would walk to the end.
	if got := pickLockSite([]uint64{0x7f00, 0x5000}, resolve); got.addr != 0x5000 {
		t.Errorf("unresolved frame: addr = %#x, want %#x", got.addr, 0x5000)
	}
}

func TestIsLockInfraFunc(t *testing.T) {
	infra := []string{
		"runtime.futex", "runtime.lock2", "internal/runtime/atomic.Xchg",
		"sync.(*Mutex).Lock", "sync.runtime_SemacquireMutex", "internal/sync.(*HashTrieMap).Load",
	}
	for _, n := range infra {
		if !isLockInfraFunc(n) {
			t.Errorf("isLockInfraFunc(%q) = false, want true", n)
		}
	}
	app := []string{
		"", "main.worker", "github.com/o/svc/pool.(*Pool).acquire",
		"syncpool.Get", "runtimex.Lock", "worker_run",
	}
	for _, n := range app {
		if isLockInfraFunc(n) {
			t.Errorf("isLockInfraFunc(%q) = true, want false", n)
		}
	}
}
