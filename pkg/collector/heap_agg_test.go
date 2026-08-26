package collector

import "testing"

func TestIsSuspectedLeak(t *testing.T) {
	const thresh = 10 * 1e9 // 10s in ns
	cases := []struct {
		age  uint64
		want bool
	}{
		{0, false},
		{thresh - 1, false},
		{thresh, false}, // boundary: must strictly exceed
		{thresh + 1, true},
		{thresh * 3, true},
	}
	for _, c := range cases {
		if got := isSuspectedLeak(c.age, thresh); got != c.want {
			t.Errorf("isSuspectedLeak(%d, %d) = %v, want %v", c.age, uint64(thresh), got, c.want)
		}
	}
}

func TestChooseTopCallSites(t *testing.T) {
	sites := []HeapCallSite{
		{CallSite: 1, LiveBytes: 100, AllocCount: 5},
		{CallSite: 2, LiveBytes: 500, AllocCount: 1},
		{CallSite: 3, LiveBytes: 300, AllocCount: 9},
		{CallSite: 4, LiveBytes: 100, AllocCount: 8}, // ties LiveBytes with #1, more allocs
	}
	got := chooseTopCallSites(sites, 3)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	wantOrder := []uint64{2, 3, 4} // 500, 300, then 100/allocs=8 beats 100/allocs=5
	for i, cs := range wantOrder {
		if got[i].CallSite != cs {
			t.Errorf("position %d: CallSite = %d, want %d (order: %+v)", i, got[i].CallSite, cs, got)
		}
	}

	// n larger than the slice keeps everything; original is not mutated.
	all := chooseTopCallSites(sites, 10)
	if len(all) != 4 {
		t.Errorf("len = %d, want 4", len(all))
	}
	if sites[0].CallSite != 1 {
		t.Errorf("input slice was mutated: %+v", sites)
	}
}

func TestPickAppFrame(t *testing.T) {
	const lo, hi = 0x7f000000, 0x7f001000
	cases := []struct {
		name   string
		frames []uint64
		want   uint64
	}{
		{"first frame in libc, second in app", []uint64{0x7f000500, 0x400123}, 0x400123},
		{"skip zero and libc frames", []uint64{0, 0x7f000800, 0x401000}, 0x401000},
		{"all libc → fall back to leaf", []uint64{0x7f000100, 0x7f000900}, 0x7f000100},
		{"no range info → first non-zero", []uint64{0x12345}, 0x12345},
		{"empty → 0", nil, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pickAppFrame(c.frames, lo, hi); got != c.want {
				t.Errorf("pickAppFrame(%x) = %#x, want %#x", c.frames, got, c.want)
			}
		})
	}
}

func TestHeapAddrHex(t *testing.T) {
	if got := heapAddrHex(0); got != "unknown" {
		t.Errorf("heapAddrHex(0) = %q, want \"unknown\"", got)
	}
	if got := heapAddrHex(0xdeadbeef); got != "0xdeadbeef" {
		t.Errorf("heapAddrHex(0xdeadbeef) = %q", got)
	}
}

// TestHeapResolverZeroValue locks in the StackResolver contract a not-yet-
// Start()ed (or stub) collector must honor: no tracer/symbolizer → graceful
// not-found and an empty build-id, never a panic. Holds on both lanes (the real
// collector guards on a nil tracer; the stub returns the same).
func TestHeapResolverZeroValue(t *testing.T) {
	c := &HeapEBPFCollector{}
	if fr, ok := c.ResolveStack(1); ok || fr != nil {
		t.Errorf("ResolveStack = %v,%v; want nil,false", fr, ok)
	}
	if id := c.ProcessBuildID(); id != "" {
		t.Errorf("ProcessBuildID = %q, want \"\"", id)
	}
}

func TestHeapOpName(t *testing.T) {
	cases := map[uint32]string{0: "malloc", 1: "calloc", 2: "realloc", 3: "free", 99: "?"}
	for op, want := range cases {
		if got := heapOpName(op); got != want {
			t.Errorf("heapOpName(%d) = %q, want %q", op, got, want)
		}
	}
}

// On the Go lane every site has LiveBytes 0 (nothing observes a free), so the
// ranking has to fall through to allocation volume. Without the AllocBytes
// tier this degenerates into a sort by address and the "top call sites" list
// stops meaning anything for an entire runtime family.
func TestChooseTopCallSitesRanksByAllocBytesWhenLiveIsUnmeasured(t *testing.T) {
	sites := []HeapCallSite{
		{CallSite: 0x40, AllocBytes: 1_000, AllocCount: 50},
		{CallSite: 0x10, AllocBytes: 9_000, AllocCount: 3},
		{CallSite: 0x30, AllocBytes: 4_000, AllocCount: 7},
		{CallSite: 0x20, AllocBytes: 4_000, AllocCount: 90}, // ties bytes, more allocs
	}
	got := chooseTopCallSites(sites, 3)
	wantOrder := []uint64{0x10, 0x20, 0x30}
	for i, cs := range wantOrder {
		if got[i].CallSite != cs {
			t.Errorf("position %d: CallSite = %#x, want %#x (order: %+v)", i, got[i].CallSite, cs, got)
		}
	}
}

// Live bytes still outrank allocation volume where both are measured — the new
// tier must not reorder the libc lane.
func TestChooseTopCallSitesPrefersLiveBytesOverAllocBytes(t *testing.T) {
	sites := []HeapCallSite{
		{CallSite: 1, LiveBytes: 10, AllocBytes: 1_000_000},
		{CallSite: 2, LiveBytes: 20, AllocBytes: 1},
	}
	if got := chooseTopCallSites(sites, 1); got[0].CallSite != 2 {
		t.Errorf("CallSite = %d, want 2 (live bytes rank first)", got[0].CallSite)
	}
}

func TestPickGoAppFrame(t *testing.T) {
	names := map[uint64]string{
		0x10: "runtime.mallocgc",
		0x20: "runtime.newobject",
		0x30: "internal/runtime/maps.(*Map).Put",
		0x40: "main.handleRequest",
		0x50: "main.main",
	}
	nameAt := func(a uint64) string { return names[a] }

	cases := []struct {
		name   string
		frames []uint64
		want   uint64
	}{
		{"skips the allocator and its runtime callers",
			[]uint64{0x10, 0x20, 0x40, 0x50}, 0x40},
		{"skips internal/runtime packages too",
			[]uint64{0x10, 0x30, 0x40}, 0x40},
		{"ignores zero padding in the captured stack",
			[]uint64{0, 0x10, 0, 0x40}, 0x40},
		{"all-runtime stack falls back to the leaf",
			[]uint64{0x10, 0x20}, 0x10},
		{"empty stack yields 0",
			nil, 0},
		// A stripped module resolves to no name at all. Treating "" as runtime
		// would skip every frame and hand back the leaf — reporting
		// runtime.mallocgc as the call site of every allocation in the process.
		{"unresolvable frames count as application code",
			[]uint64{0x10, 0x99}, 0x99},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pickGoAppFrame(c.frames, nameAt); got != c.want {
				t.Errorf("pickGoAppFrame = %#x, want %#x", got, c.want)
			}
		})
	}
}

func TestIsGoRuntimeFunc(t *testing.T) {
	runtimeNames := []string{
		"runtime.mallocgc",
		"runtime.newobject",
		"internal/runtime/maps.(*Map).Put",
	}
	for _, n := range runtimeNames {
		if !isGoRuntimeFunc(n) {
			t.Errorf("isGoRuntimeFunc(%q) = false, want true", n)
		}
	}
	// Application and library frames are the answer we want, not noise to
	// skip: the first non-runtime frame IS the call site, even when it is in a
	// dependency rather than in main.
	appNames := []string{
		"main.handleRequest",
		"fmt.Sprintf",
		"github.com/x/y.(*Client).Do",
		"", // unresolvable
		// Not the runtime: a user package that merely starts with the letters.
		"runtimecheck.Verify",
	}
	for _, n := range appNames {
		if isGoRuntimeFunc(n) {
			t.Errorf("isGoRuntimeFunc(%q) = true, want false", n)
		}
	}
}

// TestFoldCallSitesCountsTheCapInCallSitesNotStacks is the regression for #109.
//
// The measured case: a thumbnail cache that stops evicting grows its map, and
// growth reaches the allocator through several distinct stacks. The kernel keys
// its aggregate by stack id, so before folding each of those stacks held a slot
// of its own and pushed a busy single-stack site (fmt.Sprintf, ~6000
// allocations a window, called identically in both builds) out of a cap of 8 —
// while a consumer counting the FUNCTIONS it received saw a short list and
// concluded nothing had been dropped.
func TestFoldCallSitesCountsTheCapInCallSitesNotStacks(t *testing.T) {
	// storeThumb reaches mallocgc through six stacks; fmt.Sprintf through one.
	var raw []rawCallSite
	for i := 0; i < 6; i++ {
		raw = append(raw, rawCallSite{HeapCallSite: HeapCallSite{
			CallSite: 0x1000, Func: "main.(*cache).storeThumb", StackID: int32(i),
			AllocBytes: 4 << 20, AllocCount: 2004,
		}})
	}
	raw = append(raw, rawCallSite{HeapCallSite: HeapCallSite{
		CallSite: 0x2000, Func: "fmt.Sprintf", StackID: 100,
		AllocBytes: 96 << 10, AllocCount: 6017,
	}})

	folded := foldCallSites(raw)
	if len(folded) != 2 {
		t.Fatalf("len(folded) = %d, want 2 — the cap must be counted in call sites", len(folded))
	}

	top, omitted := topCallSites(folded, 2)
	if len(top) != 2 {
		t.Fatalf("len(top) = %d, want 2", len(top))
	}
	var sawSprintf bool
	for _, s := range top {
		if s.Func == "fmt.Sprintf" {
			sawSprintf = true
			if s.AllocCount != 6017 {
				t.Errorf("fmt.Sprintf AllocCount = %d, want 6017", s.AllocCount)
			}
		}
		if s.Func == "main.(*cache).storeThumb" {
			if want := uint64(6 * 2004); s.AllocCount != want {
				t.Errorf("storeThumb AllocCount = %d, want %d (six stacks summed)", s.AllocCount, want)
			}
			if s.AllocBytes != 6*(4<<20) {
				t.Errorf("storeThumb AllocBytes = %d, want %d", s.AllocBytes, 6*(4<<20))
			}
		}
	}
	if !sawSprintf {
		t.Errorf("fmt.Sprintf fell out of a list with room for it; the fold did not take")
	}
	if omitted.Sites != 0 {
		t.Errorf("omitted.Sites = %d, want 0 — this list is a census", omitted.Sites)
	}
}

// TestFoldCallSitesKeepsTheHeaviestStack pins what a folded StackID means: the
// stack that contributed most, so resolving it still yields frames that
// genuinely reached this site.
func TestFoldCallSitesKeepsTheHeaviestStack(t *testing.T) {
	raw := []rawCallSite{
		{HeapCallSite: HeapCallSite{CallSite: 0x40, StackID: 7, AllocBytes: 10}},
		{HeapCallSite: HeapCallSite{CallSite: 0x40, StackID: 9, AllocBytes: 900}},
		{HeapCallSite: HeapCallSite{CallSite: 0x40, StackID: 3, AllocBytes: 50}},
	}
	got := foldCallSites(raw)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].StackID != 9 {
		t.Errorf("StackID = %d, want 9 (the heaviest contributor)", got[0].StackID)
	}
	if got[0].AllocBytes != 960 {
		t.Errorf("AllocBytes = %d, want 960", got[0].AllocBytes)
	}
}

// TestFoldCallSitesRecomputesTheLifetimeMean: a mean cannot be merged, only
// recomputed from the pooled parts. Averaging the two averages here would give
// 55ms; the real pooled mean is 19ms, because the 10ms bucket holds 90 of the
// 100 freed allocations.
func TestFoldCallSitesRecomputesTheLifetimeMean(t *testing.T) {
	raw := []rawCallSite{
		{HeapCallSite: HeapCallSite{CallSite: 0x50, StackID: 1}, LifetimeSumNs: 90 * 10 * 1e6, LifetimeCount: 90},
		{HeapCallSite: HeapCallSite{CallSite: 0x50, StackID: 2}, LifetimeSumNs: 10 * 100 * 1e6, LifetimeCount: 10},
	}
	got := foldCallSites(raw)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].AvgLifetimeMs != 19 {
		t.Errorf("AvgLifetimeMs = %v, want 19 (pooled), not 55 (mean of means)", got[0].AvgLifetimeMs)
	}
}

// TestFoldCallSitesPoolsUnresolvedStacks: a failed stack walk yields CallSite 0.
// Those are one bucket of unattributed allocation, not N distinct sites — left
// apart they crowd out sites that did resolve.
func TestFoldCallSitesPoolsUnresolvedStacks(t *testing.T) {
	raw := []rawCallSite{
		{HeapCallSite: HeapCallSite{CallSite: 0, StackID: 1, AllocCount: 3}},
		{HeapCallSite: HeapCallSite{CallSite: 0, StackID: 2, AllocCount: 4}},
		{HeapCallSite: HeapCallSite{CallSite: 0, StackID: 3, AllocCount: 5}},
		{HeapCallSite: HeapCallSite{CallSite: 0x60, StackID: 4, AllocCount: 1}},
	}
	got := foldCallSites(raw)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (one unknown bucket + one resolved site)", len(got))
	}
	for _, s := range got {
		if s.CallSite == 0 && s.AllocCount != 12 {
			t.Errorf("unknown bucket AllocCount = %d, want 12", s.AllocCount)
		}
	}
}

// TestTopCallSitesAccountsForWhatItDropped pins the completeness signal.
//
// A truncated list cannot tell a consumer whether a site is missing because it
// stopped allocating or because it stopped being reported, and the two call for
// opposite responses (sunnysystems/witness#69). The omitted totals bound what
// any one missing site can account for.
func TestTopCallSitesAccountsForWhatItDropped(t *testing.T) {
	sites := []HeapCallSite{
		{CallSite: 1, AllocBytes: 1000, AllocCount: 10, LiveBytes: 100},
		{CallSite: 2, AllocBytes: 900, AllocCount: 9, LiveBytes: 90},
		{CallSite: 3, AllocBytes: 30, AllocCount: 3, LiveBytes: 3},
		{CallSite: 4, AllocBytes: 20, AllocCount: 2, LiveBytes: 2},
	}
	top, om := topCallSites(sites, 2)
	if len(top) != 2 {
		t.Fatalf("len(top) = %d, want 2", len(top))
	}
	if om.Sites != 2 {
		t.Errorf("omitted.Sites = %d, want 2", om.Sites)
	}
	if om.AllocBytes != 50 || om.AllocCount != 5 || om.LiveBytes != 5 {
		t.Errorf("omitted = %+v, want AllocBytes 50 / AllocCount 5 / LiveBytes 5", om)
	}

	// A census reports nothing omitted — the state in which a consumer may read
	// absence as zero.
	if _, om := topCallSites(sites, 4); om.Sites != 0 || om.AllocBytes != 0 {
		t.Errorf("a complete list reported omissions: %+v", om)
	}
	if _, om := topCallSites(sites, -1); om.Sites != 0 {
		t.Errorf("n < 0 keeps all but reported omissions: %+v", om)
	}
}
