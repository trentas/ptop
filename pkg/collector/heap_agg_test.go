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
