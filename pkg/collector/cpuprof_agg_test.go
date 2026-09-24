package collector

import (
	"testing"

	"github.com/trentas/ptop/pkg/symbol"
)

func rawAt(addr uint64, fn, module string, line int, sid int32, samples uint64) rawCPUSite {
	return rawCPUSite{
		Addr:    addr,
		Frame:   symbol.Frame{Func: fn, Module: module, Line: line, Offset: addr},
		StackID: sid,
		Samples: samples,
	}
}

// The defect this fold exists to prevent, stated as a test: CPU samples land
// all over a function's body, so folding by address the way the heap axis does
// shatters one hot function into an entry per sampled instruction. Six
// addresses inside one function are one site, not six.
func TestFoldCPUSitesFoldsOneFunctionReachedAtManyAddresses(t *testing.T) {
	raw := []rawCPUSite{
		rawAt(0x1000, "main.hot", "app", 10, 1, 40),
		rawAt(0x1008, "main.hot", "app", 11, 2, 30),
		rawAt(0x1010, "main.hot", "app", 12, 3, 20),
		rawAt(0x2000, "main.cold", "app", 99, 4, 5),
	}
	sites, unresolved := foldCPUSites(raw)
	if unresolved != 0 {
		t.Errorf("unresolved = %d, want 0", unresolved)
	}
	if len(sites) != 2 {
		t.Fatalf("got %d sites, want 2 (one per function): %+v", len(sites), sites)
	}
	var hot CPUSite
	for _, s := range sites {
		if s.Func == "main.hot" {
			hot = s
		}
	}
	if hot.Samples != 90 {
		t.Errorf("main.hot has %d samples, want 40+30+20=90", hot.Samples)
	}
	// The identity comes from the dominant sample, which is what makes Line
	// the hottest line in the function rather than an arbitrary one.
	if hot.Line != 10 || hot.Addr != 0x1000 || hot.StackID != 1 {
		t.Errorf("identity should come from the dominant sample (line 10, 0x1000, stack 1), got line %d, %#x, stack %d",
			hot.Line, hot.Addr, hot.StackID)
	}
}

// A later stack that outranks the first must re-donate EVERY identity field,
// not just the one being compared — otherwise a site reports one sample's
// address with another's line.
func TestFoldCPUSitesIdentityStaysOneObservation(t *testing.T) {
	sites, _ := foldCPUSites([]rawCPUSite{
		rawAt(0x1000, "main.hot", "app", 10, 1, 5),
		rawAt(0x1020, "main.hot", "app", 44, 7, 500),
	})
	if len(sites) != 1 {
		t.Fatalf("want 1 site, got %d", len(sites))
	}
	s := sites[0]
	if s.Samples != 505 {
		t.Errorf("samples = %d, want 505", s.Samples)
	}
	if s.Addr != 0x1020 || s.Line != 44 || s.StackID != 7 || s.Offset != 0x1020 {
		t.Errorf("identity should be entirely the dominant sample's, got %#x line %d stack %d offset %#x",
			s.Addr, s.Line, s.StackID, s.Offset)
	}
}

// An address that resolved to a module but to no symbol folds by MODULE. A
// stripped third-party library is then one readable entry, not one entry per
// sampled instruction — the same fragmentation, one level down.
func TestFoldCPUSitesFoldsUnsymbolizedFramesByModule(t *testing.T) {
	sites, unresolved := foldCPUSites([]rawCPUSite{
		rawAt(0x7f01, "", "libfoo.so", 0, 1, 10),
		rawAt(0x7f88, "", "libfoo.so", 0, 2, 25),
		rawAt(0x7fcc, "", "libbar.so", 0, 3, 3),
	})
	if unresolved != 0 {
		t.Errorf("a resolved module is not an unresolved sample: %d", unresolved)
	}
	if len(sites) != 2 {
		t.Fatalf("want one site per module, got %d: %+v", len(sites), sites)
	}
	for _, s := range sites {
		if s.Module == "libfoo.so" && s.Samples != 35 {
			t.Errorf("libfoo.so has %d samples, want 35", s.Samples)
		}
	}
}

// The blind-axis case. A failed stack walk must never take a slot in the
// ranking: on a target built without frame pointers it would win every time and
// present a nearly blind axis as a confident one-item profile.
func TestFoldCPUSitesKeepsFailedWalksOutOfTheRanking(t *testing.T) {
	sites, unresolved := foldCPUSites([]rawCPUSite{
		{Addr: 0, StackID: -14, Samples: 900},
		{Addr: 0, StackID: -22, Samples: 50},
		rawAt(0x1000, "main.hot", "app", 10, 1, 20),
	})
	if unresolved != 950 {
		t.Errorf("unresolved = %d, want 950", unresolved)
	}
	if len(sites) != 1 || sites[0].Func != "main.hot" {
		t.Fatalf("only the resolved function belongs in the list, got %+v", sites)
	}
}

// Shares are computed against the TOTAL, unresolved samples included, so they
// sum to less than 100 exactly when the axis is partly blind. Normalising over
// the resolved samples alone would report a 2%-visible profile as the whole
// picture.
func TestCPUSharesDoNotHideTheBlindFraction(t *testing.T) {
	sites := withCPUShares([]CPUSite{{Samples: 20}}, 1000)
	if got := sites[0].SharePct; got < 1.99 || got > 2.01 {
		t.Errorf("share = %v, want ~2 (20 of 1000, not 20 of 20)", got)
	}
}

func TestTopCPUSitesReportsWhatItDropped(t *testing.T) {
	sites := []CPUSite{
		{Func: "a", Samples: 100}, {Func: "b", Samples: 50},
		{Func: "c", Samples: 7}, {Func: "d", Samples: 3},
	}
	top, om := topCPUSites(sites, 2)
	if len(top) != 2 || top[0].Func != "a" || top[1].Func != "b" {
		t.Fatalf("top = %+v", top)
	}
	if om.Sites != 2 || om.Samples != 10 {
		t.Errorf("omitted = %+v, want 2 sites / 10 samples", om)
	}
	// Nothing dropped must report nothing dropped — that is the state in which
	// a consumer may read absence as zero.
	if _, om := topCPUSites(sites, 4); om.Sites != 0 || om.Samples != 0 {
		t.Errorf("a census should omit nothing, got %+v", om)
	}
}

// The rate is measured or it is absent. Falling back to the requested rate is
// the exact mistake #108 was about, so there is no path here that can invent
// one.
func TestAchievedHzIsMeasuredOrZero(t *testing.T) {
	if got := achievedHz(792, 4, 2); got != 99 {
		t.Errorf("achievedHz(792, 4s, 2cpu) = %v, want 99", got)
	}
	if got := achievedHz(100, 0, 2); got != 0 {
		t.Errorf("no window means no measurement, got %v", got)
	}
	if got := achievedHz(100, 1, 0); got != 0 {
		t.Errorf("no CPUs means no measurement, got %v", got)
	}
}

// A new collector value defaults to the snapshot class, which is what keeps a
// per-occurrence flood from starving it (#108/#121). Pinned because the default
// is the safe direction and a future edit could move it.
func TestCPUProfileIsShedAsASnapshot(t *testing.T) {
	if isPerOccurrenceValue(CPUProfile{}) {
		t.Error("CPUProfile is a periodic snapshot; classing it per-occurrence lets a flood shed it")
	}
}

// A frame with neither a function nor a module is not a site: nothing can name
// it. Letting it into the ranking published a lie — measured on a real capture,
// three samples at a bare 0xfa5ac80bb7d0 sat in the list as a row with no name
// while unresolved_samples read 0, so the axis claimed to have named everything
// it saw.
func TestFoldCPUSitesTreatsANamelessAddressAsUnresolved(t *testing.T) {
	sites, unresolved := foldCPUSites([]rawCPUSite{
		rawAt(0x1000, "main.hot", "app", 10, 1, 500),
		{Addr: 0xfa5ac80bb7d0, StackID: 7, Samples: 3}, // outside every mapped module
		{Addr: 0, StackID: -14, Samples: 2},            // the walk failed outright
	})
	if unresolved != 5 {
		t.Errorf("unresolved = %d, want 5 — a nameless address is not a named site", unresolved)
	}
	if len(sites) != 1 || sites[0].Func != "main.hot" {
		t.Fatalf("only the named function belongs in the list, got %+v", sites)
	}
	// And it must still be a site when the module alone is known.
	sites, unresolved = foldCPUSites([]rawCPUSite{
		rawAt(0x7f00, "", "libfoo.so", 0, 1, 9),
	})
	if unresolved != 0 || len(sites) != 1 || sites[0].Module != "libfoo.so" {
		t.Errorf("a module without a symbol is still an answer: sites=%+v unresolved=%d", sites, unresolved)
	}
}
