package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/trentas/ptop/pkg/collector"
)

func profile(total, unresolved uint64, sites ...collector.CPUSite) collector.CPUProfile {
	return collector.CPUProfile{
		Sites: sites, TotalSamples: total, UnresolvedSamples: unresolved,
		WindowMs: 1000, SampleRateHz: 99, RequestedRateHz: 99,
	}
}

func site(fn string, samples uint64, line int) collector.CPUSite {
	return collector.CPUSite{Func: fn, Module: "app", Line: line, Samples: samples}
}

func TestCPUSiteWindowFoldsAcrossProfiles(t *testing.T) {
	var w cpuSiteWindow
	for i := 0; i < 3; i++ {
		w.add(profile(100, 0, site("main.hot", 80, 10), site("main.cold", 20, 99)))
	}
	got := w.fold()
	if got.Total != 300 {
		t.Errorf("total = %d, want 300", got.Total)
	}
	if len(got.Sites) != 2 {
		t.Fatalf("want 2 folded sites, got %d", len(got.Sites))
	}
	if got.Sites[0].Func != "main.hot" || got.Sites[0].Samples != 240 {
		t.Errorf("hot site = %s/%d, want main.hot/240", got.Sites[0].Func, got.Sites[0].Samples)
	}
	if s := got.Sites[0].SharePct; s < 79.9 || s > 80.1 {
		t.Errorf("share = %v, want ~80", s)
	}
}

// The window is bounded: a long-running panel must not accumulate forever, and
// a regression that started a minute ago must be able to push an old one out.
func TestCPUSiteWindowIsBounded(t *testing.T) {
	var w cpuSiteWindow
	for i := 0; i < cpuSiteWindowSeconds*3; i++ {
		w.add(profile(10, 0, site("main.hot", 10, 1)))
	}
	if len(w.profiles) != cpuSiteWindowSeconds {
		t.Errorf("window holds %d profiles, want %d", len(w.profiles), cpuSiteWindowSeconds)
	}
	if got := w.fold().Total; got != uint64(cpuSiteWindowSeconds*10) {
		t.Errorf("fold covers %d samples, want only the window's %d", got, cpuSiteWindowSeconds*10)
	}
}

// Shares are recomputed against the window's own total, not averaged from the
// per-second percentages — otherwise a second in which the target did almost
// nothing would weigh as much as a busy one.
func TestCPUSiteSharesWeightBusySecondsMore(t *testing.T) {
	var w cpuSiteWindow
	// One busy second, entirely in A. One nearly idle second, entirely in B.
	w.add(profile(990, 0, site("main.A", 990, 1)))
	w.add(profile(10, 0, site("main.B", 10, 2)))
	got := w.fold()
	if got.Sites[0].Func != "main.A" {
		t.Fatalf("busiest site should rank first, got %s", got.Sites[0].Func)
	}
	// Averaging the two seconds' shares would give A 50%. The truth is 99%.
	if s := got.Sites[0].SharePct; s < 98.9 || s > 99.1 {
		t.Errorf("share = %v, want ~99 (a per-second average would say 50)", s)
	}
}

// Below the floor the panel refuses to rank. A top-N drawn from a dozen samples
// is an ordering of noise, and a human reading a flickering list believes it.
func TestCPUSiteSummaryRefusesToRankTooFewSamples(t *testing.T) {
	var w cpuSiteWindow
	w.add(profile(12, 0, site("main.hot", 12, 1)))
	if w.fold().Ranked() {
		t.Error("12 samples is not a ranking")
	}
	var w2 cpuSiteWindow
	for i := 0; i < 20; i++ {
		w2.add(profile(50, 0, site("main.hot", 50, 1)))
	}
	if !w2.fold().Ranked() {
		t.Error("1000 samples is plenty to rank")
	}
}

// The blind fraction is computed against the total including unresolved
// samples, so a panel ranking 6% of the evidence says so.
func TestCPUSiteBlindFractionIsVisible(t *testing.T) {
	var w cpuSiteWindow
	w.add(profile(1000, 940, site("main.hot", 60, 1)))
	got := w.fold()
	if b := got.BlindPct(); b < 93.9 || b > 94.1 {
		t.Errorf("blind = %v%%, want ~94", b)
	}
	if s := got.Sites[0].SharePct; s < 5.9 || s > 6.1 {
		t.Errorf("share = %v, want ~6 — normalising over the resolved samples would say 100", s)
	}
}

// The achieved rate is weighted by the window each profile covers, so a short
// or empty window does not drag it.
func TestCPUSiteRateIsSampleWeighted(t *testing.T) {
	var w cpuSiteWindow
	a := profile(100, 0, site("main.hot", 100, 1))
	a.SampleRateHz, a.WindowMs = 99, 1000
	b := profile(100, 0, site("main.hot", 100, 1))
	b.SampleRateHz, b.WindowMs = 49, 100 // a tenth of the time at half the rate
	w.add(a)
	w.add(b)
	got := w.fold()
	// Unweighted this would be 74. Weighted by window it is ~94.
	if got.RateHz < 93 || got.RateHz > 95 {
		t.Errorf("rate = %v, want ~94 (an unweighted mean would say 74)", got.RateHz)
	}
}

// The collector's own top-N cut must reach the panel, or a reader watching a
// function leave the list cannot tell it from the function going quiet.
func TestCPUSiteTruncationSurvivesTheFold(t *testing.T) {
	var w cpuSiteWindow
	for i := 0; i < 10; i++ {
		p := profile(100, 0, site("main.hot", 60, 1))
		p.OmittedSamples, p.TotalSites = 40, 23
		w.add(p)
	}
	got := w.fold()
	if !got.Truncated() {
		t.Error("the collector dropped 40 samples a second; the panel must know")
	}
	if got.TotalSites != 23 {
		t.Errorf("TotalSites = %d, want 23", got.TotalSites)
	}
	var full cpuSiteWindow
	full.add(profile(100, 0, site("main.hot", 100, 1)))
	if full.fold().Truncated() {
		t.Error("nothing omitted must read as a census")
	}
}

// The panel and the collector must fold by one rule; the TUI uses the exported
// one rather than a copy, and a copy would drift silently.
func TestCPUSiteKeySeparatesFunctionsAndJoinsAddresses(t *testing.T) {
	a := collector.CPUSite{Func: "main.hot", Module: "app", Addr: 0x1000}
	b := collector.CPUSite{Func: "main.hot", Module: "app", Addr: 0x1080}
	c := collector.CPUSite{Func: "main.cold", Module: "app", Addr: 0x2000}
	if a.Key() != b.Key() {
		t.Error("two addresses inside one function are one site")
	}
	if a.Key() == c.Key() {
		t.Error("two functions are two sites")
	}
	unsym := collector.CPUSite{Module: "libfoo.so", Addr: 0x7f00}
	if unsym.Key() == a.Key() {
		t.Error("an unsymbolized module is not the application function")
	}
}

// A panel wider than its box wraps, and a wrapped line inside a border pushes
// every row below it out — the failure the width-discipline rule in CLAUDE.md
// exists for. The first version of this panel overflowed by 23 columns at w=20:
// fixed column widths plus a minimum name width cannot fit in a narrow terminal,
// so columns are dropped in priority order instead.
func TestCPUPanelNeverOverflowsItsWidth(t *testing.T) {
	var w cpuSiteWindow
	for i := 0; i < 30; i++ {
		w.add(collector.CPUProfile{
			TotalSamples: 200, WindowMs: 1000, SampleRateHz: 97, RequestedRateHz: 99,
			OmittedSamples: 40, TotalSites: 231, UnresolvedSamples: 70,
			Sites: []collector.CPUSite{
				{Func: "github.com/some/very/long/module/path.(*Deeply).NestedReceiverMethodName",
					Module: "api", File: "an_extremely_long_source_file_name.go", Line: 123456, Samples: 90},
				{Module: "libsomethingwithaverylongname.so.6", AddrHex: "0x7f22aabbccdd", Samples: 40},
			},
		})
	}
	sum := w.fold()
	for _, width := range []int{20, 40, 60, 80, 120, 200} {
		body := renderCPU(make([]float64, 60), sum, width, 12)
		for i, line := range strings.Split(body, "\n") {
			if got := lipgloss.Width(line); got > width {
				t.Errorf("w=%d: line %d is %d wide — a panel that overflows wraps and flips the layout\n%q",
					width, i, got, line)
			}
		}
	}
}

// TotalSites is how many distinct functions the WINDOW holds. Taking the
// largest any single profile reported is a different number — each profile
// counts one second, and the union over thirty of them is bigger — and it
// published total_sites=4 beside a list of five, a count smaller than the thing
// it counts.
func TestCPUSiteTotalIsNeverSmallerThanTheListItCounts(t *testing.T) {
	var w cpuSiteWindow
	// Each second sees two functions; across the window there are four.
	w.add(profile(100, 0, site("main.a", 60, 1), site("main.b", 40, 2)))
	w.add(profile(100, 0, site("main.c", 60, 3), site("main.d", 40, 4)))
	got := w.fold()
	if len(got.Sites) != 4 {
		t.Fatalf("folded %d sites, want 4", len(got.Sites))
	}
	if int(got.TotalSites) < len(got.Sites) {
		t.Errorf("total_sites=%d beside a list of %d — the count is smaller than what it counts",
			got.TotalSites, len(got.Sites))
	}
}
