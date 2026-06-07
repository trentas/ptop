package tui

import (
	"strings"
	"testing"

	"github.com/trentas/ptop/pkg/collector"
)

// TestHeapMsgUpdatesState verifies a HeapMsg lands in the model, appends the
// live-heap value to the sparkline history, and that the F1 overview then
// renders the heap detail (top call site + live-heap + alloc-rate rows) instead
// of the compact classic panel.
func TestHeapMsgUpdatesState(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	hs := collector.HeapStats{
		LiveHeapBytes:      4 << 20,
		AllocRate:          1500,
		SuspectedLeakBytes: 1 << 20,
		TopCallSites: []collector.HeapCallSite{
			// Symbolized (#54): rendered as "func (file:line)", not hex.
			{CallSite: 0x4011a3, AddrHex: "0x4011a3", Func: "leakyAlloc",
				File: "/build/app/alloc.go", Line: 42, Module: "app",
				LiveBytes: 2 << 20, AllocCount: 128, Suspected: true},
			// Unresolved: falls back to the raw-address hex.
			{CallSite: 0x7f00, AddrHex: "0x7f00", LiveBytes: 1 << 20, AllocCount: 9},
		},
	}
	nm, _ := m.Update(HeapMsg(hs))
	mm := nm.(Model)

	if mm.HeapStats.LiveHeapBytes != hs.LiveHeapBytes {
		t.Errorf("LiveHeapBytes = %d, want %d", mm.HeapStats.LiveHeapBytes, hs.LiveHeapBytes)
	}
	if n := len(mm.HeapLiveHist); n == 0 || mm.HeapLiveHist[n-1] != float64(hs.LiveHeapBytes) {
		t.Errorf("HeapLiveHist not appended with live bytes: %v", mm.HeapLiveHist)
	}

	mm.Width, mm.Height = 180, 50
	mm.ActiveTab = TabOverview
	out := mm.View()
	// "leakyAlloc" proves the symbolized site renders (the full "(alloc.go:42)"
	// suffix may be truncated by the panel width); "0x7f00" proves the
	// unresolved fallback still shows hex.
	for _, want := range []string{"leakyAlloc", "0x7f00", "Live heap", "Alloc rate", "top alloc sites"} {
		if !strings.Contains(out, want) {
			t.Errorf("F1 overview missing %q with heap data", want)
		}
	}
}

// TestHeapSiteLabel covers the call-site label fallback chain (#54): full
// func+file:line, func-only, module+offset, and raw-address/unknown.
func TestHeapSiteLabel(t *testing.T) {
	cases := []struct {
		name string
		cs   collector.HeapCallSite
		want string
	}{
		{"go func+line", collector.HeapCallSite{
			Func: "main.leakyAlloc", File: "/build/app/main.go", Line: 42,
			Module: "app", AddrHex: "0x4011a3"}, "main.leakyAlloc (main.go:42)"},
		{"c func only", collector.HeapCallSite{
			Func: "malloc", Module: "libc.so.6", AddrHex: "0x7f12"}, "malloc"},
		{"stripped module+offset", collector.HeapCallSite{
			Module: "libfoo.so", Offset: 0x1500, AddrHex: "0x55aa1500"}, "libfoo.so+0x1500"},
		{"raw hex fallback", collector.HeapCallSite{AddrHex: "0xdead"}, "0xdead"},
		{"unknown", collector.HeapCallSite{AddrHex: "unknown"}, "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := heapSiteLabel(c.cs); got != c.want {
				t.Errorf("heapSiteLabel = %q, want %q", got, c.want)
			}
		})
	}
}

// TestMemPanelClassicWithoutHeap confirms the F1 Memory panel keeps the compact
// mockup layout (no heap detail) when there is no heap data — preserving the
// degraded-mode / macOS / Go-target appearance.
func TestMemPanelClassicWithoutHeap(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width, m.Height = 180, 50
	m.ActiveTab = TabOverview
	out := m.View()
	for _, heapOnly := range []string{"top alloc sites", "Live heap", "Alloc rate"} {
		if strings.Contains(out, heapOnly) {
			t.Errorf("F1 overview shows heap-only marker %q without any heap data", heapOnly)
		}
	}
	if !strings.Contains(out, "RSS") {
		t.Errorf("F1 overview missing the Memory panel entirely")
	}
}
