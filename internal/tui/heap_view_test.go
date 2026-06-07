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
			{CallSite: 0x4011a3, AddrHex: "0x4011a3", LiveBytes: 2 << 20, AllocCount: 128, Suspected: true},
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
	for _, want := range []string{"0x4011a3", "Live heap", "Alloc rate", "top alloc sites"} {
		if !strings.Contains(out, want) {
			t.Errorf("F1 overview missing %q with heap data", want)
		}
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
