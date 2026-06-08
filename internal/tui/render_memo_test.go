package tui

import (
	"testing"
	"time"

	"github.com/trentas/ptop/pkg/collector"
)

// TestViewMemoization locks in the render-decoupling contract: collector (data)
// messages mutate state but must NOT trigger a re-render — View() returns the
// cached frame — while the FPS TickMsg forces a fresh one. This is what caps the
// lipgloss layout cost at ~FPS/s instead of once per collector publish (~20+/s).
// If someone adds commit=true to a data handler (or drops the View() gate), this
// test fails — the optimization would silently regress otherwise.
func TestViewMemoization(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width, m.Height = 180, 50
	m.ActiveTab = TabOverview

	// First View renders fresh (no cached frame yet) and caches it.
	base := m.View()
	if base == "" {
		t.Fatal("baseline frame is empty")
	}

	// Data messages change visible state (the CPU sparkline) but must leave the
	// frame cached — the next View returns the exact same bytes.
	for i := 0; i < 5; i++ {
		nm, _ := m.Update(CpuMsg(collector.CpuSample{UsagePct: float64(10 + i*15)}))
		m = nm.(Model)
	}
	if got := m.View(); got != base {
		t.Error("a collector message triggered a re-render; expected the cached frame")
	}

	// The FPS heartbeat commits: the next frame reflects the new CPU samples.
	nm, _ := m.Update(TickMsg(time.Now()))
	m = nm.(Model)
	if got := m.View(); got == base {
		t.Error("TickMsg did not produce a fresh frame after state changed")
	}
}

func benchModel() Model {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width, m.Height = 180, 50
	m.ActiveTab = TabOverview
	return m
}

// BenchmarkViewCached is the cost View() pays on a collector message after the
// decoupling: it returns the cached frame, so this is what the ~20+ data
// messages/s now cost instead of a full render.
func BenchmarkViewCached(b *testing.B) {
	m := benchModel()
	m.View() // prime the cache (commit path resets commit=false)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.View()
	}
}

// BenchmarkViewFresh is the full lipgloss render — what EVERY message cost
// before the decoupling, and what the FPS TickMsg still costs.
func BenchmarkViewFresh(b *testing.B) {
	m := benchModel()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.render.commit = true
		_ = m.View()
	}
}
