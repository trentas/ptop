package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/trentas/ptop/pkg/collector"
)

// TestLockSiteLabel covers the lock-naming fallback chain (#89): a lock is
// named by the call site contending on it, and only falls back to the futex
// word address when nothing resolved.
func TestLockSiteLabel(t *testing.T) {
	cases := []struct {
		name string
		e    collector.LockEntry
		want string
	}{
		{"go func+line", collector.LockEntry{
			UAddr: 0x7f00, Func: "db.(*Pool).acquire", File: "/build/app/pool.go",
			Line: 42, Module: "app"}, "db.(*Pool).acquire (pool.go:42)"},
		{"c func only", collector.LockEntry{
			UAddr: 0x7f00, Func: "worker_run", Module: "libworker.so"}, "worker_run"},
		{"stripped module+offset", collector.LockEntry{
			UAddr: 0x7f00, Module: "libfoo.so", Offset: 0x1500}, "libfoo.so+0x1500"},
		{"no site at all", collector.LockEntry{UAddr: 0x7f00}, "futex@0x7f00"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := lockSiteLabel(c.e); got != c.want {
				t.Errorf("lockSiteLabel = %q, want %q", got, c.want)
			}
		})
	}
}

// A long symbol must be truncated into the panel, not pushed past its width —
// an overflowing row wraps and shears the whole layout (see "Width discipline").
func TestRenderLockLineFitsWidth(t *testing.T) {
	e := collector.LockEntry{
		UAddr: 0x7f00, WaitDelta: 42, LatencyMs: 3.2, LastWaitTID: 1247,
		Func: strings.Repeat("verylongsymbolname.", 8),
	}
	for _, w := range []int{40, 60, 100} {
		if got := lipgloss.Width(renderLockLine(e, w)); got > w {
			t.Errorf("width %d: rendered %d columns", w, got)
		}
	}
}

// The contended lock's F4 row shows its call site and drops nothing else.
func TestRenderLockGraphShowsCallSite(t *testing.T) {
	if locksUnavailable {
		t.Skip("lock graph has no source on this platform")
	}
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width, m.Height = 180, 50
	m.LockGraph = []collector.LockEntry{{
		UAddr: 0x7f00, WaitDelta: 42, Waiters: 120, LatencyMs: 3.2, LastWaitTID: 1247,
		Func: "acquireSlot", File: "/build/pool.go", Line: 42, Module: "app", StackID: 7,
	}}

	out := renderLockGraph(m, 60)
	for _, want := range []string{"acquireSlot", "↑42", "3.2ms", "tid=1247"} {
		if !strings.Contains(out, want) {
			t.Errorf("lock graph missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "futex@0x7f00") {
		t.Errorf("lock graph fell back to the address despite a resolved site:\n%s", out)
	}
}
