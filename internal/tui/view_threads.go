package tui

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/trentas/ptop/pkg/collector"
)

// renderThreadsView (F4) — assets/mockup.jsx → ThreadView
func renderThreadsView(m Model, w, h int) string {
	if w < 40 || h < 10 {
		return MutedStyle.Render("(terminal too small)")
	}
	leftW := w * 2 / 3
	rightW := w - leftW

	// Reserve ~5 lines for the lock graph (title + 3-4 lines)
	lockH := 5
	if len(m.LockGraph) > 4 {
		lockH = 6
	}
	body := renderThreadTable(m.Threads, leftW-2, h-3-lockH) +
		"\n\n" +
		renderLockGraph(m, leftW-2)

	threads := Panel("Thread State", body, leftW, h)

	stream := Panel("Lock Events",
		renderTimelineCompact(filterTimelineByCategory(m.Timeline, "lock"), rightW-2, h-3),
		rightW, h)

	return lipgloss.JoinHorizontal(lipgloss.Top, threads, stream)
}

// renderLockGraph: compact list of the most contended futexes in the current
// window. When LockGraph is empty (no eBPF futex collector or no contention
// detected), shows a discrete placeholder. On macOS the lock graph has no
// Tier 1 source at all (no public __ulock_wait hook), so the placeholder
// is more explicit.
func renderLockGraph(m Model, w int) string {
	title := MutedStyle.Render("lock graph (futex)")
	if locksUnavailable {
		return title + "\n" + renderUnavailableInline("not available on macOS — see ?")
	}
	if len(m.LockGraph) == 0 {
		return title + "\n" + MutedStyle.Render("(no contention detected)")
	}

	lines := []string{title}
	for i, e := range m.LockGraph {
		if i >= 4 { // 4 entries fit comfortably
			break
		}
		lines = append(lines, renderLockLine(e, w))
	}
	return strings.Join(lines, "\n")
}

// renderLockLine: "pool.acquire (db.go:42) · ↑42 · 3.2ms · tid=1247".
// The lock is named by the call site contending on it (#89) and falls back to
// the futex word address — see lockSiteLabel. The name absorbs whatever width
// the fixed-size right-hand fields leave, so a long symbol can't overflow the
// panel.
func renderLockLine(e collector.LockEntry, w int) string {
	deltaColor := ColorMuted
	switch {
	case e.WaitDelta >= 100:
		deltaColor = ColorRed
	case e.WaitDelta >= 30:
		deltaColor = ColorAmber
	case e.WaitDelta > 0:
		deltaColor = ColorGreen
	}
	delta := lipgloss.NewStyle().Foreground(deltaColor).Background(ColorPanel).
		Render(fmt.Sprintf("↑%d", e.WaitDelta))

	parts := []string{delta, MutedStyle.Render(fmt.Sprintf("%.1fms", e.LatencyMs))}
	if e.LastWaitTID != 0 {
		parts = append(parts, MutedStyle.Render(fmt.Sprintf("tid=%d", e.LastWaitTID)))
	}
	sep := MutedStyle.Render(" · ")
	tail := strings.Join(parts, sep)

	avail := w - lipgloss.Width(tail) - lipgloss.Width(sep)
	if avail < 8 {
		avail = 8 // never squeeze the name to nothing; the row may wrap instead
	}
	name := lipgloss.NewStyle().Foreground(ColorAmber).Background(ColorPanel).
		Render(truncate(lockSiteLabel(e), avail))

	return name + sep + tail
}

// lockSiteLabel names a lock by the most specific form available, mirroring
// heapSiteLabel:
//
//	func (file:line)  — contention site resolved with a line table (Go)
//	func              — resolved by symbol name only (C; no DWARF line info)
//	module+0xoffset   — stripped module, located by load offset
//	futex@0xADDR      — no site: stack walk failed, /proc mode, or cgroup mode
//
// The first three survive ASLR; the address does not (it is this run's futex
// word), which is why it is the last resort.
func lockSiteLabel(e collector.LockEntry) string {
	if e.Func != "" {
		if e.File != "" && e.Line > 0 {
			return fmt.Sprintf("%s (%s:%d)", e.Func, filepath.Base(e.File), e.Line)
		}
		return e.Func
	}
	if e.Module != "" {
		return fmt.Sprintf("%s+0x%x", e.Module, e.Offset)
	}
	return fmt.Sprintf("futex@0x%x", e.UAddr)
}
