package tui

import (
	"fmt"
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

// renderLockLine: "futex@0xADDR  ↑42 waits  avg 3.2ms  last tid 1247"
func renderLockLine(e collector.LockEntry, w int) string {
	addrStyle := lipgloss.NewStyle().Foreground(ColorAmber).Background(ColorPanel)
	addr := addrStyle.Render(fmt.Sprintf("futex@0x%x", e.UAddr))

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

	lat := MutedStyle.Render(fmt.Sprintf("%.1fms", e.LatencyMs))

	tid := ""
	if e.LastWaitTID != 0 {
		tid = MutedStyle.Render(fmt.Sprintf("tid=%d", e.LastWaitTID))
	}

	parts := []string{addr, delta, lat, tid}
	return strings.Join(parts, MutedStyle.Render(" · "))
}
