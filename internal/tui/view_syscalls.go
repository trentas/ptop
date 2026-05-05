package tui

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/yourusername/bpf-inspector/internal/collector"
)

// renderSyscallsView (F2) — assets/mockup.jsx → SyscallView
//
//   ┌── Syscall Frequency (2/3) ────────────┬── Event Stream (1/3) ───┐
//   │ name      ▇▇▇▇▇▇▇▇  count  pct        │ 12:34:56 SYS read fd=3  │
//   │ ...                                   │ ...                     │
//   └───────────────────────────────────────┴─────────────────────────┘
func renderSyscallsView(m Model, w, h int) string {
	if w < 40 || h < 10 {
		return MutedStyle.Render("(terminal pequeno demais)")
	}
	leftW := w * 2 / 3
	rightW := w - leftW

	freq := Panel("Syscall Frequency",
		renderSyscallTable(m.SyscallCounts, leftW-2, h-3),
		leftW, h)

	stream := Panel("Event Stream",
		renderTimelineCompact(filterTimelineByCategory(m.Timeline, "syscall"), rightW-2, h-3),
		rightW, h)

	return lipgloss.JoinHorizontal(lipgloss.Top, freq, stream)
}

func filterTimelineByCategory(events []collector.TimelineEvent, cat string) []collector.TimelineEvent {
	out := make([]collector.TimelineEvent, 0, len(events))
	for _, e := range events {
		if e.Category == cat {
			out = append(out, e)
		}
	}
	return out
}
