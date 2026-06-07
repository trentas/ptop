package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/trentas/ptop/pkg/collector"
)

// renderTimelineView (F7) — assets/mockup.jsx → TimelineView
// Stream completo de eventos com badge por categoria.
func renderTimelineView(m Model, w, h int) string {
	if w < 30 || h < 6 {
		return MutedStyle.Render("(terminal pequeno demais)")
	}
	body := renderTimelineFull(m.Timeline, w-2, h-3)
	return Panel("Full Event Stream", body, w, h)
}

func renderTimelineFull(events []collector.TimelineEvent, w, h int) string {
	if h <= 0 {
		return ""
	}
	visible := events
	if len(visible) > h {
		visible = visible[:h]
	}
	const tsW = 12
	const catW = 5
	msgW := w - tsW - catW - 2
	if msgW < 8 {
		msgW = 8
	}

	lines := make([]string, 0, len(visible))
	for _, e := range visible {
		ts := lipgloss.NewStyle().Foreground(ColorDim).Background(ColorPanel).Width(tsW).
			Render(e.Timestamp.Format("15:04:05.000"))
		c := CategoryColor(e.Category)
		cat := lipgloss.NewStyle().
			Foreground(c).
			Background(ColorPanel).
			Width(catW).
			Align(lipgloss.Center).
			Render(strings.TrimSpace(CategoryLabel(e.Category)))
		msg := lipgloss.NewStyle().Foreground(ColorText).Background(ColorPanel).Width(msgW).
			Render(truncate(e.Message, msgW))
		lines = append(lines, panelRow(ts, cat, msg))

	}
	return strings.Join(lines, "\n")
}
