package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// renderNetworkView (F3) — assets/mockup.jsx → NetworkView
//
//   ┌── Active Connections (left) ────────┬── Network Events (1/3) ─┐
//   │ TYPE REMOTE         STATE   LAT     │ 12:34 NET TCP SYN  …    │
//   │ ...                                  │                          │
//   ├── Latency Trend ────────────────────┤                          │
//   │ remote        ▇▇▇▇▇▇  42ms          │                          │
//   └─────────────────────────────────────┴──────────────────────────┘
func renderNetworkView(m Model, w, h int) string {
	if w < 40 || h < 10 {
		return MutedStyle.Render("(terminal too small)")
	}
	leftW := w * 2 / 3
	rightW := w - leftW

	leftHs := splitFlex([]float64{1.0, 1.5}, h)

	conns := Panel("Active Connections",
		renderNetMini(m.NetConns, leftW-2, leftHs[0]-3),
		leftW, leftHs[0])

	latency := Panel("Latency Trend",
		renderNetLatencyTrend(m, leftW-2),
		leftW, leftHs[1])

	stream := Panel("Network Events",
		renderTimelineCompact(filterTimelineByCategory(m.Timeline, "net"), rightW-2, h-3),
		rightW, h)

	left := lipgloss.JoinVertical(lipgloss.Left, conns, latency)
	return lipgloss.JoinHorizontal(lipgloss.Top, left, stream)
}

func renderNetLatencyTrend(m Model, w int) string {
	if len(m.NetConns) == 0 {
		return MutedStyle.Render("(no connections)")
	}
	const labelW = 28
	barW := w - labelW - 10
	if barW < 8 {
		barW = 8
	}
	lines := []string{}
	for _, c := range m.NetConns {
		latColor := ColorGreen
		if c.LatencyMs > 30 {
			latColor = ColorAmber
		}
		if c.LatencyMs > 100 {
			latColor = ColorRed
		}
		left := lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorPanel).Width(labelW).Render(truncate(c.Remote, labelW))
		bar := HorizontalBar(c.LatencyMs, 100, barW, latColor)
		val := lipgloss.NewStyle().Foreground(latColor).Background(ColorPanel).Width(8).Align(lipgloss.Right).
			Render(fmt.Sprintf("%.1fms", c.LatencyMs))
		lines = append(lines, panelRow(left, bar, val))

	}
	return strings.Join(lines, "\n\n") // spacing between rows
}
