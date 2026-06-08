package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/trentas/ptop/pkg/collector"
)

// renderNetworkView (F3) — assets/mockup.jsx → NetworkView
//
//   ┌── Active Connections (left) ──────────────┬── Network Events ─┐
//   │ TYPE REMOTE       STATE   LAT      TX/RX   │ 12:34 NET TCP …   │
//   │ ...                                         │                   │
//   ├── Anomalies ────────────────────────┤                          │
//   │ ⚠ refused → 10.0.1.5:5432 (RST 1.5ms)│                          │
//   ├── Latency Trend ────────────────────┤                          │
//   │ remote        ▇▇▇▇▇▇  42ms          │                          │
//   └─────────────────────────────────────┴──────────────────────────┘
func renderNetworkView(m Model, w, h int) string {
	if w < 40 || h < 10 {
		return MutedStyle.Render("(terminal too small)")
	}
	leftW := w * 2 / 3
	rightW := w - leftW

	leftHs := splitFlex([]float64{1.0, 0.7, 1.3}, h)

	conns := Panel("Active Connections",
		renderNetMini(m.NetConns, leftW-2, leftHs[0]-3, true),
		leftW, leftHs[0])

	anomalies := Panel("Anomalies",
		renderNetAnomalies(m, leftW-2, leftHs[1]-3),
		leftW, leftHs[1])

	latency := Panel("Latency Trend",
		renderNetLatencyTrend(m, leftW-2),
		leftW, leftHs[2])

	stream := Panel("Network Events",
		renderTimelineCompact(filterTimelineByCategory(m.Timeline, "net"), rightW-2, h-3),
		rightW, h)

	left := lipgloss.JoinVertical(lipgloss.Left, conns, anomalies, latency)
	return lipgloss.JoinHorizontal(lipgloss.Top, left, stream)
}

// renderNetAnomalies lists recent kernel network errors (#56) newest-first.
// Errors only ever come from the real eBPF collector — never simulated — so a
// mock network source honestly reports that they're unavailable rather than
// inventing anomalies.
func renderNetAnomalies(m Model, w, h int) string {
	if len(m.NetErrors) == 0 {
		if m.usingMockNet {
			return MutedStyle.Render("(net errors need eBPF)")
		}
		return GreenStyle.Render("✓ no network errors")
	}
	lines := []string{}
	for _, e := range m.NetErrors {
		if h > 0 && len(lines) >= h {
			break
		}
		style := lipgloss.NewStyle().Foreground(netErrorColor(e.Kind)).Background(ColorPanel)
		lines = append(lines, style.Render(truncate("⚠ "+netErrorMessage(e), w)))
	}
	return strings.Join(lines, "\n")
}

// netErrorMessage renders a NetError as a one-line cause + peer + timing, used
// both by the Anomalies panel and the synthesized net-timeline entry.
func netErrorMessage(e collector.NetError) string {
	switch e.Kind {
	case "refused":
		if e.DetailMs > 0 {
			return fmt.Sprintf("refused → %s (RST %.1fms)", e.Remote, e.DetailMs)
		}
		return fmt.Sprintf("refused → %s", e.Remote)
	case "reset":
		if e.DetailMs > 0 {
			return fmt.Sprintf("reset → %s mid-stream (%.1fms)", e.Remote, e.DetailMs)
		}
		return fmt.Sprintf("reset → %s mid-stream", e.Remote)
	case "retransmit":
		return fmt.Sprintf("retransmit ×%d → %s", e.Retransmits, e.Remote)
	default:
		return fmt.Sprintf("%s → %s", e.Kind, e.Remote)
	}
}

// netErrorColor maps an error kind to a severity color: a fatal RST is red,
// a retransmit (recoverable backoff) is amber.
func netErrorColor(kind string) lipgloss.Color {
	if kind == "retransmit" {
		return ColorAmber
	}
	return ColorRed
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
