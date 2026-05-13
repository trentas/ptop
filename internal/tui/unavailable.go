package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// renderUnavailablePanel produces a centered "feature not available on this
// OS" placeholder for views (or sub-panels) that have no Tier 1 path on the
// current build target. Distinct from mock data — used when no toggle from
// the user side can flip it to real.
//
// Use this in place of mocked content so the F2 / lock-graph panels on
// macOS state the limitation explicitly instead of showing fake data that
// looks like a working monitor.
func renderUnavailablePanel(title, reason string, w, h int) string {
	if h <= 0 {
		return ""
	}
	titleStyle := lipgloss.NewStyle().
		Foreground(ColorRed).
		Background(ColorPanel).
		Bold(true)
	reasonStyle := lipgloss.NewStyle().
		Foreground(ColorMuted).
		Background(ColorPanel).
		Italic(true)
	hintStyle := lipgloss.NewStyle().
		Foreground(ColorDim).
		Background(ColorPanel).
		Italic(true)

	lines := []string{
		titleStyle.Render("✕ " + title),
		"",
		reasonStyle.Render(reason),
		"",
		hintStyle.Render("(see issue #22 for the macOS Tier 1 scope)"),
	}

	// Pad to fill height. Center vertically by adding top padding.
	visible := len(lines)
	topPad := (h - visible) / 2
	if topPad < 0 {
		topPad = 0
	}
	body := strings.Repeat("\n", topPad) + strings.Join(lines, "\n")
	return lipgloss.NewStyle().
		Width(w).
		Height(h).
		Align(lipgloss.Center).
		Background(ColorPanel).
		Render(body)
}

// renderUnavailableInline is a compact one-line variant for sub-panels (e.g.
// the lock graph slot inside F4) where there's no room for a full centered
// card. Renders as a single dim italic line.
func renderUnavailableInline(reason string) string {
	style := lipgloss.NewStyle().
		Foreground(ColorRed).
		Background(ColorPanel).
		Italic(true)
	return style.Render("✕ " + reason)
}
