package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// renderTabBar draws the F1-F7 tab line with the active tab highlighted in cyan.
// Critical: must never overflow m.Width (otherwise the terminal wraps and
// destroys the layout below). At tight widths the right hint disappears,
// and at very tight widths we use short labels (F1, F2…).
func renderTabBar(m Model) string {
	tabBg := lipgloss.Color("#0d1017")

	hint := lipgloss.NewStyle().
		Foreground(ColorDim).
		Background(tabBg).
		Padding(0, 2).
		Render("q quit · / filter · p pause")

	// try the full version; if it doesn't fit, drop the hint;
	// if it still doesn't fit, abbreviate the labels.
	tabs := buildTabs(m, tabNames)
	if lipgloss.Width(tabs)+lipgloss.Width(hint) > m.Width {
		hint = ""
	}
	if lipgloss.Width(tabs) > m.Width {
		short := []string{"F1", "F2", "F3", "F4", "F5", "F6", "F7"}
		tabs = buildTabs(m, short)
	}

	gap := m.Width - lipgloss.Width(tabs) - lipgloss.Width(hint)
	if gap < 0 {
		// last resort: truncate the tabs (shouldn't happen with short labels)
		return truncate(tabs, m.Width)
	}
	pad := lipgloss.NewStyle().Background(tabBg).Render(strings.Repeat(" ", gap))
	return tabs + pad + hint
}

func buildTabs(m Model, labels []string) string {
	tabBg := lipgloss.Color("#0d1017")
	pieces := make([]string, 0, len(labels))
	for i, name := range labels {
		var style lipgloss.Style
		if i == m.ActiveTab {
			style = lipgloss.NewStyle().
				Foreground(ColorCyan).
				Background(ColorPanel).
				Bold(true).
				Padding(0, 2)
		} else {
			style = lipgloss.NewStyle().
				Foreground(ColorMuted).
				Background(tabBg).
				Padding(0, 2)
		}
		piece := style.Render(name)
		if i < len(labels)-1 {
			piece += lipgloss.NewStyle().Foreground(ColorBorder).Background(tabBg).Render("│")
		}
		pieces = append(pieces, piece)
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, pieces...)
}

