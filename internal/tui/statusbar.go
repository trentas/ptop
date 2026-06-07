package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// renderStatusBar draws the footer with keybindings and overhead info.
// Like the header/tabbar: must never overflow m.Width.
func renderStatusBar(m Model) string {
	barBg := lipgloss.Color("#0a0d11")
	keyStyle := lipgloss.NewStyle().Foreground(ColorCyan).Background(barBg).Bold(true)
	lblStyle := lipgloss.NewStyle().Foreground(ColorDim).Background(barBg)

	hint := func(key, label string) string {
		return keyStyle.Render(key) + lblStyle.Render(" "+label)
	}

	// long and short versions of the keybindings
	longParts := []string{
		hint("F1-F7", "tabs"),
		hint("q", "quit"),
		hint("p", "pause"),
		hint("/", "filter"),
		hint("s", "snapshot"),
		hint("e", "export"),
	}
	shortParts := []string{
		hint("F1-F7", "tabs"),
		hint("q", "quit"),
		hint("p", "pause"),
		hint("/", "filter"),
	}
	miniParts := []string{
		hint("F1-F7", "tabs"),
		hint("q", "quit"),
	}

	left := strings.Join(longParts, lblStyle.Render("  ·  "))

	rightParts := []string{}
	// Toast has priority — replaces the right info for 2s
	if m.toast != "" {
		toastStyle := lipgloss.NewStyle().
			Foreground(ColorTeal).
			Background(barBg).
			Bold(true)
		// If toast starts with ⚠, switch to warning color
		if strings.HasPrefix(m.toast, "⚠") {
			toastStyle = toastStyle.Foreground(ColorAmber)
		}
		rightParts = append(rightParts, toastStyle.Render(m.toast))
	} else {
		if m.Paused {
			rightParts = append(rightParts, lipgloss.NewStyle().
				Foreground(ColorAmber).
				Background(barBg).
				Bold(true).
				Render("⏸ PAUSED"))
		}
		if m.cfg.NoEBPF {
			rightParts = append(rightParts, lipgloss.NewStyle().
				Foreground(ColorOrange).
				Background(barBg).
				Render("[--no-ebpf]"))
		}
		if m.exportFile != nil {
			rightParts = append(rightParts, lipgloss.NewStyle().
				Foreground(ColorTeal).
				Background(barBg).
				Render("● REC"))
		}
		rightParts = append(rightParts, lblStyle.Render(statusBarSourceLabel))
	}
	right := strings.Join(rightParts, lblStyle.Render("  "))

	// degrade progressively: drop info → short keybindings → drop right entirely
	if lipgloss.Width(left)+lipgloss.Width(right)+3 > m.Width {
		right = strings.Join(rightParts, lblStyle.Render("  "))
	}
	if lipgloss.Width(left)+lipgloss.Width(right)+3 > m.Width {
		left = strings.Join(shortParts, lblStyle.Render("  ·  "))
	}
	if lipgloss.Width(left)+lipgloss.Width(right)+3 > m.Width {
		left = strings.Join(miniParts, lblStyle.Render("  ·  "))
	}
	if lipgloss.Width(left)+lipgloss.Width(right)+3 > m.Width {
		right = ""
	}

	gap := m.Width - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if gap < 1 {
		gap = 1
	}
	pad := lipgloss.NewStyle().Background(barBg).Render(strings.Repeat(" ", gap))
	edge := lipgloss.NewStyle().Background(barBg).Render(" ")

	return edge + left + pad + right + edge
}
