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
		rightParts = append(rightParts, toastStyleFor(m.toast, barBg).Render(m.toast))
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
		rightParts = append(rightParts, lblStyle.Render(statusBarSourceLabel()))
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
	// Last resort. A toast is SHORTENED rather than dropped: it is the only
	// thing on this bar that answers a question the operator just asked, and
	// the answer is usually a path. Dropping it at 80 or 100 columns — which is
	// where an absolute path stops fitting, and where most terminals are — hands
	// back nothing at all.
	//
	// Truncated from the LEFT, keeping the tail: the file name and the nearest
	// directories identify it, the leading /home/… does not.
	if lipgloss.Width(left)+lipgloss.Width(right)+3 > m.Width {
		if m.toast != "" {
			budget := m.Width - lipgloss.Width(left) - 3
			right = toastStyleFor(m.toast, barBg).Render(truncateLeft(m.toast, budget))
		} else {
			right = ""
		}
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

// toastStyleFor colours a toast: amber when it opens with the warning sign,
// teal otherwise.
func toastStyleFor(toast string, bg lipgloss.Color) lipgloss.Style {
	st := lipgloss.NewStyle().Foreground(ColorTeal).Background(bg).Bold(true)
	if strings.HasPrefix(toast, "⚠") {
		st = st.Foreground(ColorAmber)
	}
	return st
}

// truncateLeft keeps the END of a string, marking the cut with a leading "…".
//
// The opposite of truncate(), and for a reason: this is used on paths, where
// the tail is what identifies the file and the head is the part every path on
// the machine has in common.
func truncateLeft(s string, w int) string {
	if w <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	if w == 1 {
		return "…"
	}
	return "…" + string(r[len(r)-(w-1):])
}
