package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Panel renders a box with border + title bar + body.
// w and h are the outer dimensions (including borders).
// The title occupies the first inner line; the body inherits Width=w-2, Height=h-3.
//
// If body is shorter than (h-3) lines, it's padded with spaces.
// If longer, it's truncated via MaxHeight.
func Panel(title, body string, w, h int) string {
	if w < 4 || h < 3 {
		return strings.Repeat(" ", maxInt(w, 0))
	}
	inner := w - 2
	bodyH := h - 3 // 2 borders + 1 title line

	titleBar := lipgloss.NewStyle().
		Background(lipgloss.Color("#0d1017")).
		Foreground(ColorCyan).
		Width(inner).
		Render(" ▸ " + strings.ToUpper(title))

	bodyArea := lipgloss.NewStyle().
		Background(ColorPanel).
		Foreground(ColorText).
		Width(inner).
		Height(bodyH).
		MaxHeight(bodyH).
		Render(body)

	stack := lipgloss.JoinVertical(lipgloss.Left, titleBar, bodyArea)

	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(ColorBorder).
		BorderBackground(ColorBG).
		Render(stack)
}

// PanelTitleless renders a box with border but no title (useful for the FD table).
func PanelTitleless(body string, w, h int) string {
	if w < 2 || h < 2 {
		return strings.Repeat(" ", maxInt(w, 0))
	}
	inner := w - 2
	bodyH := h - 2

	bodyArea := lipgloss.NewStyle().
		Background(ColorPanel).
		Foreground(ColorText).
		Width(inner).
		Height(bodyH).
		MaxHeight(bodyH).
		Render(body)

	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(ColorBorder).
		BorderBackground(ColorBG).
		Render(bodyArea)
}

// splitFlex distributes an integer total among slots proportional to the ratios.
// Ensures the sum is exactly `total` by dumping the remainder into the last slice.
func splitFlex(ratios []float64, total int) []int {
	out := make([]int, len(ratios))
	if total <= 0 || len(ratios) == 0 {
		return out
	}
	sum := 0.0
	for _, r := range ratios {
		sum += r
	}
	if sum <= 0 {
		return out
	}
	used := 0
	for i := 0; i < len(ratios)-1; i++ {
		out[i] = int(float64(total) * ratios[i] / sum)
		used += out[i]
	}
	out[len(ratios)-1] = total - used
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// padRight returns s padded with spaces up to `w` columns (visible width).
// The padding is rendered with Background(ColorPanel) — otherwise, rendered
// cells would have the terminal's default bg and leak through the gap.
func padRight(s string, w int) string {
	vw := lipgloss.Width(s)
	if vw >= w {
		return s
	}
	pad := lipgloss.NewStyle().Background(ColorPanel).Render(strings.Repeat(" ", w-vw))
	return s + pad
}

// panelRow concatenates segments with a 1-space separator PAINTED with
// ColorPanel — use to build rows inside panel bodies without leaving
// gaps with the terminal's default bg leaking between words.
//
// Replaces the old pattern `name + " " + bar + " " + count`.
func panelRow(parts ...string) string {
	return strings.Join(parts, panelSp1)
}

// panelGap returns `width` spaces painted with ColorPanel.
// Use in lipgloss.JoinHorizontal when you need a gap between elements:
//
//	lipgloss.JoinHorizontal(lipgloss.Top, spark, panelGap(2), right)
//
// — instead of raw `"  "` which would leak the terminal's background.
func panelGap(width int) string {
	if width <= 0 {
		return ""
	}
	return lipgloss.NewStyle().Background(ColorPanel).Render(strings.Repeat(" ", width))
}

var (
	panelSp1 = panelGap(1)
	panelSp2 = panelGap(2)
)

// truncate cuts s to fit in `w` visible columns, adding "…" if necessary.
func truncate(s string, w int) string {
	if w <= 0 {
		return ""
	}
	vw := lipgloss.Width(s)
	if vw <= w {
		return s
	}
	if w == 1 {
		return "…"
	}
	// runes, taking width into account
	runes := []rune(s)
	out := make([]rune, 0, len(runes))
	used := 0
	for _, r := range runes {
		rw := lipgloss.Width(string(r))
		if used+rw >= w {
			break
		}
		out = append(out, r)
		used += rw
	}
	return string(out) + "…"
}
