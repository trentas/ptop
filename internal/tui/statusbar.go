package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// renderStatusBar desenha o rodapé com keybindings e info de overhead.
// Igual ao header/tabbar: nunca pode estourar m.Width.
func renderStatusBar(m Model) string {
	barBg := lipgloss.Color("#0a0d11")
	keyStyle := lipgloss.NewStyle().Foreground(ColorCyan).Background(barBg).Bold(true)
	lblStyle := lipgloss.NewStyle().Foreground(ColorDim).Background(barBg)

	hint := func(key, label string) string {
		return keyStyle.Render(key) + lblStyle.Render(" "+label)
	}

	// versões longa e curta dos keybindings
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
	// Toast tem prioridade — substitui o info da direita por 2s
	if m.toast != "" {
		toastStyle := lipgloss.NewStyle().
			Foreground(ColorTeal).
			Background(barBg).
			Bold(true)
		// Se toast começa com ⚠, troca pra cor de aviso
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
		rightParts = append(rightParts, lblStyle.Render("eBPF kernel 6.8 · sampling 100Hz · overhead <0.5%"))
	}
	right := strings.Join(rightParts, lblStyle.Render("  "))

	// degrada progressivamente: drop info → keybindings curtos → drop right inteiro
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
