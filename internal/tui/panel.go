package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Panel renderiza uma caixa com borda + barra de título + corpo.
// w e h são as dimensões externas (incluindo bordas).
// O título ocupa a primeira linha interna; o corpo herda Width=w-2, Height=h-3.
//
// Se body for menor que (h-3) linhas, será preenchido com espaços.
// Se for maior, será truncado via MaxHeight.
func Panel(title, body string, w, h int) string {
	if w < 4 || h < 3 {
		return strings.Repeat(" ", maxInt(w, 0))
	}
	inner := w - 2
	bodyH := h - 3 // 2 bordas + 1 linha de título

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

// PanelTitleless renderiza uma caixa com borda mas sem título (útil para FD table).
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

// splitFlex distribui um total inteiro entre slots proporcionais às ratios.
// Garante que a soma seja exatamente `total` jogando o resto na última fatia.
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

// padRight retorna s padded com espaços até `w` colunas (largura visível).
// O padding sai com Background(ColorPanel) — caso contrário, células
// rendered ficariam com bg default do terminal e vazariam pelo gap.
func padRight(s string, w int) string {
	vw := lipgloss.Width(s)
	if vw >= w {
		return s
	}
	pad := lipgloss.NewStyle().Background(ColorPanel).Render(strings.Repeat(" ", w-vw))
	return s + pad
}

// panelRow concatena segments com um separador de 1 espaço PINTADO com
// ColorPanel — usar pra montar linhas dentro de panel bodies sem deixar
// gaps com bg default do terminal vazando entre as palavras.
//
// Substitui o padrão antigo `name + " " + bar + " " + count`.
func panelRow(parts ...string) string {
	sep := lipgloss.NewStyle().Background(ColorPanel).Render(" ")
	return strings.Join(parts, sep)
}

// truncate corta s para caber em `w` colunas visíveis, adicionando "…" se necessário.
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
	// runes, considerando largura
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
