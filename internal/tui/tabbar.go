package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// renderTabBar desenha a linha de abas F1-F7 com a aba ativa destacada em ciano.
// Crítico: nunca pode estourar m.Width (caso contrário o terminal wrappa e
// destrói a layout abaixo). Em larguras apertadas a hint da direita some,
// e em larguras muito apertadas usamos labels curtos (F1, F2…).
func renderTabBar(m Model) string {
	tabBg := lipgloss.Color("#0d1017")

	hint := lipgloss.NewStyle().
		Foreground(ColorDim).
		Background(tabBg).
		Padding(0, 2).
		Render("q quit · / filter · p pause")

	// tenta a versão completa; se não couber, derrubamos a hint;
	// se ainda assim não couber, abreviamos os labels.
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
		// último recurso: trunca os tabs (não deveria acontecer com short labels)
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

