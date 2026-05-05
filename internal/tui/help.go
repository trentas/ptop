package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// renderHelpOverlay desenha um modal centralizado com todos os keybindings.
// Recebe as dimensões totais do content area; lipgloss.Place centraliza o card.
//
// O model é passado pra que possamos mostrar status dos collectors em runtime
// (real vs mock) — issue #19 acceptance: "Tecla ou flag pra ver o status de
// cada collector em runtime".
func renderHelpOverlayWithStatus(m Model, w, h int) string {
	sectionTitle := lipgloss.NewStyle().Foreground(ColorCyan).Bold(true)
	keyStyle := lipgloss.NewStyle().Foreground(ColorTeal).Bold(true)
	descStyle := lipgloss.NewStyle().Foreground(ColorText)
	dimDesc := lipgloss.NewStyle().Foreground(ColorMuted)

	row := func(key, desc string) string {
		return keyStyle.Render(padRight(key, 14)) + " " + descStyle.Render(desc)
	}
	dimRow := func(key, desc string) string {
		return keyStyle.Render(padRight(key, 14)) + " " + dimDesc.Render(desc)
	}

	statusReal := lipgloss.NewStyle().Foreground(ColorGreen).Render("● real")
	statusMock := lipgloss.NewStyle().Foreground(ColorAmber).Render("○ mock")
	statusRow := func(name string, isMock bool) string {
		s := statusReal
		if isMock {
			s = statusMock
		}
		return keyStyle.Render(padRight(name, 14)) + " " + s
	}

	lines := []string{
		sectionTitle.Render("Navegação"),
		row("F1-F7", "Trocar aba"),
		row("1-7", "Atalho da aba (alternativa ao F1-F7)"),
		row("Tab", "Próxima aba"),
		row("Shift+Tab", "Aba anterior"),
		"",
		sectionTitle.Render("Filtro"),
		row("/", "Abre filtro substring (ou cicla tipos em F6 quando vazio)"),
		row("Enter", "Confirma filtro"),
		row("Esc", "Cancela input · ou limpa filtro · ou fecha help"),
		row("Ctrl+U", "Limpa o que está sendo digitado"),
		"",
		sectionTitle.Render("Estado"),
		row("p, Space", "Pausar / retomar simulação"),
		row("?", "Abre / fecha esta tela"),
		row("q, Ctrl+C", "Sair"),
		"",
		sectionTitle.Render("Snapshot / Export"),
		row("s", "Snapshot one-shot (xray-snapshot-<ts>.json)"),
		row("e", "Toggle export contínuo (xray-export-<ts>.jsonl)"),
		dimRow("--export", "Flag CLI: export desde o launch + snapshot final ao sair"),
		"",
		sectionTitle.Render("Collectors"),
		statusRow("cpu", m.usingMockCPU),
		statusRow("memory", m.usingMockMem),
		statusRow("threads", m.usingMockThreads),
		statusRow("io-wait", m.usingMockIOWait),
		statusRow("io-throughput", m.usingMockIOThrough),
		statusRow("fds", m.usingMockFDs),
	}

	body := strings.Join(lines, "\n")

	card := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorCyan).
		Background(ColorPanel).
		Padding(1, 3).
		Render(body)

	// Centraliza o card sobre fundo escurecido. lipgloss.Place pinta a área
	// total com a cor base e posiciona o card no centro.
	return lipgloss.Place(w, h,
		lipgloss.Center, lipgloss.Center,
		card,
		lipgloss.WithWhitespaceBackground(ColorBG),
	)
}

// renderFilterInput desenha o widget de input ativo em vez do statusbar.
// Mostra o cursor como bloco ▏ no fim do buffer. width = m.Width.
func renderFilterInput(m Model, w int) string {
	barBg := lipgloss.Color("#0a0d11")
	prompt := lipgloss.NewStyle().
		Foreground(ColorTeal).
		Background(barBg).
		Bold(true).
		Render(" / ")
	hint := lipgloss.NewStyle().
		Foreground(ColorDim).
		Background(barBg).
		Render(" Enter confirma · Esc cancela · Ctrl+U limpa")

	cursor := lipgloss.NewStyle().Foreground(ColorBright).Background(barBg).Render("▏")
	value := lipgloss.NewStyle().Foreground(ColorBright).Background(barBg).Render(m.inputBuf)

	used := lipgloss.Width(prompt) + lipgloss.Width(value) + lipgloss.Width(cursor) + lipgloss.Width(hint)
	gap := w - used - 2
	if gap < 1 {
		gap = 1
	}
	pad := lipgloss.NewStyle().Background(barBg).Render(strings.Repeat(" ", gap))
	edge := lipgloss.NewStyle().Background(barBg).Render(" ")
	return edge + prompt + value + cursor + pad + hint + edge
}
