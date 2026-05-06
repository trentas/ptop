package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// sourceProcOrEmpty retorna "/proc" quando o collector está rodando real,
// "" caso contrário. Usado pra anotar a source no help overlay.
func sourceProcOrEmpty(real bool) string {
	if real {
		return "/proc"
	}
	return ""
}

// renderHelpOverlay desenha um modal centralizado com todos os keybindings.
// Recebe as dimensões totais do content area; lipgloss.Place centraliza o card.
//
// O model é passado pra que possamos mostrar status dos collectors em runtime
// (real vs mock) — issue #19 acceptance: "Tecla ou flag pra ver o status de
// cada collector em runtime".
func renderHelpOverlayWithStatus(m Model, w, h int) string {
	// Help overlay vive sobre o ColorPanel do card. Todos os estilos abaixo
	// setam ColorPanel como bg pra que segmentos não vazem o background do
	// terminal entre as palavras.
	sectionTitle := lipgloss.NewStyle().Foreground(ColorCyan).Background(ColorPanel).Bold(true)
	keyStyle := lipgloss.NewStyle().Foreground(ColorTeal).Background(ColorPanel).Bold(true)
	descStyle := lipgloss.NewStyle().Foreground(ColorText).Background(ColorPanel)
	dimDesc := lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorPanel)

	row := func(key, desc string) string {
		return keyStyle.Render(padRight(key, 14)) + descStyle.Render(" "+desc)
	}
	dimRow := func(key, desc string) string {
		return keyStyle.Render(padRight(key, 14)) + dimDesc.Render(" "+desc)
	}

	statusReal := lipgloss.NewStyle().Foreground(ColorGreen).Background(ColorPanel).Render("● real")
	statusMock := lipgloss.NewStyle().Foreground(ColorAmber).Background(ColorPanel).Render("○ mock")
	sourceStyle := lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorPanel).Italic(true)

	statusRow := func(name string, isMock bool, source string) string {
		s := statusReal
		if isMock {
			s = statusMock
		}
		row := keyStyle.Render(padRight(name, 14)) + descStyle.Render(" ") + s
		if source != "" {
			row += sourceStyle.Render(" via " + source)
		}
		return row
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
		statusRow("syscalls", m.usingMockSyscalls, m.syscallsSource),
		statusRow("cpu", m.usingMockCPU, m.cpuSource),
		statusRow("io-files", m.usingMockIOFiles, m.ioFilesSource),
		statusRow("network", m.usingMockNet, m.netSource),
		statusRow("memory", m.usingMockMem, m.memSource),
		statusRow("threads", m.usingMockThreads, m.threadsSource),
		statusRow("io-wait", m.usingMockIOWait, sourceProcOrEmpty(!m.usingMockIOWait)),
		statusRow("io-throughput", m.usingMockIOThrough, sourceProcOrEmpty(!m.usingMockIOThrough)),
		statusRow("fds", m.usingMockFDs, sourceProcOrEmpty(!m.usingMockFDs)),
	}

	// Scroll: card tem border (2 lines) + padding (2 lines) = 4 overhead;
	// se ainda assim sobrar pra scroll indicators (2 linhas), maxBody fica
	// h - 4 - 2 = h - 6. Em terminais 80x24 com chrome ocupando ~3 linhas,
	// contentH ≈ 21, maxBody ≈ 15 — menor que ~30 linhas do help. Scroll é
	// realmente necessário.
	maxBody := h - 4
	if maxBody < 5 {
		maxBody = 5
	}

	scroll := m.helpScroll
	hasMoreAbove := false
	hasMoreBelow := false

	if len(lines) > maxBody {
		// reserva 2 linhas pros indicators de scroll
		bodyH := maxBody - 2
		if bodyH < 3 {
			bodyH = 3
		}
		// clamp scroll
		maxScroll := len(lines) - bodyH
		if scroll > maxScroll {
			scroll = maxScroll
		}
		if scroll < 0 {
			scroll = 0
		}
		hasMoreAbove = scroll > 0
		hasMoreBelow = scroll+bodyH < len(lines)
		lines = lines[scroll : scroll+bodyH]
	}

	scrollIndicator := func(visible bool, glyph, hint string) string {
		if !visible {
			return lipgloss.NewStyle().Foreground(ColorPanel).Background(ColorPanel).Render(strings.Repeat(" ", 30))
		}
		return lipgloss.NewStyle().Foreground(ColorTeal).Background(ColorPanel).Italic(true).
			Render(glyph + " " + hint)
	}

	if hasMoreAbove || hasMoreBelow {
		lines = append([]string{scrollIndicator(hasMoreAbove, "↑", "mais acima (↑/PgUp)")}, lines...)
		lines = append(lines, scrollIndicator(hasMoreBelow, "↓", "mais abaixo (↓/PgDn)"))
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
