package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// renderHeader desenha a barra superior:
//
//	⬡ bpf-inspector │ <process> [PID N] [Go 1.22] [STATE] [N fds]            uptime MM:SS │ HH:MM:SS
//
// O resultado é SEMPRE truncado para caber em m.Width. Se a linha estourar a
// largura, o terminal faz line-wrap e o resto da TUI vira de ponta-cabeça —
// daí a obsessão por nunca passar do limite.
func renderHeader(m Model) string {
	headerBg := lipgloss.Color("#0a0d11")

	logo := lipgloss.NewStyle().
		Foreground(ColorCyan).
		Background(headerBg).
		Bold(true).
		Render("⬡ bpf-inspector")

	sep := lipgloss.NewStyle().
		Foreground(ColorBorder).
		Background(headerBg).
		Render("│")

	procName := lipgloss.NewStyle().
		Foreground(ColorBright).
		Background(headerBg).
		Render(m.ProcessName)

	pidBadge := Badge(fmt.Sprintf("PID %d", m.cfg.PID), ColorBlue)
	rtBadge := Badge(m.Runtime, ColorCyan)

	stateColor := ColorGreen
	switch strings.ToUpper(m.State) {
	case "BLOCKED", "STOPPED", "ZOMBIE":
		stateColor = ColorRed
	case "SLEEPING":
		stateColor = ColorMuted
	}
	stateBadge := Badge(strings.ToUpper(m.State), stateColor)

	fdBadge := Badge(fmt.Sprintf("%d fds", len(m.FDs)), ColorTeal)

	// monta segmentos do "left" em ordem de prioridade decrescente
	// (seg é declarado ao final do arquivo)
	leftSegs := []seg{
		{logo, 0},
		{sep, 0},
		{procName, 0},
		{pidBadge, 0},
		{rtBadge, 2},
		{stateBadge, 1},
		{fdBadge, 1},
	}

	uptime := time.Since(m.StartedAt)
	upMin := int(uptime.Minutes())
	upSec := int(uptime.Seconds()) % 60

	clock := time.Now().Format("15:04:05")
	rightFull := fmt.Sprintf("uptime %02d:%02d  │  %s", upMin, upSec, clock)
	rightShort := clock // versão fallback para terminais estreitos

	style := lipgloss.NewStyle().Foreground(ColorMuted).Background(headerBg)

	// determina qual versão do "right" cabe
	// e quais segmentos do "left" cortar
	left := buildSegments(leftSegs, " ")
	right := style.Render(rightFull)
	for budget := 0; budget < 4; budget++ {
		if lipgloss.Width(left)+lipgloss.Width(right)+3 <= m.Width {
			break
		}
		// 1) tentar versão curta do right
		if budget == 0 {
			right = style.Render(rightShort)
			continue
		}
		// 2) descartar segmentos opcionais do left por prioridade
		left = buildSegments(filterSegs(leftSegs, budget), " ")
	}

	gap := m.Width - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if gap < 1 {
		gap = 1
	}
	pad := lipgloss.NewStyle().Background(headerBg).Render(strings.Repeat(" ", gap))
	edge := lipgloss.NewStyle().Background(headerBg).Render(" ")

	return edge + left + pad + right + edge
}

// buildSegments concatena seg.text com sep, respeitando ordem.
func buildSegments(segs []seg, sep string) string {
	parts := make([]string, 0, len(segs))
	for _, s := range segs {
		parts = append(parts, s.text)
	}
	return strings.Join(parts, sep)
}

// filterSegs retorna apenas segmentos com prioridade <= maxPrio.
// Usado para reduzir o conjunto a caber numa largura menor.
func filterSegs(segs []seg, maxPrio int) []seg {
	limit := 0
	switch maxPrio {
	case 1:
		limit = 1 // mantém prio 0 e 1
	case 2:
		limit = 0 // só essenciais
	default:
		limit = 0
	}
	out := make([]seg, 0, len(segs))
	for _, s := range segs {
		if s.prio <= limit {
			out = append(out, s)
		}
	}
	return out
}

type seg struct {
	text string
	prio int
}
