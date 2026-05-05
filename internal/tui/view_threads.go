package tui

import (
	"github.com/charmbracelet/lipgloss"
)

// renderThreadsView (F4) — assets/mockup.jsx → ThreadView
func renderThreadsView(m Model, w, h int) string {
	if w < 40 || h < 10 {
		return MutedStyle.Render("(terminal pequeno demais)")
	}
	leftW := w * 2 / 3
	rightW := w - leftW

	body := renderThreadTable(m.Threads, leftW-2, h-3-4) +
		"\n\n" +
		renderLockGraph(m, leftW-2)

	threads := Panel("Thread State", body, leftW, h)

	stream := Panel("Lock Events",
		renderTimelineCompact(filterTimelineByCategory(m.Timeline, "lock"), rightW-2, h-3),
		rightW, h)

	return lipgloss.JoinHorizontal(lipgloss.Top, threads, stream)
}

// renderLockGraph desenha um grafo textual simples de locks contestados.
// Versão MVP — quando vier um collector real, substituir por análise de hold/wait.
func renderLockGraph(m Model, w int) string {
	title := MutedStyle.Render("lock graph")
	body := lipgloss.NewStyle().Foreground(ColorAmber).Render("mutex-A") +
		MutedStyle.Render(" held by ") +
		GreenStyle.Render("main(1)") +
		MutedStyle.Render(" ← blocked: ") +
		RedStyle.Render("worker-1(2)")
	return title + "\n" + body
}
