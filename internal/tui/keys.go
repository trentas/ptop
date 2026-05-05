package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// fdFilters define a ordem de ciclagem ao apertar '/' na FD view.
var fdFilters = []string{"all", "file", "socket", "pipe", "epoll", "timer"}

// handleKey processa entrada do teclado.
// Retorna o model atualizado (cópia mutada) e qualquer Cmd subsequente.
func (m Model) handleKey(msg tea.KeyMsg) (Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit

	case "p", " ":
		m.Paused = !m.Paused

	case "f1", "1":
		m.ActiveTab = TabOverview
	case "f2", "2":
		m.ActiveTab = TabSyscalls
	case "f3", "3":
		m.ActiveTab = TabNetwork
	case "f4", "4":
		m.ActiveTab = TabThreads
	case "f5", "5":
		m.ActiveTab = TabIO
	case "f6", "6":
		m.ActiveTab = TabFD
	case "f7", "7":
		m.ActiveTab = TabTimeline

	case "tab", "right", "l":
		m.ActiveTab = (m.ActiveTab + 1) % TabCount
	case "shift+tab", "left", "h":
		m.ActiveTab = (m.ActiveTab - 1 + TabCount) % TabCount

	case "/":
		// Cicla o filtro do FD view. Implementação simplificada — substituir
		// por input field quando o módulo de input estiver pronto.
		if m.ActiveTab == TabFD {
			for i, f := range fdFilters {
				if f == m.FDFilter {
					m.FDFilter = fdFilters[(i+1)%len(fdFilters)]
					return m, nil
				}
			}
			m.FDFilter = fdFilters[0]
		}

	case "s", "e":
		// snapshot / export — placeholders. A implementação real grava JSON em disco.
	}
	return m, nil
}
