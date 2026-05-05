package tui

import (
	"fmt"

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

	case "s":
		// One-shot snapshot: grava xray-snapshot-<timestamp>.json em cwd.
		path, err := SaveSnapshot(m)
		if err != nil {
			m.toast = fmtToast("⚠ snapshot: %v", err)
		} else {
			m.toast = fmtToast("✓ snapshot: %s", path)
		}
		return m, clearToastAfter(toastTTL)

	case "e":
		// Toggle export contínuo: liga/desliga o JSONL.
		if m.exportFile != nil {
			_ = m.exportFile.Close()
			m.exportFile = nil
			m.toast = "✓ export: OFF"
			return m, clearToastAfter(toastTTL)
		}
		f, err := openExportFile()
		if err != nil {
			m.toast = fmtToast("⚠ export: %v", err)
			return m, clearToastAfter(toastTTL)
		}
		m.exportFile = f
		m.toast = fmtToast("✓ export: %s", f.Name())
		// Dispara o primeiro tick + clear-toast em paralelo
		return m, tea.Batch(exportTick(), clearToastAfter(toastTTL))
	}
	return m, nil
}

// fmtToast é um wrapper de fmt.Sprintf isolado pra deixar a chamada legível
// no switch acima.
func fmtToast(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}
