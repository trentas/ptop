package tui

import (
	"fmt"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
)

// fdFilters define a ordem de ciclagem ao apertar '/' na FD view (modo legado
// quando o filtro substring está vazio — `/` apertar de novo entra em input mode).
var fdFilters = []string{"all", "file", "socket", "pipe", "epoll", "timer"}

// handleKey processa entrada do teclado.
//
// Ordem de prioridade:
//  1. Help overlay aberto: qualquer tecla fecha
//  2. Input mode (filtro) ativo: forwarding pra inputBuf, com Enter/Esc/Backspace especiais
//  3. Comandos globais (F1-F7, q, p, etc)
func (m Model) handleKey(msg tea.KeyMsg) (Model, tea.Cmd) {
	key := msg.String()

	// 1. Help overlay
	if m.showHelp {
		m.showHelp = false
		return m, nil
	}

	// 2. Input mode (filtro substring)
	if m.inputMode == InputModeFilter {
		return m.handleFilterInput(msg, key)
	}

	// 3. Comandos globais
	switch key {
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

	case "?":
		m.showHelp = true
		return m, nil

	case "esc":
		// Esc fora de input/help limpa filtro ativo (se houver)
		if m.filter != "" {
			m.filter = ""
		}
		return m, nil

	case "/":
		// Em F6, se o filtro substring está vazio, primeiro `/` cicla os tipos
		// (comportamento legado pra ergonomia rápida). Quando há filtro ativo
		// ou em outras views, abre input mode.
		if m.ActiveTab == TabFD && m.filter == "" {
			for i, f := range fdFilters {
				if f == m.FDFilter {
					m.FDFilter = fdFilters[(i+1)%len(fdFilters)]
					return m, nil
				}
			}
			m.FDFilter = fdFilters[0]
			return m, nil
		}
		// Entra em modo de input com o valor atual pré-preenchido
		m.inputMode = InputModeFilter
		m.inputBuf = m.filter
		return m, nil

	case "s":
		path, err := SaveSnapshot(m)
		if err != nil {
			m.toast = fmtToast("⚠ snapshot: %v", err)
		} else {
			m.toast = fmtToast("✓ snapshot: %s", path)
		}
		return m, clearToastAfter(toastTTL)

	case "e":
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
		return m, tea.Batch(exportTick(), clearToastAfter(toastTTL))
	}
	return m, nil
}

// handleFilterInput processa teclas em modo de input. Enter confirma, Esc
// cancela mantendo o filtro anterior, Backspace apaga, runas printáveis são
// concatenadas.
func (m Model) handleFilterInput(msg tea.KeyMsg, key string) (Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		m.filter = m.inputBuf
		m.inputMode = InputModeNone
		m.inputBuf = ""
		return m, nil

	case tea.KeyEsc, tea.KeyCtrlC:
		// Cancela: fecha input sem alterar o filtro vigente
		m.inputMode = InputModeNone
		m.inputBuf = ""
		return m, nil

	case tea.KeyBackspace:
		if len(m.inputBuf) > 0 {
			r := []rune(m.inputBuf)
			m.inputBuf = string(r[:len(r)-1])
		}
		return m, nil

	case tea.KeyCtrlU:
		m.inputBuf = ""
		return m, nil

	case tea.KeyRunes:
		// Concatena os runas do evento — geralmente 1 rune por keystroke,
		// mas paste pode entregar vários de uma vez
		m.inputBuf += string(msg.Runes)
		return m, nil

	case tea.KeySpace:
		m.inputBuf += " "
		return m, nil
	}

	// Fallback: alguns terminais entregam printáveis como string única
	if len(key) == 1 && unicode.IsPrint(rune(key[0])) {
		m.inputBuf += key
	}
	return m, nil
}

// fmtToast wrapper de fmt.Sprintf — deixa o switch acima legível.
func fmtToast(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}
