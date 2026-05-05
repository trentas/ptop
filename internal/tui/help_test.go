package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// TestHelpOverlayToggle confirma que `?` abre/fecha o help.
func TestHelpOverlayToggle(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width = 140
	m.Height = 40

	if m.showHelp {
		t.Fatal("showHelp deveria começar false")
	}

	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	m = nm.(Model)
	if !m.showHelp {
		t.Error("? não abriu help")
	}

	// View() deve renderizar o overlay quando showHelp
	out := m.View()
	if !strings.Contains(out, "Navegação") {
		t.Error("overlay não renderizou seção Navegação")
	}
	if !strings.Contains(out, "Filtro") {
		t.Error("overlay não renderizou seção Filtro")
	}

	// Qualquer tecla fecha
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	m = nm.(Model)
	if m.showHelp {
		t.Error("tecla não fechou o help")
	}
}

// TestFilterInputFlow exercita / → tipa → Enter → confirma filtro
func TestFilterInputFlow(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width = 140
	m.Height = 40
	m.ActiveTab = TabSyscalls // F6 tem o cycle dos types — uso outra view

	// Inicialmente sem filtro
	if m.filter != "" || m.inputMode != InputModeNone {
		t.Fatal("estado inicial inesperado")
	}

	// Press /
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = nm.(Model)
	if m.inputMode != InputModeFilter {
		t.Errorf("após '/', inputMode=%d (esperado %d)", m.inputMode, InputModeFilter)
	}

	// Type "tcp"
	for _, r := range "tcp" {
		nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = nm.(Model)
	}
	if m.inputBuf != "tcp" {
		t.Errorf("inputBuf=%q", m.inputBuf)
	}
	if m.filter != "" {
		t.Error("filter não deveria ter mudado antes de Enter")
	}

	// Press Enter
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = nm.(Model)
	if m.filter != "tcp" {
		t.Errorf("após Enter, filter=%q (esperado tcp)", m.filter)
	}
	if m.inputMode != InputModeNone {
		t.Error("inputMode deveria ter saído")
	}
	if m.inputBuf != "" {
		t.Error("inputBuf deveria estar vazio após Enter")
	}

	// Esc fora de input mode com filter ativo limpa o filtro
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = nm.(Model)
	if m.filter != "" {
		t.Errorf("Esc não limpou filter, ainda %q", m.filter)
	}
}

// TestFilterEscCancelsKeepsPreviousFilter — Esc dentro de input mode mantém o filtro anterior
func TestFilterEscCancelsKeepsPreviousFilter(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width = 140
	m.Height = 40
	m.ActiveTab = TabSyscalls
	m.filter = "old"

	// Press / — inputBuf pré-popula com filter atual
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = nm.(Model)
	if m.inputBuf != "old" {
		t.Errorf("inputBuf não pré-populou: %q", m.inputBuf)
	}

	// Type "X" para descaracterizar
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'X'}})
	m = nm.(Model)

	// Press Esc — deve cancelar e MANTER filter anterior
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = nm.(Model)
	if m.filter != "old" {
		t.Errorf("após Esc cancelando input, filter=%q (esperado 'old')", m.filter)
	}
	if m.inputMode != InputModeNone {
		t.Error("inputMode não saiu")
	}
}

// TestFilterFDView_substring confirma que m.filter restringe FDs em F6
func TestFilterFDView_substring(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width = 180
	m.Height = 40
	m.ActiveTab = TabFD

	// Sem filtro: todas as FDs aparecem
	out := m.View()
	if !strings.Contains(out, "stdin") || !strings.Contains(out, "TCP") {
		t.Error("baseline deveria ter stdin e TCP")
	}

	// Aplica filtro "TCP"
	m.filter = "TCP"
	out = m.View()
	if !strings.Contains(out, "TCP") {
		t.Error("após filter=TCP, esperava ver TCP")
	}
	if strings.Contains(out, "stdin") {
		t.Error("após filter=TCP, stdin não deveria aparecer")
	}
}
