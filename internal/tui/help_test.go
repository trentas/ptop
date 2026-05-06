package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// TestHelpOverlayToggle confirms that `?` opens/closes the help.
func TestHelpOverlayToggle(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width = 140
	m.Height = 40

	if m.showHelp {
		t.Fatal("showHelp should start false")
	}

	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	m = nm.(Model)
	if !m.showHelp {
		t.Error("? did not open help")
	}

	// View() should render the overlay when showHelp
	out := m.View()
	if !strings.Contains(out, "Navigation") {
		t.Error("overlay did not render Navigation section")
	}
	if !strings.Contains(out, "Filter") {
		t.Error("overlay did not render Filter section")
	}

	// Key 'a' no longer closes (only ?, esc, q close — others are ignored
	// to allow scrolling with arrows/PgUp/PgDn without closing accidentally).
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	m = nm.(Model)
	if !m.showHelp {
		t.Error("key 'a' closed help — should ignore")
	}

	// '?' closes
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	m = nm.(Model)
	if m.showHelp {
		t.Error("? did not close help")
	}
}

func TestHelpScroll(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width = 80
	m.Height = 24
	m.showHelp = true

	if m.helpScroll != 0 {
		t.Fatal("initial helpScroll != 0")
	}

	// ↓ increases scroll
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = nm.(Model)
	if m.helpScroll != 1 {
		t.Errorf("after ↓, helpScroll=%d (expected 1)", m.helpScroll)
	}

	// ↑ decreases
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = nm.(Model)
	if m.helpScroll != 0 {
		t.Errorf("after ↑, helpScroll=%d (expected 0)", m.helpScroll)
	}

	// ↑ doesn't go below 0
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = nm.(Model)
	if m.helpScroll != 0 {
		t.Errorf("↑ at top should stay at 0, got %d", m.helpScroll)
	}

	// Esc closes and zeroes scroll
	m.helpScroll = 5
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = nm.(Model)
	if m.showHelp || m.helpScroll != 0 {
		t.Errorf("Esc should close and zero scroll: showHelp=%v scroll=%d", m.showHelp, m.helpScroll)
	}
}

// TestFilterInputFlow exercises / → type → Enter → confirm filter
func TestFilterInputFlow(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width = 140
	m.Height = 40
	m.ActiveTab = TabSyscalls // F6 has the type cycle — use another view

	// Initially no filter
	if m.filter != "" || m.inputMode != InputModeNone {
		t.Fatal("unexpected initial state")
	}

	// Press /
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = nm.(Model)
	if m.inputMode != InputModeFilter {
		t.Errorf("after '/', inputMode=%d (expected %d)", m.inputMode, InputModeFilter)
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
		t.Error("filter should not have changed before Enter")
	}

	// Press Enter
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = nm.(Model)
	if m.filter != "tcp" {
		t.Errorf("after Enter, filter=%q (expected tcp)", m.filter)
	}
	if m.inputMode != InputModeNone {
		t.Error("inputMode should have exited")
	}
	if m.inputBuf != "" {
		t.Error("inputBuf should be empty after Enter")
	}

	// Esc outside input mode with active filter clears the filter
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = nm.(Model)
	if m.filter != "" {
		t.Errorf("Esc did not clear filter, still %q", m.filter)
	}
}

// TestFilterEscCancelsKeepsPreviousFilter — Esc inside input mode keeps the previous filter
func TestFilterEscCancelsKeepsPreviousFilter(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width = 140
	m.Height = 40
	m.ActiveTab = TabSyscalls
	m.filter = "old"

	// Press / — inputBuf pre-populates with current filter
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = nm.(Model)
	if m.inputBuf != "old" {
		t.Errorf("inputBuf did not pre-populate: %q", m.inputBuf)
	}

	// Type "X" to alter it
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'X'}})
	m = nm.(Model)

	// Press Esc — should cancel and KEEP previous filter
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = nm.(Model)
	if m.filter != "old" {
		t.Errorf("after Esc cancelling input, filter=%q (expected 'old')", m.filter)
	}
	if m.inputMode != InputModeNone {
		t.Error("inputMode did not exit")
	}
}

// TestFilterFDView_substring confirms that m.filter restricts FDs in F6
func TestFilterFDView_substring(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width = 180
	m.Height = 40
	m.ActiveTab = TabFD

	// No filter: all FDs appear
	out := m.View()
	if !strings.Contains(out, "stdin") || !strings.Contains(out, "TCP") {
		t.Error("baseline should have stdin and TCP")
	}

	// Apply filter "TCP"
	m.filter = "TCP"
	out = m.View()
	if !strings.Contains(out, "TCP") {
		t.Error("after filter=TCP, expected to see TCP")
	}
	if strings.Contains(out, "stdin") {
		t.Error("after filter=TCP, stdin should not appear")
	}
}
