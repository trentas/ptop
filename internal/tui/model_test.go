package tui

import (
	"regexp"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;:?]*[a-zA-Z]`)

func ansiStrip(s string) int {
	return len([]rune(ansiRe.ReplaceAllString(s, "")))
}

// TestRenderAllTabs ensures each tab renders something non-empty at various
// terminal sizes without panicking — vital because the TUI does a lot of
// width arithmetic and any overflow turns into visual corruption.
func TestRenderAllTabs(t *testing.T) {
	sizes := []struct{ w, h int }{
		{120, 40},
		{180, 50},
		{80, 24},
		{200, 60},
	}
	for _, sz := range sizes {
		m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
		m.Width = sz.w
		m.Height = sz.h
		for tab := 0; tab < TabCount; tab++ {
			m.ActiveTab = tab
			out := m.View()
			if out == "" {
				t.Errorf("size=%dx%d tab=%d: empty", sz.w, sz.h, tab)
			}
			if !strings.Contains(out, "ptop") {
				t.Errorf("size=%dx%d tab=%d: header missing", sz.w, sz.h, tab)
			}
		}
	}
}

// TestTickAdvances confirms that the tick advances the CPU history without
// panicking and that the history len is capped.
func TestTickAdvances(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width = 120
	m.Height = 40

	for i := 0; i < 200; i++ {
		nm, _ := m.Update(TickMsg(time.Now()))
		m = nm.(Model)
	}
	if len(m.CPUHistory) > 60 {
		t.Errorf("CPUHistory grew unbounded: %d", len(m.CPUHistory))
	}
	if len(m.IOReadHist) > 60 {
		t.Errorf("IOReadHist grew unbounded: %d", len(m.IOReadHist))
	}
	if len(m.Timeline) > 120 {
		t.Errorf("Timeline grew unbounded: %d", len(m.Timeline))
	}
}

// TestKeyHandling verifies F1-F7 navigate between tabs and q quits.
func TestKeyHandling(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})

	for i := 1; i <= TabCount; i++ {
		key := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{rune('0' + i)}}
		nm, _ := m.Update(key)
		m = nm.(Model)
		if m.ActiveTab != i-1 {
			t.Errorf("after '%d' expected tab=%d, got=%d", i, i-1, m.ActiveTab)
		}
	}

	q := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}}
	_, cmd := m.Update(q)
	if cmd == nil {
		t.Fatal("'q' should emit tea.Quit cmd")
	}
}

// TestChromeFitsWidth — regression for the root cause of "everything jumping":
// the tabbar had 129 chars in a 120-wide terminal, the terminal wraps, and the
// next screen builds 1 line lower. Ensures header/tabbar/statusbar never go
// past m.Width at reasonable widths.
func TestChromeFitsWidth(t *testing.T) {
	widths := []int{60, 80, 100, 110, 120, 140, 200}
	for _, w := range widths {
		m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
		m.Width = w
		m.Height = 40

		for _, line := range []struct {
			name, value string
		}{
			{"header", renderHeader(m)},
			{"tabbar", renderTabBar(m)},
			{"statusbar", renderStatusBar(m)},
		} {
			vw := visibleWidth(line.value)
			if vw > w {
				t.Errorf("w=%d %s overflow: visible=%d", w, line.name, vw)
			}
		}
	}
}

// visibleWidth is the "occupied" width in the terminal — strips ANSI sequences.
func visibleWidth(s string) int {
	// reuses the same logic as lipgloss
	// here we use a simple measurement: lipgloss.Width already strips ANSI
	return ansiStrip(s)
}

// TestStableTopOrdering — sim advances 60 ticks (~10s); the top-syscall list
// can only change order at most ~3x (refresh every 4s) — not every tick
// like before.
func TestStableTopOrdering(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width = 180
	m.Height = 50

	prev := append([]string{}, m.topSyscallNames...)
	changes := 0
	for i := 0; i < 60; i++ {
		// force sim to advance (tests don't wait for time.Sleep)
		m.lastSimAt = time.Time{}
		nm, _ := m.Update(TickMsg(time.Now()))
		m = nm.(Model)
		if !sameStrings(prev, m.topSyscallNames) {
			changes++
			prev = append([]string{}, m.topSyscallNames...)
		}
	}
	// since the test ran fast, the real clock only advanced a few ms — but
	// the refresh fires "every N REAL seconds". When we run fast,
	// the refresh never happens. We accept 0..2 changes.
	if changes > 2 {
		t.Errorf("topSyscallNames changed %d times in 60 ticks (expected <=2)", changes)
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSeed ensures NewModel populates visible fields without nil panic.
func TestSeed(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	if len(m.CPUHistory) == 0 {
		t.Error("CPUHistory empty after seed")
	}
	if len(m.SyscallCounts) == 0 {
		t.Error("SyscallCounts empty after seed")
	}
	if len(m.FDs) == 0 {
		t.Error("FDs empty after seed")
	}
	if len(m.NetConns) == 0 {
		t.Error("NetConns empty after seed")
	}
	if len(m.Threads) == 0 {
		t.Error("Threads empty after seed")
	}
	if len(m.IOStats.TopFiles) == 0 {
		t.Error("IOStats.TopFiles empty after seed")
	}
}
