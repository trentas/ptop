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

// TestRenderAllTabs garante que cada aba renderiza algo não-vazio em diversos
// tamanhos de terminal sem panicar — vital porque a TUI faz muita aritmética
// de larguras e qualquer overflow vira corruption visual.
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
				t.Errorf("size=%dx%d tab=%d: vazio", sz.w, sz.h, tab)
			}
			if !strings.Contains(out, "xray") {
				t.Errorf("size=%dx%d tab=%d: header ausente", sz.w, sz.h, tab)
			}
		}
	}
}

// TestTickAdvances confirma que o tick avança o histórico de CPU sem panicar
// e que o len do histórico está limitado ao cap.
func TestTickAdvances(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width = 120
	m.Height = 40

	for i := 0; i < 200; i++ {
		nm, _ := m.Update(TickMsg(time.Now()))
		m = nm.(Model)
	}
	if len(m.CPUHistory) > 60 {
		t.Errorf("CPUHistory cresceu sem limite: %d", len(m.CPUHistory))
	}
	if len(m.IOReadHist) > 60 {
		t.Errorf("IOReadHist cresceu sem limite: %d", len(m.IOReadHist))
	}
	if len(m.Timeline) > 120 {
		t.Errorf("Timeline cresceu sem limite: %d", len(m.Timeline))
	}
}

// TestKeyHandling verifica que F1-F7 navegam entre abas e q quita.
func TestKeyHandling(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})

	for i := 1; i <= TabCount; i++ {
		key := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{rune('0' + i)}}
		nm, _ := m.Update(key)
		m = nm.(Model)
		if m.ActiveTab != i-1 {
			t.Errorf("após '%d' esperava tab=%d, got=%d", i, i-1, m.ActiveTab)
		}
	}

	q := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}}
	_, cmd := m.Update(q)
	if cmd == nil {
		t.Fatal("'q' deveria emitir tea.Quit cmd")
	}
}

// TestChromeFitsWidth — regressão da causa raiz do "tudo pulando":
// o tabbar tinha 129 chars num terminal de 120, o terminal wrappa, e a próxima
// tela inteira monta-se 1 linha mais embaixo. Garante que header/tabbar/
// statusbar nunca passam de m.Width em larguras razoáveis.
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

// visibleWidth é a largura "ocupada" no terminal — desconta sequências ANSI.
func visibleWidth(s string) int {
	// reaproveita a mesma lógica do lipgloss
	// aqui usamos uma medição simples: lipgloss.Width já desconta ANSI
	return ansiStrip(s)
}

// TestStableTopOrdering — sim avança 60 ticks (~10s); o top-syscall list
// só pode mudar ordem no máximo umas 3x (refresh a cada 4s) — não a cada tick
// como antes.
func TestStableTopOrdering(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width = 180
	m.Height = 50

	prev := append([]string{}, m.topSyscallNames...)
	changes := 0
	for i := 0; i < 60; i++ {
		// força sim a avançar (testes não esperam time.Sleep)
		m.lastSimAt = time.Time{}
		nm, _ := m.Update(TickMsg(time.Now()))
		m = nm.(Model)
		if !sameStrings(prev, m.topSyscallNames) {
			changes++
			prev = append([]string{}, m.topSyscallNames...)
		}
	}
	// como o teste rodou rápido, o relógio real só avançou alguns ms — mas
	// o refresh dispara em "a cada N segundos REAIS". Quando rodamos rápido,
	// o refresh nunca acontece. Aceitamos 0..2 mudanças.
	if changes > 2 {
		t.Errorf("topSyscallNames mudou %d vezes em 60 ticks (esperado <=2)", changes)
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

// TestSeed garante que NewModel popula campos visíveis sem nil panic.
func TestSeed(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	if len(m.CPUHistory) == 0 {
		t.Error("CPUHistory vazio após seed")
	}
	if len(m.SyscallCounts) == 0 {
		t.Error("SyscallCounts vazio após seed")
	}
	if len(m.FDs) == 0 {
		t.Error("FDs vazio após seed")
	}
	if len(m.NetConns) == 0 {
		t.Error("NetConns vazio após seed")
	}
	if len(m.Threads) == 0 {
		t.Error("Threads vazio após seed")
	}
	if len(m.IOStats.TopFiles) == 0 {
		t.Error("IOStats.TopFiles vazio após seed")
	}
}
