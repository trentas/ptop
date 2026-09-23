package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func frameAt(w, h, tab int) string {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width, m.Height = w, h
	m.ActiveTab = tab
	m.render.commit = true
	return m.View()
}

func TestTooSmallGateFiresBelowTheMinimumAndNotAtIt(t *testing.T) {
	// Exactly the minimum must draw the real frame: a gate that fires at its
	// own threshold locks out the size it advertises as sufficient.
	if got := frameAt(minTerminalWidth, minTerminalHeight, 0); strings.Contains(got, "too small") {
		t.Errorf("%dx%d is the advertised minimum and must render",
			minTerminalWidth, minTerminalHeight)
	}
	for _, sz := range [][2]int{
		{minTerminalWidth - 1, minTerminalHeight},
		{minTerminalWidth, minTerminalHeight - 1},
		{20, 6},
	} {
		got := frameAt(sz[0], sz[1], 0)
		if !strings.Contains(got, "too small") {
			t.Errorf("%dx%d should refuse to draw, got:\n%s", sz[0], sz[1], got)
		}
		// The fix has to be nameable, or "too small" is just a complaint.
		if !strings.Contains(got, "50") {
			t.Errorf("%dx%d does not say what size is needed:\n%s", sz[0], sz[1], got)
		}
	}
}

// The one screen that has to render at any size at all — including whatever an
// over-split pane leaves behind.
func TestTooSmallScreenNeverOverflows(t *testing.T) {
	for w := 1; w <= 60; w += 3 {
		for h := 1; h <= 20; h += 2 {
			out := renderTooSmall(w, h)
			if out == "" {
				continue
			}
			lines := strings.Split(out, "\n")
			if len(lines) > h {
				t.Fatalf("%dx%d: %d lines", w, h, len(lines))
			}
			for i, l := range lines {
				if got := lipgloss.Width(l); got > w {
					t.Fatalf("%dx%d: line %d is %d wide", w, h, i, got)
				}
			}
		}
	}
}

// The sweep that should have existed. It caught three real overflows on main —
// Network, Threads and FD, at 60, 80 and 100 columns, 80 being the width more
// terminals are than any other. A line wider than the terminal wraps, and one
// wrapped line pushes every row below it out of the frame.
func TestEveryTabFitsTheTerminal(t *testing.T) {
	for _, h := range []int{minTerminalHeight, 20, 24, 30, 44} {
		for _, w := range []int{minTerminalWidth, 60, 70, 80, 100, 120, 160, 200} {
			for tab := 0; tab < TabCount; tab++ {
				for i, l := range strings.Split(frameAt(w, h, tab), "\n") {
					if got := lipgloss.Width(l); got > w {
						t.Errorf("tab %d at %dx%d: line %d is %d wide", tab, w, h, i, got)
					}
				}
			}
		}
	}
}

// Width is a MINIMUM in lipgloss; MaxWidth is what makes a box keep its size.
// Without it an over-wide body grew the box, two panels side by side came out
// wider than the terminal, and the layout collapsed.
func TestPanelKeepsItsWidthWithAnOverWideBody(t *testing.T) {
	body := strings.Repeat("very-long-content-", 20)
	for _, w := range []int{10, 24, 53, 80} {
		if got := lipgloss.Width(Panel("T", body, w, 6)); got != w {
			t.Errorf("Panel(w=%d) with an over-wide body rendered %d", w, got)
		}
		if got := lipgloss.Width(PanelTitleless(body, w, 6)); got != w {
			t.Errorf("PanelTitleless(w=%d) with an over-wide body rendered %d", w, got)
		}
	}
}
