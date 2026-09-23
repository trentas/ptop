package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// The smallest terminal ptop will draw into, and what it shows below that.
//
// ─── Why a gate and not seven ───────────────────────────────────────────────
//
// Every view used to carry its own threshold and its own bail-out string —
// three different width limits, two different height limits, and the message in
// two languages. Worse, they were checked too late: a view is handed the
// content area, so by the time one of them gave up, the header, tab bar and
// status bar had already been drawn into a terminal that could not hold them.
// What the operator saw was a broken frame with an apology inside it.
//
// So the size is decided once, before any chrome exists, and the thresholds are
// two constants the views share rather than repeat.
const (
	// minTerminalWidth is the narrowest the two-column layouts stay honest at.
	// It is the largest width any view asked for on its own (the I/O and FD
	// tables), now shared instead of duplicated.
	minTerminalWidth = 50

	// minContentHeight is the shortest CONTENT area a view can use — what a
	// view receives, not what the terminal has.
	minContentHeight = 12

	// chromeLines is the header, the tab bar and the status bar: one row each,
	// always present, never part of the content area.
	chromeLines = 3

	// minTerminalHeight is therefore what the terminal itself must have.
	minTerminalHeight = minContentHeight + chromeLines
)

// tooSmall reports whether the terminal cannot hold a frame worth drawing.
func tooSmall(w, h int) bool {
	return w < minTerminalWidth || h < minTerminalHeight
}

// renderTooSmall fills the terminal with the reason and the fix.
//
// It names BOTH sizes — what ptop needs and what it has — because "too small"
// alone leaves the reader guessing which dimension, and in a tiling window
// manager the answer is usually only one of them. The offending dimension is
// the one in red.
//
// It degrades to the point of a single word: this is the one screen that must
// render at any size at all, including the 20x4 an over-split pane leaves.
func renderTooSmall(w, h int) string {
	if w < 1 || h < 1 {
		return ""
	}
	bg := lipgloss.NewStyle().Background(ColorBG)
	wStyle, hStyle := BrightStyle, BrightStyle
	if w < minTerminalWidth {
		wStyle = RedStyle
	}
	if h < minTerminalHeight {
		hStyle = RedStyle
	}

	// Widest first, then progressively less, so a narrow pane still says
	// something true rather than nothing.
	lines := [][]string{
		{
			AmberStyle.Render("terminal too small"),
			"",
			MutedStyle.Render("ptop needs ") +
				BrightStyle.Render(fmt.Sprintf("%d×%d", minTerminalWidth, minTerminalHeight)) +
				MutedStyle.Render(", this is ") +
				wStyle.Render(fmt.Sprintf("%d", w)) + MutedStyle.Render("×") + hStyle.Render(fmt.Sprintf("%d", h)),
			"",
			MutedStyle.Render("resize the window, or q to quit"),
		},
		{
			AmberStyle.Render("too small"),
			MutedStyle.Render(fmt.Sprintf("need %d×%d", minTerminalWidth, minTerminalHeight)),
			MutedStyle.Render(fmt.Sprintf("have %d×%d", w, h)),
		},
		{AmberStyle.Render("too small")},
		{AmberStyle.Render("×")},
	}

	for _, block := range lines {
		if len(block) > h {
			continue
		}
		fits := true
		for _, l := range block {
			if lipgloss.Width(l) > w {
				fits = false
				break
			}
		}
		if !fits {
			continue
		}
		return bg.Width(w).Height(h).Align(lipgloss.Center, lipgloss.Center).
			Render(strings.Join(block, "\n"))
	}
	return bg.Width(w).Height(h).Render("")
}
