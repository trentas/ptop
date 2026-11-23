package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/trentas/ptop/pkg/collector"
)

// renderHeader draws the top bar:
//
//	⬡ ptop │ <process> [PID N] [Go 1.22] [STATE] [N fds]            uptime MM:SS │ HH:MM:SS
//
// STATE and uptime are the target's: the state summarizes its threads (see
// processState), the uptime counts from its start (ProcContext.StartTime).
// Either is left out while unknown, rather than showing the mockup's
// RUNNING or the time since ptop opened.
//
// The result is ALWAYS truncated to fit m.Width. If the line overflows
// width, the terminal line-wraps and the rest of the TUI gets flipped upside
// down — hence the obsession with never going over the limit.
func renderHeader(m Model) string {
	headerBg := lipgloss.Color("#0a0d11")

	logo := lipgloss.NewStyle().
		Foreground(ColorCyan).
		Background(headerBg).
		Bold(true).
		Render("⬡ ptop")

	sep := lipgloss.NewStyle().
		Foreground(ColorBorder).
		Background(headerBg).
		Render("│")

	procName := lipgloss.NewStyle().
		Foreground(ColorBright).
		Background(headerBg).
		Render(m.ProcessName)

	pidBadge := Badge(fmt.Sprintf("PID %d", m.cfg.PID), ColorBlue)

	fdBadge := Badge(fmt.Sprintf("%d fds", len(m.FDs)), ColorTeal)

	// build "left" segments in descending priority order
	// (seg is declared at the end of the file)
	leftSegs := []seg{
		{logo, 0},
		{sep, 0},
		{procName, 0},
		{pidBadge, 0},
	}
	// Only show the runtime badge if we actually know the runtime (see
	// Model.Runtime). Empty → omit, rather than display a mock value.
	if m.Runtime != "" {
		leftSegs = append(leftSegs, seg{Badge(m.Runtime, ColorCyan), 2})
	}
	// Container/execution context (#60): show the derived container id when the
	// target runs inside one. Lowest priority (prio 2) — drops first on narrow
	// terminals, like the runtime badge.
	if m.ProcCtx.Container != "" {
		leftSegs = append(leftSegs, seg{Badge(m.ProcCtx.Container, ColorPurple), 2})
	}
	if state := processState(m.Threads); state != "" {
		stateColor := ColorGreen
		switch state {
		case "BLOCKED", "STOPPED":
			stateColor = ColorRed
		case "SLEEPING":
			stateColor = ColorMuted
		}
		leftSegs = append(leftSegs, seg{Badge(state, stateColor), 1})
	}
	leftSegs = append(leftSegs, seg{fdBadge, 1})

	clock := time.Now().Format("15:04:05")
	rightFull := clock
	if start := m.ProcCtx.StartTime; !start.IsZero() {
		rightFull = fmt.Sprintf("uptime %s  │  %s", fmtUptime(time.Since(start)), clock)
	}
	rightShort := clock // fallback version for narrow terminals

	style := lipgloss.NewStyle().Foreground(ColorMuted).Background(headerBg)

	// determine which "right" version fits
	// and which "left" segments to drop
	left := buildSegments(leftSegs, " ")
	right := style.Render(rightFull)
	for budget := 0; budget < 4; budget++ {
		if lipgloss.Width(left)+lipgloss.Width(right)+3 <= m.Width {
			break
		}
		// 1) try short version of right
		if budget == 0 {
			right = style.Render(rightShort)
			continue
		}
		// 2) drop optional left segments by priority
		left = buildSegments(filterSegs(leftSegs, budget), " ")
	}

	gap := m.Width - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if gap < 1 {
		gap = 1
	}
	pad := lipgloss.NewStyle().Background(headerBg).Render(strings.Repeat(" ", gap))
	edge := lipgloss.NewStyle().Background(headerBg).Render(" ")

	return edge + left + pad + right + edge
}

// buildSegments concatenates seg.text with sep, respecting order.
func buildSegments(segs []seg, sep string) string {
	parts := make([]string, 0, len(segs))
	for _, s := range segs {
		parts = append(parts, s.text)
	}
	return strings.Join(parts, sep)
}

// filterSegs returns only segments with priority <= maxPrio.
// Used to shrink the set to fit a narrower width.
func filterSegs(segs []seg, maxPrio int) []seg {
	limit := 0
	switch maxPrio {
	case 1:
		limit = 1 // keep prio 0 and 1
	case 2:
		limit = 0 // essentials only
	default:
		limit = 0
	}
	out := make([]seg, 0, len(segs))
	for _, s := range segs {
		if s.prio <= limit {
			out = append(out, s)
		}
	}
	return out
}

type seg struct {
	text string
	prio int
}

// processState sums up the target's threads for the header badge, from the
// last thread sample: RUNNING when any thread is on a CPU or runnable,
// BLOCKED when none is but one sits in uninterruptible sleep (D: disk, a
// stuck mount), STOPPED when all are stopped, SLEEPING otherwise. "" with no
// threads, which is the badge left out.
//
// It reads every thread, not the leader the way top does: a Go or JVM
// server's main thread parks for its whole life while the others work, and
// its state alone would call the busiest process SLEEPING.
func processState(threads []collector.ThreadInfo) string {
	if len(threads) == 0 {
		return ""
	}
	var blocked, stopped int
	for _, t := range threads {
		switch t.State {
		case "running":
			return "RUNNING"
		case "blocked":
			blocked++
		case "stopped":
			stopped++
		}
	}
	switch {
	case blocked > 0:
		return "BLOCKED"
	case stopped == len(threads):
		return "STOPPED"
	default:
		return "SLEEPING"
	}
}

// fmtUptime renders a process's uptime: MM:SS under an hour, H:MM:SS under a
// day, then days and HH:MM. A long-running server is up for weeks, and the
// mockup's MM:SS would print 40000 minutes.
func fmtUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := int64(d / time.Second)
	switch {
	case s < 3600:
		return fmt.Sprintf("%02d:%02d", s/60, s%60)
	case s < 86400:
		return fmt.Sprintf("%d:%02d:%02d", s/3600, s/60%60, s%60)
	default:
		return fmt.Sprintf("%dd %02d:%02d", s/86400, s/3600%24, s/60%60)
	}
}
