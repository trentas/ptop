package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/trentas/ptop/internal/collector"
)

// ─── CPU ─────────────────────────────────────────────────────────────────────

// renderCPU draws a sparkline + current value on the right.
// Uses a FIXED 0-100% scale — without this the sparkline would rescale every
// tick and cause the "everything jumping" effect.
func renderCPU(history []float64, w int) string {
	if w < 12 {
		return MutedStyle.Render("…")
	}
	cur := 0.0
	if len(history) > 0 {
		cur = history[len(history)-1]
	}
	color := ColorGreen
	switch {
	case cur > 80:
		color = ColorRed
	case cur > 50:
		color = ColorAmber
	}

	val := lipgloss.NewStyle().Foreground(color).Background(ColorPanel).Bold(true).Render(fmt.Sprintf("%.0f%%", cur))
	lbl := MutedStyle.Render("cpu usage")

	rightW := maxInt(lipgloss.Width(val), lipgloss.Width(lbl))
	sparkW := w - rightW - 2
	if sparkW < 4 {
		sparkW = 4
	}
	spark := SparklineWithMax(history, sparkW, 100, color)

	right := lipgloss.JoinVertical(lipgloss.Right,
		lipgloss.NewStyle().Width(rightW).Background(ColorPanel).Align(lipgloss.Right).Render(val),
		lipgloss.NewStyle().Width(rightW).Background(ColorPanel).Align(lipgloss.Right).Render(lbl),
	)

	return lipgloss.JoinHorizontal(lipgloss.Top, spark, panelSp2, right)
}

// ─── Syscall bars ────────────────────────────────────────────────────────────

var syscallBarColors = []lipgloss.Color{
	ColorCyan, ColorBlue, ColorPurple, ColorPink, ColorAmber, ColorGreen, ColorRed, ColorMuted,
}

type syscallEntry struct {
	name  string
	count uint64
}

func sortedSyscalls(counts map[string]uint64) []syscallEntry {
	out := make([]syscallEntry, 0, len(counts))
	for k, v := range counts {
		out = append(out, syscallEntry{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].count == out[j].count {
			return out[i].name < out[j].name
		}
		return out[i].count > out[j].count
	})
	return out
}

// renderSyscallBars: compact table for the overview (up to 8 rows).
// Receives the list of names in STABLE order (from m.topSyscallNames) and
// only renders those; counts are read from the map (updated every tick).
// When names is nil or empty, falls back to dynamic behavior (top-N by count
// reordered each call — useful only for the first frame before the refresh).
func renderSyscallBars(counts map[string]uint64, names []string, w, h int) string {
	entries := stableSyscallEntries(counts, names)
	if h > 0 && len(entries) > h {
		entries = entries[:h]
	}
	if len(entries) == 0 {
		return ""
	}

	maxCount := uint64(1)
	for _, s := range entries {
		if s.count > maxCount {
			maxCount = s.count
		}
	}

	const nameW = 13
	const countW = 7
	barW := w - nameW - countW - 2
	if barW < 5 {
		barW = 5
	}

	lines := make([]string, 0, len(entries))
	for i, s := range entries {
		c := syscallBarColors[i%len(syscallBarColors)]
		name := lipgloss.NewStyle().Foreground(c).Background(ColorPanel).Width(nameW).Render(truncate(s.name, nameW))
		bar := HorizontalBar(float64(s.count), float64(maxCount), barW, c)
		count := lipgloss.NewStyle().
			Foreground(c).Background(ColorPanel).Width(countW).Align(lipgloss.Right).
			Render(fmt.Sprintf("%d", s.count))
		lines = append(lines, panelRow(name, bar, count))

	}
	return strings.Join(lines, "\n")
}

// stableSyscallEntries builds the list of entries respecting `names` if
// provided; otherwise takes the top-8 by count.
func stableSyscallEntries(counts map[string]uint64, names []string) []syscallEntry {
	if len(names) > 0 {
		out := make([]syscallEntry, 0, len(names))
		for _, n := range names {
			out = append(out, syscallEntry{name: n, count: counts[n]})
		}
		return out
	}
	all := sortedSyscalls(counts)
	if len(all) > 8 {
		all = all[:8]
	}
	return all
}

// renderSyscallTable: full version for F2 (all syscalls + percentage + total).
// Shows ALL syscalls — in F2 reordering by count is desirable (the whole
// screen is dedicated). To reduce oscillation, we use a cumulative max (the
// peak ever seen) instead of the current max.
func renderSyscallTable(counts map[string]uint64, w, h int) string {
	all := sortedSyscalls(counts)
	if len(all) == 0 {
		return MutedStyle.Render("(no data)")
	}
	var total uint64
	for _, s := range all {
		total += s.count
	}
	maxCount := all[0].count
	if maxCount == 0 {
		maxCount = 1
	}

	const nameW = 14
	const countW = 8
	const pctW = 7
	barW := w - nameW - countW - pctW - 3
	if barW < 5 {
		barW = 5
	}

	header := MutedStyle.Render(
		padRight("SYSCALL", nameW) + " " +
			padRight("FREQUENCY", barW) + " " +
			lipgloss.NewStyle().Width(countW).Background(ColorPanel).Align(lipgloss.Right).Render("COUNT") + " " +
			lipgloss.NewStyle().Width(pctW).Background(ColorPanel).Align(lipgloss.Right).Render("%"),
	)

	lines := []string{header}
	maxRows := h - 3
	if maxRows < 0 {
		maxRows = 0
	}
	if len(all) > maxRows {
		all = all[:maxRows]
	}

	for i, s := range all {
		c := syscallBarColors[i%len(syscallBarColors)]
		name := lipgloss.NewStyle().Foreground(c).Background(ColorPanel).Width(nameW).Render(truncate(s.name, nameW))
		bar := HorizontalBar(float64(s.count), float64(maxCount), barW, c)
		count := lipgloss.NewStyle().
			Foreground(ColorText).Background(ColorPanel).Width(countW).Align(lipgloss.Right).
			Render(fmt.Sprintf("%d", s.count))
		pct := 0.0
		if total > 0 {
			pct = float64(s.count) / float64(total) * 100
		}
		pctStr := lipgloss.NewStyle().
			Foreground(ColorMuted).Background(ColorPanel).Width(pctW).Align(lipgloss.Right).
			Render(fmt.Sprintf("%.1f%%", pct))
		lines = append(lines, panelRow(name, bar, count, pctStr))

	}

	footer := DimStyle.Render(strings.Repeat("─", w)) + "\n" +
		MutedStyle.Render("total events  ") + BrightStyle.Render(fmt.Sprintf("%d", total))
	return strings.Join(lines, "\n") + "\n" + footer
}

// ─── Threads ─────────────────────────────────────────────────────────────────

func threadStateGlyph(state string) (string, lipgloss.Color) {
	switch state {
	case "running":
		return "▶", ColorGreen
	case "blocked":
		return "■", ColorRed
	case "sleeping":
		return "·", ColorMuted
	default:
		return "·", ColorMuted
	}
}

// renderThreadList: compact list for the overview.
func renderThreadList(threads []collector.ThreadInfo, w, h int) string {
	const nameW = 11
	const cpuW = 5
	const waitW = 14
	barW := w - nameW - cpuW - waitW - 5
	if barW < 5 {
		barW = 5
	}

	lines := make([]string, 0, len(threads))
	for _, t := range threads {
		if h > 0 && len(lines) >= h {
			break
		}
		glyph, color := threadStateGlyph(t.State)
		gly := lipgloss.NewStyle().Foreground(color).Background(ColorPanel).Render(glyph)
		name := lipgloss.NewStyle().Foreground(ColorBright).Background(ColorPanel).Width(nameW).Render(truncate(t.Name, nameW))

		var bar string
		if t.State == "running" {
			bar = HorizontalBar(t.CPUPct, 100, barW, color)
		} else {
			bar = lipgloss.NewStyle().Foreground(ColorDim).Background(ColorPanel).Render(strings.Repeat("░", barW))
		}

		cpuLabel := "--"
		if t.CPUPct > 0 {
			cpuLabel = fmt.Sprintf("%.0f%%", t.CPUPct)
		}
		cpuStr := lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorPanel).Width(cpuW).Align(lipgloss.Right).Render(cpuLabel)

		wait := ""
		if t.Waiting != "" {
			wait = AmberStyle.Render(truncate("⏳ "+t.Waiting, waitW))
		}
		waitCol := lipgloss.NewStyle().Width(waitW).Background(ColorPanel).Render(wait)

		lines = append(lines, panelRow(gly, name, bar, cpuStr, waitCol))

	}
	return strings.Join(lines, "\n")
}

// renderThreadTable: full version for F4 (wider, with textual STATE).
func renderThreadTable(threads []collector.ThreadInfo, w, h int) string {
	const nameW = 14
	const stateW = 10
	const cpuW = 5
	const waitW = 18
	barW := w - 2 - nameW - stateW - cpuW - waitW - 5
	if barW < 5 {
		barW = 5
	}

	header := MutedStyle.Render(
		padRight("  NAME", 2+nameW) + " " +
			padRight("STATE", stateW) + " " +
			padRight("CPU", barW) + " " +
			lipgloss.NewStyle().Width(cpuW).Background(ColorPanel).Align(lipgloss.Right).Render("%") + " " +
			padRight("WAITING ON", waitW),
	)

	lines := []string{header}
	for _, t := range threads {
		if h > 0 && len(lines) >= h-1 {
			break
		}
		glyph, color := threadStateGlyph(t.State)
		gly := lipgloss.NewStyle().Foreground(color).Background(ColorPanel).Width(2).Render(glyph)
		name := lipgloss.NewStyle().Foreground(ColorBright).Background(ColorPanel).Width(nameW).Render(truncate(t.Name, nameW))
		state := lipgloss.NewStyle().Foreground(color).Background(ColorPanel).Width(stateW).Render(strings.ToUpper(t.State))

		var bar string
		if t.State == "running" {
			bar = HorizontalBar(t.CPUPct, 100, barW, color)
		} else {
			bar = lipgloss.NewStyle().Foreground(ColorDim).Background(ColorPanel).Render(strings.Repeat("░", barW))
		}
		cpuLabel := "--"
		if t.CPUPct > 0 {
			cpuLabel = fmt.Sprintf("%.0f%%", t.CPUPct)
		}
		cpuStr := lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorPanel).Width(cpuW).Align(lipgloss.Right).Render(cpuLabel)

		wait := "–"
		waitColor := ColorDim
		if t.Waiting != "" {
			wait = t.Waiting
			waitColor = ColorAmber
		}
		waitStr := lipgloss.NewStyle().Foreground(waitColor).Background(ColorPanel).Width(waitW).Render(truncate(wait, waitW))

		lines = append(lines, panelRow(gly+name, state, bar, cpuStr, waitStr))

	}
	return strings.Join(lines, "\n")
}

// ─── I/O Throughput mini (overview) ──────────────────────────────────────────

// renderIOMini: read/write sparklines + compact stats.
// maxRead/maxWrite come from the model with slow decay — without this the
// sparkline rescales every tick and gives an impression of instability.
func renderIOMini(io collector.IOStats, readH, writeH []float64, maxRead, maxWrite float64, w int) string {
	if w < 24 {
		return MutedStyle.Render("…")
	}
	curR := 0.0
	curW := 0.0
	if len(readH) > 0 {
		curR = readH[len(readH)-1]
	}
	if len(writeH) > 0 {
		curW = writeH[len(writeH)-1]
	}

	rightW := 12
	sparkW := w - rightW - 2
	if sparkW < 5 {
		sparkW = 5
	}

	rSpark := SparklineWithMax(readH, sparkW, maxRead, ColorCyan)
	wSpark := SparklineWithMax(writeH, sparkW, maxWrite, ColorOrange)

	rLabel := MutedStyle.Render("read/s ") +
		lipgloss.NewStyle().Foreground(ColorCyan).Background(ColorPanel).Bold(true).Render(fmtBytesPerSec(curR))
	wLabel := MutedStyle.Render("write/s ") +
		lipgloss.NewStyle().Foreground(ColorOrange).Background(ColorPanel).Bold(true).Render(fmtBytesPerSec(curW))
	right := lipgloss.NewStyle().Width(rightW).Background(ColorPanel).Align(lipgloss.Left).Render(rLabel) +
		"\n" +
		lipgloss.NewStyle().Width(rightW).Background(ColorPanel).Align(lipgloss.Left).Render(wLabel)

	sparks := rSpark + "\n" + wSpark
	header := lipgloss.JoinHorizontal(lipgloss.Top, sparks, panelSp2, right)

	stats := []string{
		MutedStyle.Render("read ops ") + CyanStyle.Render(fmt.Sprintf("%d", io.ReadOps)),
		MutedStyle.Render("write ops ") + OrangeStyle.Render(fmt.Sprintf("%d", io.WriteOps)),
		MutedStyle.Render("fsyncs ") + colorByThreshold(io.Fsyncs, 20).Render(fmt.Sprintf("%d", io.Fsyncs)),
		MutedStyle.Render("io-wait ") + colorByPctThreshold(io.IOWaitPct, 15).Render(fmt.Sprintf("%.1f%%", io.IOWaitPct)),
	}
	bottom := strings.Join(stats, panelSp2)

	return header + "\n" + bottom
}

// renderIOLargeThroughput: larger dual sparkline for F5.
// Uses decaying max (same as mini) to keep the scale stable.
func renderIOLargeThroughput(io collector.IOStats, readH, writeH []float64, maxRead, maxWrite float64, w, h int) string {
	if w < 30 {
		return MutedStyle.Render("…")
	}
	rightW := 14
	sparkW := w - rightW - 2
	if sparkW < 10 {
		sparkW = 10
	}

	curR, curW := 0.0, 0.0
	if len(readH) > 0 {
		curR = readH[len(readH)-1]
	}
	if len(writeH) > 0 {
		curW = writeH[len(writeH)-1]
	}

	rSpark := SparklineWithMax(readH, sparkW, maxRead, ColorCyan)
	wSpark := SparklineWithMax(writeH, sparkW, maxWrite, ColorOrange)

	rRight := MutedStyle.Render("read/s\n") +
		lipgloss.NewStyle().Foreground(ColorCyan).Background(ColorPanel).Bold(true).Render(fmtBytesPerSec(curR))
	wRight := MutedStyle.Render("write/s\n") +
		lipgloss.NewStyle().Foreground(ColorOrange).Background(ColorPanel).Bold(true).Render(fmtBytesPerSec(curW))

	first := lipgloss.JoinHorizontal(lipgloss.Top,
		rSpark, panelSp2,
		lipgloss.NewStyle().Width(rightW).Background(ColorPanel).Render(rRight),
	)
	second := lipgloss.JoinHorizontal(lipgloss.Top,
		wSpark, panelSp2,
		lipgloss.NewStyle().Width(rightW).Background(ColorPanel).Render(wRight),
	)
	return first + "\n" + second
}

// ─── FD breakdown / mini ─────────────────────────────────────────────────────

var fdTypeOrder = []string{"file", "socket", "pipe", "epoll", "timer"}

func fdBreakdownCounts(fds []collector.FDEntry) map[string]int {
	m := make(map[string]int, len(fdTypeOrder))
	for _, t := range fdTypeOrder {
		m[t] = 0
	}
	for _, f := range fds {
		m[f.Type]++
	}
	return m
}

func renderFDMini(fds []collector.FDEntry, w int) string {
	counts := fdBreakdownCounts(fds)
	maxC := 1
	for _, c := range counts {
		if c > maxC {
			maxC = c
		}
	}
	const nameW = 8
	const countW = 4
	barW := w - nameW - countW - 2
	if barW < 5 {
		barW = 5
	}

	headerLine := MutedStyle.Render(padRight("open fds", w-6)) +
		lipgloss.NewStyle().Foreground(ColorBright).Background(ColorPanel).Bold(true).Render(fmt.Sprintf("%4d", len(fds)))

	lines := []string{headerLine}
	for _, t := range fdTypeOrder {
		c := counts[t]
		color := FDTypeColor(t)
		name := lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorPanel).Width(nameW).Render(t)
		bar := HorizontalBar(float64(c), float64(maxC), barW, color)
		count := lipgloss.NewStyle().Foreground(color).Background(ColorPanel).Width(countW).Align(lipgloss.Right).Render(fmt.Sprintf("%d", c))
		lines = append(lines, panelRow(name, bar, count))

	}
	return strings.Join(lines, "\n")
}

// ─── Network mini / table ────────────────────────────────────────────────────

func netStateColor(state string) lipgloss.Color {
	switch state {
	case "WAIT":
		return ColorAmber
	case "RECV":
		return ColorCyan
	case "ESTABLISHED":
		return ColorGreen
	default:
		return ColorMuted
	}
}

func renderNetMini(conns []collector.NetConn, w, h int) string {
	const typeW = 5
	const stateW = 12
	const latW = 7
	remoteW := w - typeW - stateW - latW - 4
	if remoteW < 8 {
		remoteW = 8
	}

	header := MutedStyle.Render(
		padRight("TYPE", typeW) + " " +
			padRight("REMOTE", remoteW) + " " +
			padRight("STATE", stateW) + " " +
			lipgloss.NewStyle().Width(latW).Background(ColorPanel).Align(lipgloss.Right).Render("LAT"),
	)

	lines := []string{header}
	for _, c := range conns {
		if h > 0 && len(lines) >= h {
			break
		}
		t := lipgloss.NewStyle().Foreground(ColorBlue).Background(ColorPanel).Width(typeW).Render(c.Type)
		dir := c.Dir
		if dir == "" {
			dir = "↔"
		}
		remote := lipgloss.NewStyle().Foreground(ColorBright).Background(ColorPanel).Width(remoteW).Render(truncate(dir+" "+c.Remote, remoteW))
		state := lipgloss.NewStyle().Foreground(netStateColor(c.State)).Background(ColorPanel).Width(stateW).Render(c.State)
		latColor := ColorGreen
		if c.LatencyMs > 30 {
			latColor = ColorAmber
		}
		if c.LatencyMs > 100 {
			latColor = ColorRed
		}
		lat := lipgloss.NewStyle().Foreground(latColor).Background(ColorPanel).Width(latW).Align(lipgloss.Right).
			Render(fmt.Sprintf("%.0fms", c.LatencyMs))
		lines = append(lines, panelRow(t, remote, state, lat))

	}
	return strings.Join(lines, "\n")
}

// ─── Memory ──────────────────────────────────────────────────────────────────

func renderMemMini(s collector.MemStats, w int) string {
	rows := []struct {
		label string
		value string
		color lipgloss.Color
	}{
		{"RSS", fmt.Sprintf("%.0f MB", float64(s.RSSBytes)/(1<<20)), ColorCyan},
		{"Heap", fmt.Sprintf("%.0f MB", float64(s.HeapBytes)/(1<<20)), ColorPurple},
		{"Page faults", fmt.Sprintf("%d", s.PageFaults), ColorAmber},
		{"Allocs/s", fmt.Sprintf("%d", s.AllocsPerS), ColorGreen},
	}
	lines := make([]string, 0, len(rows))
	for _, r := range rows {
		left := MutedStyle.Render(r.label)
		right := lipgloss.NewStyle().Foreground(r.color).Background(ColorPanel).Render(r.value)
		gap := w - lipgloss.Width(left) - lipgloss.Width(right)
		if gap < 1 {
			gap = 1
		}
		lines = append(lines, left+panelGap(gap)+right)
	}
	return strings.Join(lines, "\n")
}

// ─── Timeline ────────────────────────────────────────────────────────────────

func renderTimelineCompact(events []collector.TimelineEvent, w, h int) string {
	if h <= 0 {
		return ""
	}
	visible := events
	if len(visible) > h {
		visible = visible[:h]
	}
	const tsW = 12
	const catW = 4
	msgW := w - tsW - catW - 2
	if msgW < 8 {
		msgW = 8
	}

	lines := make([]string, 0, len(visible))
	for _, e := range visible {
		ts := lipgloss.NewStyle().Foreground(ColorDim).Background(ColorPanel).Width(tsW).
			Render(e.Timestamp.Format("15:04:05.000"))
		c := CategoryColor(e.Category)
		cat := lipgloss.NewStyle().
			Foreground(c).Background(ColorPanel).Width(catW).Align(lipgloss.Center).
			Render(strings.TrimSpace(CategoryLabel(e.Category)))
		msg := lipgloss.NewStyle().Foreground(ColorText).Background(ColorPanel).Width(msgW).
			Render(truncate(e.Message, msgW))
		lines = append(lines, panelRow(ts, cat, msg))

	}
	return strings.Join(lines, "\n")
}

// ─── visual helpers ──────────────────────────────────────────────────────────

func colorByThreshold(value uint64, warn uint64) lipgloss.Style {
	switch {
	case value > warn*2:
		return RedStyle
	case value > warn:
		return AmberStyle
	default:
		return GreenStyle
	}
}

func colorByPctThreshold(value, warn float64) lipgloss.Style {
	switch {
	case value > warn*2:
		return RedStyle
	case value > warn:
		return AmberStyle
	default:
		return GreenStyle
	}
}
